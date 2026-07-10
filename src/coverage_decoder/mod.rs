use crate::cpu::PtCpu;
use crate::image::PtImage;
use crate::packet::decoder::PtPacketDecoder;
use crate::packet::mode::{AddressingMode, ModeExec, ModeTsx, TransactionState};
use crate::packet::pip::Pip;
use crate::packet::tip::{Fup, Tip, TipPgd, TipPge};
use crate::packet::tnt::TntIter;
use crate::packet::vmcs::Vmcs;
use crate::packet::{PtPacket, PtPacketParseError};
use crate::utils::fmix64;
use cache::*;
use core::fmt::Debug;
use core::mem;
use iced_x86::{Code, FlowControl, Instruction, Register};
use num_traits::{SaturatingAdd, WrappingAdd};

mod cache;

/// Marker trait for coverage map entry types.
///
/// Implementors must be numeric types that support saturating and wrapping addition
/// and can be constructed from a `u8`.
pub trait CoverageEntry: Copy + Debug + From<u8> + SaturatingAdd + WrappingAdd {}
impl<T> CoverageEntry for T where T: Copy + Debug + From<u8> + SaturatingAdd + WrappingAdd {}

/// Errors returned by [`PtCoverageDecoder`].
#[derive(Debug, PartialEq)]
#[non_exhaustive]
pub enum PtDecoderError {
    /// Unexpected end of trace buffer.
    Eof,
    /// Decoder reached an inconsistent internal state.
    IncoherentState,
    /// Decoded instruction flow is inconsistent with the provided images.
    IncoherentImage,
    /// An argument passed to the decoder is invalid.
    InvalidArgument,
    /// Received an unexpected PT packet sequence.
    InvalidPacketSequence {
        /// Sequence of packets that led to the error.
        packets: Vec<PtPacket>,
    },
    /// Could not decode an x86 instruction.
    MalformedInstruction,
    /// Could not parse a PT packet.
    MalformedPacket,
    /// Could not parse a PSB+ block.
    MalformedPsbPlus,
    /// No image found covering the given virtual address.
    MissingImage {
        /// The virtual address that could not be found in any `PtImage`.
        address: u64,
    },
    /// Return compression referred to a return target, but the return stack was empty.
    ReturnCompressionStackUnderflow,
    /// Could not find a PSB synchronization point in the trace.
    SyncFailed,
    // todo: if an OVF packet is encountered, the coverage might be incomplete and a source of
    // fuzzer instability. Consider returning this information so that a fuzzer using this lib can
    // decide to trash the execution and repeat it.
}

impl From<PtPacketParseError> for PtDecoderError {
    fn from(value: PtPacketParseError) -> Self {
        match value {
            PtPacketParseError::MalformedPacket => Self::MalformedPacket,
            PtPacketParseError::Eof => Self::Eof,
        }
    }
}

/// Builder for [`PtCoverageDecoder`].
#[derive(Debug, Clone, PartialEq)]
pub struct PtCoverageDecoderBuilder<'a> {
    cpu: Option<PtCpu>, // todo: consider if caching the errata makes sense
    images: &'a [PtImage<'a>],
    filter_vmx_non_root: bool,
}

/// Intel Processor Trace coverage decoder.
///
/// Decodes PT traces and computes edge coverage in an AFL-style bitmap.
#[derive(Debug)]
pub struct PtCoverageDecoder<'a> {
    builder: PtCoverageDecoderBuilder<'a>,

    is_syncd: bool,
    state: ExecutionState,
    proceed_inst_cache: InstCache,
    tnt_cache: TntCache,
}

#[derive(Debug)]
struct ExecutionState {
    packet_en: bool,
    pip: Pip,
    tip_last_ip: u64,
    ip: u64,
    vmcs: Option<Vmcs>,
    mode_exec: ModeExec,
    mode_tsx: ModeTsx,
    save_coverage: bool,
    #[cfg(feature = "retc")]
    ret_comp_stack: Vec<u64>,
}

#[derive(Debug)]
struct CovDecIterationState<'a, CE: Debug> {
    packet_decoder: PtPacketDecoder<'a>,
    coverage: &'a mut [CE],
}

impl<'a, CE> CovDecIterationState<'a, CE>
where
    CE: CoverageEntry,
{
    fn new(
        cov_dec: &mut PtCoverageDecoder,
        pt_trace: &'a [u8],
        coverage: &'a mut [CE],
    ) -> Result<Self, PtDecoderError> {
        if coverage.is_empty() {
            return Err(PtDecoderError::InvalidArgument);
        }

        let packet_decoder = if cov_dec.is_syncd {
            PtPacketDecoder::new_not_syncd(pt_trace)
        } else {
            let pd = PtPacketDecoder::new(pt_trace)?;
            cov_dec.is_syncd = true;
            pd
        };

        Ok(Self {
            packet_decoder,
            coverage,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum ProceedInstStopReason {
    CondBranch {
        branch_to: u64,
    },
    FarIndirect,
    Indirect,
    MovCr3,
    Return,
    #[cfg(feature = "more_checks")]
    UntilIpReached,
}

impl ExecutionState {
    const fn new() -> Self {
        Self {
            packet_en: false,
            pip: Pip { raw: [0; 6] },
            tip_last_ip: 0, // SDM 34.4.2.2 “Last IP” is initialized to zero
            ip: 0,
            vmcs: None,
            mode_exec: ModeExec::new(AddressingMode::_16, false),
            mode_tsx: ModeTsx::new(TransactionState::Commit),
            save_coverage: true,
            #[cfg(feature = "retc")]
            ret_comp_stack: Vec::new(), // todo: const hack, Vec::with_capacity(64) should be a better fit
        }
    }

    fn new_inst_decoder<'a>(
        &self,
        images: &'a [PtImage],
    ) -> Result<iced_x86::Decoder<'a>, PtDecoderError> {
        let image = images
            .iter()
            .find(|&image| {
                self.ip >= image.virtual_address_start() && self.ip <= image.virtual_address_end()
            })
            .ok_or(PtDecoderError::MissingImage { address: self.ip })?;

        let mut decoder = iced_x86::Decoder::with_ip(
            self.mode_exec.addressing_mode().into(),
            image.data(),
            self.ip,
            iced_x86::DecoderOptions::NONE,
        );
        decoder
            .set_position((decoder.ip() - image.virtual_address_start()) as usize)
            .expect(
                "current IP should be in the current image, otherwise we should have Err before",
            );

        #[cfg(feature = "log_instructions")]
        log::trace!(
            "Using image starting at: 0x{:x}",
            image.virtual_address_start()
        );
        Ok(decoder)
    }

    /// Position instruction decoder using the image that includes the current IP
    fn reposition_inst_decoder<'a>(
        &self,
        mut inst_decoder: iced_x86::Decoder<'a>,
        images: &'a [PtImage],
    ) -> Result<iced_x86::Decoder<'a>, PtDecoderError> {
        let current_image_start = inst_decoder.ip() - inst_decoder.position() as u64;

        if self.ip >= current_image_start
            && inst_decoder
                .set_position((self.ip - current_image_start) as usize)
                .is_ok()
        {
            inst_decoder.set_ip(self.ip);
            Ok(inst_decoder)
        } else {
            self.new_inst_decoder(images)
        }
    }
}

impl<'a> PtCoverageDecoderBuilder<'a> {
    /// Creates a new builder with default settings.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            cpu: None,
            images: &[],
            filter_vmx_non_root: false,
        }
    }

    /// Set the CPU model used to produce the traces.
    ///
    /// Providing the CPU is optional but, it will allow the decoder to consider the relevant CPU
    /// erratas, improving decoding quality.
    #[must_use]
    pub const fn cpu(mut self, cpu: Option<PtCpu>) -> Self {
        self.cpu = cpu;
        self
    }

    /// Consider only execution in VMX non-root when computing coverage, ignore VMX root
    /// (hypervisor) traces.
    #[must_use]
    pub const fn filter_vmx_non_root(mut self, filter_vmx_non_root: bool) -> Self {
        self.filter_vmx_non_root = filter_vmx_non_root;
        self
    }

    /// Exact runtime memory image of the executed target.
    #[must_use]
    pub fn images(mut self, images: &'a [PtImage<'a>]) -> Self {
        self.images = images;
        self
    }

    /// Builds a [`PtCoverageDecoder`].
    #[must_use]
    pub fn build(self) -> PtCoverageDecoder<'a> {
        PtCoverageDecoder {
            builder: self,
            state: ExecutionState::new(),
            is_syncd: false,
            proceed_inst_cache: InstCache::default(),
            tnt_cache: TntCache::default(),
        }
    }
}

impl Default for PtCoverageDecoderBuilder<'_> {
    fn default() -> Self {
        Self::new()
    }
}

impl PtCoverageDecoder<'_> {
    /// Decodes `pt_trace` and increments coverage map entries for each executed edge.
    ///
    /// `coverage` must have a power-of-two length greater than zero.
    pub fn coverage<CE>(
        &mut self,
        pt_trace: &[u8],
        coverage: &mut [CE],
    ) -> Result<(), PtDecoderError>
    where
        CE: CoverageEntry,
    {
        if coverage.is_empty() || !coverage.len().is_power_of_two() {
            return Err(PtDecoderError::InvalidArgument);
        }

        let mut iteration_state = CovDecIterationState::new(self, pt_trace, coverage)?;

        loop {
            match self.proceed_with_trace(&mut iteration_state) {
                Ok(()) => {}
                Err(PtDecoderError::Eof) => break Ok(()),
                Err(e) => {
                    self.is_syncd = false;
                    break Err(e);
                }
            }
        }
    }

    /// Continue decoding using PT trace.
    /// Can consume one or more PT packets.
    fn proceed_with_trace<CE: CoverageEntry>(
        &mut self,
        iteration_state: &mut CovDecIterationState<CE>,
    ) -> Result<(), PtDecoderError> {
        let packet = iteration_state.packet_decoder.next_packet_likely_tnt()?;

        match packet {
            PtPacket::Tnt(tnt_iter) => self.proceed_inst_tnt(tnt_iter, iteration_state)?,
            PtPacket::Tip(tip) => self.proceed_inst_tip(tip, iteration_state)?,
            PtPacket::TipPge(tip_pge) => self.handle_tip_pge(tip_pge)?,
            PtPacket::TipPgd(tip_pgd) => self.handle_tip_pgd(tip_pgd)?,
            PtPacket::Fup(fup) => self.handle_fup(fup, iteration_state)?,
            PtPacket::Pip(pip) => self.handle_pip(pip)?,
            PtPacket::ModeExec(mode_exec) => self.handle_mode_exec(mode_exec, iteration_state)?,
            PtPacket::ModeTsx(mode_tsx) => self.handle_mode_tsx(mode_tsx, iteration_state)?,
            PtPacket::TraceStop(..) => {} // todo
            PtPacket::Vmcs(..) => {}      //todo
            PtPacket::Ovf(..) => self.handle_ovf(iteration_state)?,
            PtPacket::Psb(..) => self.state = decode_psbplus(iteration_state, self.builder.cpu)?,
            PtPacket::PsbEnd(..) => {
                return Err(PtDecoderError::InvalidPacketSequence {
                    packets: vec![packet],
                });
            }
        }
        Ok(())
    }

    #[cold]
    fn handle_ovf<CE: CoverageEntry>(
        &mut self,
        iteration_state: &mut CovDecIterationState<CE>,
    ) -> Result<(), PtDecoderError> {
        #[cfg(feature = "retc")]
        self.state.ret_comp_stack.clear();

        // state.packet_en might have changed during the overflow
        let packet_decoder_pos = iteration_state.packet_decoder.pos();
        match iteration_state.packet_decoder.next_packet()? {
            PtPacket::Fup(fup) => {
                self.state.packet_en = true;
                self.handle_fup_after_ovf(fup)
            }
            _ => {
                self.state.packet_en = false;
                iteration_state.packet_decoder.set_pos(packet_decoder_pos);
                Ok(())
            }
        }
    }

    fn handle_mode_tsx<CE: CoverageEntry>(
        &mut self,
        mode_tsx: ModeTsx,
        iteration_state: &mut CovDecIterationState<CE>,
    ) -> Result<(), PtDecoderError> {
        // todo: double check this function
        if self.state.packet_en {
            let fup = match iteration_state.packet_decoder.next_packet()? {
                PtPacket::Fup(fup) => fup,
                p => {
                    return Err(PtDecoderError::InvalidPacketSequence {
                        packets: vec![PtPacket::ModeTsx(mode_tsx), p],
                    });
                }
            };
            self.handle_standalone_fup(&fup)?;

            if mode_tsx.transaction_state() == TransactionState::Abort {
                match iteration_state.packet_decoder.next_packet()? {
                    PtPacket::Tip(tip) => self.proceed_inst_tip(tip, iteration_state)?,
                    PtPacket::TipPge(tip_pge) => self.handle_tip_pge(tip_pge)?,
                    PtPacket::TipPgd(tip_pgd) => self.handle_tip_pgd(tip_pgd)?,
                    p => {
                        return Err(PtDecoderError::InvalidPacketSequence {
                            packets: vec![PtPacket::ModeTsx(mode_tsx), PtPacket::Fup(fup), p],
                        });
                    }
                }
            }
        }

        self.state.mode_tsx = mode_tsx;
        Ok(())
    }

    fn handle_fup_after_ovf(&mut self, fup: Fup) -> Result<(), PtDecoderError> {
        if fup.ip(&mut self.state.tip_last_ip) {
            self.state.ip = self.state.tip_last_ip;
            Ok(())
        } else {
            Err(PtDecoderError::MalformedPacket)
        }
    }

    fn handle_standalone_fup(&mut self, fup: &Fup) -> Result<(), PtDecoderError> {
        if !fup.ip(&mut self.state.tip_last_ip) {
            return Err(PtDecoderError::MalformedPacket);
        }

        #[cfg(feature = "more_checks")]
        return match self.proceed_inst_until(Some(self.state.tip_last_ip))? {
            ProceedInstStopReason::UntilIpReached => Ok(()),
            _ => Err(PtDecoderError::IncoherentImage),
        };

        #[cfg_attr(feature = "more_checks", expect(unreachable_code))]
        Ok(())
    }

    fn handle_mode_exec<CE: CoverageEntry>(
        &mut self,
        mode_exec: ModeExec,
        iteration_state: &mut CovDecIterationState<CE>,
    ) -> Result<(), PtDecoderError> {
        match iteration_state.packet_decoder.next_packet()? {
            PtPacket::Tip(tip) => self.proceed_inst_tip(tip, iteration_state)?,
            PtPacket::TipPge(tip_pge) => self.handle_tip_pge(tip_pge)?,
            PtPacket::Fup(fup) => self.handle_standalone_fup(&fup)?,
            p => {
                return Err(PtDecoderError::InvalidPacketSequence {
                    packets: vec![PtPacket::ModeExec(mode_exec), p],
                });
            }
        }
        self.state.mode_exec = mode_exec;

        Ok(())
    }

    fn handle_async_pip(&mut self, pip: Pip) {
        // todo: The purpose of the PIP is to indicate to the decoder which application is running,
        // so that it can apply the proper binaries to the linear addresses that are being traced.
        // add decoder cr3 filtering

        if self.builder.filter_vmx_non_root {
            self.state.save_coverage = pip.non_root_vmx();
        }

        self.state.pip = pip;
    }

    fn handle_pip(&mut self, pip: Pip) -> Result<(), PtDecoderError> {
        use ProceedInstStopReason::*;

        if self.state.packet_en {
            match self.proceed_inst_until(None)? {
                MovCr3 | FarIndirect => {}
                CondBranch { .. } | Indirect | Return => {
                    return Err(PtDecoderError::IncoherentImage);
                }
                #[cfg(feature = "more_checks")]
                UntilIpReached => unreachable!("until parameter is set to None"),
            }
        }

        self.handle_async_pip(pip);
        Ok(())
    }

    fn handle_fup<CE: CoverageEntry>(
        &mut self,
        fup: Fup,
        iteration_state: &mut CovDecIterationState<CE>,
    ) -> Result<(), PtDecoderError> {
        self.handle_standalone_fup(&fup)?;
        loop {
            let packet = iteration_state.packet_decoder.next_packet()?;
            match packet {
                PtPacket::Pip(pip) => self.handle_async_pip(pip),
                PtPacket::Vmcs(..) => todo!("handle fup vmcs"),
                PtPacket::ModeExec(..) => todo!("handle fup mode exec"),
                PtPacket::Tip(tip) => break self.handle_async_tip(tip)?,
                PtPacket::TipPgd(tip_pgd) => break self.handle_async_tip_pgd(tip_pgd),
                p => {
                    // todo handle overflow packet here (and in other InvalidPacketSequence?)
                    return Err(PtDecoderError::InvalidPacketSequence {
                        packets: vec![PtPacket::Fup(fup), p],
                    });
                }
            }
        }
        Ok(())
    }

    fn handle_async_tip(&mut self, tip: Tip) -> Result<(), PtDecoderError> {
        if tip.ip(&mut self.state.tip_last_ip) {
            self.state.ip = self.state.tip_last_ip;
            Ok(())
        } else {
            // we jumped somewhere but who knows where?
            Err(PtDecoderError::InvalidPacketSequence {
                packets: vec![PtPacket::Tip(tip)],
            })
        }
    }

    fn handle_async_tip_pgd(&mut self, tip_pgd: TipPgd) {
        self.state.packet_en = false;
        if tip_pgd.ip(&mut self.state.tip_last_ip) {
            self.state.ip = self.state.tip_last_ip;
        }
    }

    fn handle_tip_pgd(&mut self, tip_pgd: TipPgd) -> Result<(), PtDecoderError> {
        use ProceedInstStopReason::*;

        let ret = if tip_pgd.ip(&mut self.state.tip_last_ip) {
            #[cfg(feature = "more_checks")]
            return match self.proceed_inst_until(Some(self.state.tip_last_ip))? {
                CondBranch { .. } | Indirect | FarIndirect | UntilIpReached | Return => Ok(()),
                MovCr3 => Err(PtDecoderError::IncoherentImage),
            };

            #[cfg_attr(feature = "more_checks", expect(unreachable_code))]
            Ok(())
        } else {
            // might be caused by:
            // - trace stopped manually or operational error probably there is no way to get the
            //   precise ip where tracing actually stopped... Let's ignore this case.
            // - a conditional branch (replaces TNT)
            // - Change of CPL/CR3
            //
            // try to proceed with instructions, on error silently ignore and continue.
            if let Ok(stop_reason) = self.proceed_inst_until(None) {
                match stop_reason {
                    CondBranch { .. } | Indirect | FarIndirect | MovCr3 | Return => Ok(()),
                    #[cfg(feature = "more_checks")]
                    UntilIpReached => unreachable!("until parameter is set to None"),
                }
            } else {
                Ok(())
            }
        };

        self.state.packet_en = false;
        ret
    }

    fn handle_tip_pge(&mut self, tip_pge: TipPge) -> Result<(), PtDecoderError> {
        if tip_pge.ip(&mut self.state.tip_last_ip) {
            self.state.packet_en = true;
            self.state.ip = self.state.tip_last_ip;
            Ok(())
        } else {
            Err(PtDecoderError::MalformedPacket)
        }
    }

    fn proceed_inst_tip<CE: CoverageEntry>(
        &mut self,
        tip: Tip,
        #[cfg_attr(not(feature = "indirect_edges"), expect(unused_variables))]
        iteration_state: &mut CovDecIterationState<CE>,
    ) -> Result<(), PtDecoderError> {
        use ProceedInstStopReason::*;

        match self.proceed_inst_until(None)? {
            Indirect | FarIndirect | Return => {
                if tip.ip(&mut self.state.tip_last_ip) {
                    #[cfg(feature = "indirect_edges")]
                    self.add_coverage_entry(self.state.ip, self.state.tip_last_ip, iteration_state);
                    self.state.ip = self.state.tip_last_ip;
                    Ok(())
                } else {
                    Err(PtDecoderError::MalformedPacket)
                }
            }
            CondBranch { .. } | MovCr3 => Err(PtDecoderError::IncoherentImage),
            #[cfg(feature = "more_checks")]
            UntilIpReached => unreachable!("until parameter is set to None"),
        }
    }

    /// Proceed decoding the instructions until next decision point, considering the current PT
    /// packet is a TNT
    fn proceed_inst_tnt<CE: CoverageEntry>(
        &mut self,
        mut tnt_iter: TntIter,
        iteration_state: &mut CovDecIterationState<CE>,
    ) -> Result<(), PtDecoderError> {
        use ProceedInstStopReason::*;
        #[cfg(feature = "log_packets")]
        log::trace!("TNT handling start");

        let mut tnt_cache_key = TntCacheKey {
            from: self.state.ip,
            tnt: tnt_iter,
        };
        let mut tnt_cache_val = TntCacheValue::builder();

        'tnt: loop {
            // retc is not yet supported in tntcache
            if cfg!(not(feature = "retc"))
                && let Some(v) = self.tnt_cache.get(&tnt_cache_key)
            {
                let _ = tnt_iter.nth(v.coverage_len());
                self.state.ip = v.to();
                for i in v.coverage() {
                    self.add_coverage_from_index(*i, iteration_state);
                }
                tnt_cache_key = TntCacheKey {
                    from: self.state.ip,
                    tnt: tnt_iter,
                };
            }

            let Some(tnt) = tnt_iter.peek() else {
                break 'tnt;
            };

            match self.proceed_inst_until(None)? {
                // TNT consumed at the current decision point
                CondBranch { branch_to } => {
                    tnt_iter.advance();
                    let from = self.state.ip;
                    if tnt {
                        self.state.ip = branch_to;
                        #[cfg(feature = "log_packets")]
                        log::trace!("TNT taken to 0x{:x}", branch_to);
                    } else {
                        #[cfg(feature = "log_packets")]
                        log::trace!("TNT not taken");
                    }

                    let coverage_index =
                        CoverageIndex::new(from, self.state.ip, iteration_state.coverage.len());
                    tnt_cache_val.add(coverage_index);
                    self.add_coverage_from_index(coverage_index, iteration_state);
                }
                #[cfg(feature = "retc")]
                Return => {
                    tnt_iter.advance();
                    if tnt {
                        let to = self
                            .state
                            .ret_comp_stack
                            .pop()
                            .ok_or(PtDecoderError::ReturnCompressionStackUnderflow)?;
                        let to_masked = match self.state.mode_exec.addressing_mode() {
                            AddressingMode::_16 => to & u64::from(u16::MAX),
                            AddressingMode::_32 => to & u64::from(u32::MAX),
                            AddressingMode::_64 => to,
                        };
                        self.add_coverage_entry(self.state.ip, to_masked, iteration_state);
                        self.state.ip = to_masked;
                        #[cfg(feature = "log_packets")]
                        log::trace!("TNT taken (retc) to 0x{:x}", self.state.ip);
                    } else {
                        log::error!(
                            "Broken return compression. TNT taken expected, found TNT not taken"
                        );
                        return Err(PtDecoderError::IncoherentState);
                    }
                }
                // TNT NOT consumed at the current decision point, handle the decision point
                // and continue in the loop without consuming the TNT
                #[cfg_attr(feature = "retc", expect(unreachable_patterns))]
                Indirect | FarIndirect | Return => {
                    #[cfg(feature = "log_packets")]
                    log::trace!("TNT Handling deferred TIP");
                    let deferred = iteration_state.packet_decoder.next_packet()?;
                    let PtPacket::Tip(tip) = deferred else {
                        return Err(PtDecoderError::InvalidPacketSequence {
                            packets: vec![PtPacket::Tnt(tnt_iter), deferred],
                        });
                    };

                    // commit the TNT cache entry
                    if tnt_cache_val.coverage_len() > 0 {
                        self.tnt_cache.insert(
                            tnt_cache_key,
                            mem::take(&mut tnt_cache_val).build(self.state.ip),
                        );
                    }

                    if tip.ip(&mut self.state.tip_last_ip) {
                        #[cfg(feature = "indirect_edges")]
                        self.add_coverage_entry(
                            self.state.ip,
                            self.state.tip_last_ip,
                            iteration_state,
                        );
                        self.state.ip = self.state.tip_last_ip;
                        tnt_cache_key = TntCacheKey {
                            from: self.state.ip,
                            tnt: tnt_iter,
                        };
                    } else {
                        return Err(PtDecoderError::MalformedPacket);
                    }
                }
                MovCr3 => return Err(PtDecoderError::IncoherentImage),
                #[cfg(feature = "more_checks")]
                UntilIpReached => unreachable!("until parameter is set to None"),
            }
        }

        if tnt_cache_val.coverage_len() > 0 {
            self.tnt_cache
                .insert(tnt_cache_key, tnt_cache_val.build(self.state.ip));
        }

        #[cfg(feature = "log_packets")]
        log::trace!("TNT handling end");
        Ok(())
    }

    #[inline]
    fn proceed_inst_until(
        &mut self,
        until: Option<u64>,
    ) -> Result<ProceedInstStopReason, PtDecoderError> {
        if cfg!(feature = "more_checks") && !self.state.packet_en {
            return Err(PtDecoderError::IncoherentState);
        }

        // Use cache (only if until is None)
        if until.is_none()
            && let Some(cache_entry) = self.proceed_inst_cache.get(&InstCacheKey {
                from: self.state.ip,
                // vmcs: self.state.vmcs,
            })
        {
            #[cfg(feature = "retc")]
            self.state
                .ret_comp_stack
                .extend_from_slice(cache_entry.retc_stack_diff.as_slice());

            #[cfg(feature = "log_instructions")]
            log::trace!(
                "Cache hit: skipping disassembling from 0x{:x} to 0x{:x}",
                self.state.ip,
                cache_entry.to
            );
            self.state.ip = cache_entry.to;
            Ok(cache_entry.stop_reason)
        } else {
            #[cfg(feature = "more_checks")]
            return self.proceed_inst_until_slow_path(until);
            #[cfg(not(feature = "more_checks"))]
            return self.proceed_inst_until_slow_path();
        }
    }

    fn proceed_inst_until_slow_path(
        &mut self,
        #[cfg(feature = "more_checks")] until: Option<u64>,
    ) -> Result<ProceedInstStopReason, PtDecoderError> {
        use ProceedInstStopReason::*;

        #[cfg(feature = "retc")]
        let from_retc_stack_size = self.state.ret_comp_stack.len();
        let from = self.state.ip;
        let mut inst_decoder = self.state.new_inst_decoder(self.builder.images)?;
        let ins = loop {
            #[cfg(feature = "more_checks")]
            if let Some(ip) = until
                && inst_decoder.ip() == ip
            {
                return Ok(UntilIpReached);
            }

            if !inst_decoder.can_decode() {
                inst_decoder = self
                    .state
                    .reposition_inst_decoder(inst_decoder, self.builder.images)?;
            }

            let ins = inst_decoder.decode();
            #[cfg(feature = "log_instructions")]
            log::trace!(
                "\tip: 0x{:x}: {:?} {:?}",
                inst_decoder.ip() - ins.len() as u64,
                ins.code(),
                ins.op0_kind()
            );
            if ins.is_invalid() {
                return Err(PtDecoderError::MalformedInstruction);
            }

            match InstructionClass::from(&ins) {
                // Just proceed to the subsequent instruction, can continue with instruction decoder
                InstructionClass::Other => continue,
                // zero-length CALLs are ignored by return compression
                InstructionClass::JumpDirect | InstructionClass::CallDirect
                    if ins.near_branch_target() == ins.next_ip() =>
                {
                    continue;
                }
                // Needs trace to proceed
                InstructionClass::JumpIndirect
                | InstructionClass::MovCr3
                | InstructionClass::CondBranch
                | InstructionClass::FarCall
                | InstructionClass::FarJump
                | InstructionClass::FarReturn
                | InstructionClass::Return => {
                    self.state.ip = inst_decoder.ip();
                    break ins;
                }
                InstructionClass::CallIndirect => {
                    self.state.ip = inst_decoder.ip();
                    #[cfg(feature = "retc")]
                    {
                        self.state.ret_comp_stack.push(inst_decoder.ip());
                        #[cfg(feature = "log_packets")]
                        log::trace!("Pushed on retc stack: 0x{:x}", inst_decoder.ip());
                    }
                    break ins;
                }
                // Reposition instruction decoder before continuing
                #[cfg(feature = "retc")]
                InstructionClass::CallDirect => {
                    self.state.ret_comp_stack.push(inst_decoder.ip());
                    #[cfg(feature = "log_packets")]
                    log::trace!("Pushed on retc stack: 0x{:x}", inst_decoder.ip());
                }
                #[cfg_attr(feature = "retc", expect(unreachable_patterns))]
                InstructionClass::JumpDirect | InstructionClass::CallDirect => {}
            }
            self.state.ip = ins.near_branch_target();
            #[cfg(feature = "more_checks")]
            if let Some(ip) = until
                && self.state.ip == ip
            {
                return Ok(UntilIpReached);
            }

            inst_decoder = self
                .state
                .reposition_inst_decoder(inst_decoder, self.builder.images)?;
        };

        let reason = match InstructionClass::from(&ins) {
            InstructionClass::CondBranch => CondBranch {
                branch_to: ins.near_branch64(),
            },
            InstructionClass::Return => Return,
            InstructionClass::JumpIndirect | InstructionClass::CallIndirect => Indirect,
            InstructionClass::FarCall | InstructionClass::FarReturn | InstructionClass::FarJump => {
                FarIndirect
            }
            InstructionClass::MovCr3 => MovCr3,
            InstructionClass::JumpDirect
            | InstructionClass::CallDirect
            | InstructionClass::Other => unreachable!("These instructions do not need traces"),
        };

        #[cfg(feature = "retc")]
        let retc_stack_diff = self.state.ret_comp_stack[from_retc_stack_size..].to_vec();

        self.proceed_inst_cache.insert(
            InstCacheKey {
                from,
                // vmcs: self.state.vmcs,
            },
            InstCacheValue {
                to: self.state.ip,
                stop_reason: reason,
                #[cfg(feature = "retc")]
                retc_stack_diff,
            },
        );

        Ok(reason)
    }

    #[cfg(any(feature = "indirect_edges", feature = "retc"))]
    fn add_coverage_entry<CE: CoverageEntry>(
        &self,
        from: u64,
        to: u64,
        iteration_state: &mut CovDecIterationState<CE>,
    ) {
        if !self.state.save_coverage {
            return;
        }

        let cov_index = CoverageIndex::new(from, to, iteration_state.coverage.len());
        self.add_coverage_from_index(cov_index, iteration_state);
    }

    fn add_coverage_from_index<CE: CoverageEntry>(
        &self,
        i: CoverageIndex,
        iteration_state: &mut CovDecIterationState<CE>,
    ) {
        if !self.state.save_coverage {
            return;
        }

        // SAFETY: `CoverageIndex.new()` ensures that the inner value is < `coverage.len()`
        let coverage_entry = unsafe { iteration_state.coverage.get_unchecked_mut(usize::from(i)) };

        *coverage_entry = coverage_entry.wrapping_add(&1.into());
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct CoverageIndex {
    inner: usize,
}

impl CoverageIndex {
    #[allow(clippy::cast_possible_truncation)]
    #[inline]
    const fn new(from: u64, to: u64, map_len: usize) -> Self {
        let inner = (fmix64(from) ^ fmix64(to)) as usize & (map_len - 1);
        Self { inner }
    }
}

impl From<CoverageIndex> for usize {
    fn from(value: CoverageIndex) -> Self {
        value.inner
    }
}

#[cold]
fn decode_psbplus<CE: Debug>(
    iteration_state: &mut CovDecIterationState<CE>,
    cpu: Option<PtCpu>,
) -> Result<ExecutionState, PtDecoderError> {
    let mut state = ExecutionState::new();

    loop {
        match iteration_state.packet_decoder.next_packet()? {
            PtPacket::PsbEnd(..) => return Ok(state),
            PtPacket::Pip(pip) => state.pip = pip,
            PtPacket::Vmcs(vmcs) => state.vmcs = Some(vmcs),
            PtPacket::ModeTsx(mode_tsx) => state.mode_tsx = mode_tsx,
            PtPacket::ModeExec(mode_exec) => state.mode_exec = mode_exec,
            PtPacket::Fup(fup) => {
                // fixme: if the decoder was already running, consider also that some code executed
                // between PSB's preceeding packet and PSB might get ignored here
                if let Some(last_ip) = decode_psbplus_fup(fup, state.tip_last_ip, cpu) {
                    state.packet_en = true;
                    state.tip_last_ip = last_ip;
                    state.ip = last_ip;
                } else {
                    state.packet_en = false;
                }
            }
            PtPacket::Ovf(..) => todo!(),
            _ => return Err(PtDecoderError::MalformedPsbPlus),
        }
    }
}

fn decode_psbplus_fup(fup: Fup, mut last_ip: u64, cpu: Option<PtCpu>) -> Option<u64> {
    if let Some(cpu) = cpu
        && cpu.errata().bdm70
    {
        // todo: pt_evt_check_bdm70
    }
    fup.ip(&mut last_ip).then_some(last_ip)
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum InstructionClass {
    Other,

    CallDirect,
    CallIndirect,
    CondBranch,
    FarCall,
    FarJump,
    FarReturn,
    JumpDirect,
    JumpIndirect,
    MovCr3,
    Return,
}

impl From<&Instruction> for InstructionClass {
    fn from(instruction: &Instruction) -> Self {
        match instruction.flow_control() {
            FlowControl::Next => {
                if matches!(instruction.code(), Code::Mov_cr_r32 | Code::Mov_cr_r64)
                    && instruction.op0_register() == Register::CR3
                {
                    Self::MovCr3
                } else {
                    Self::Other
                }
            }
            FlowControl::ConditionalBranch => Self::CondBranch,
            FlowControl::UnconditionalBranch => {
                if instruction.is_jmp_far() {
                    Self::FarJump
                } else {
                    Self::JumpDirect
                }
            }
            FlowControl::Interrupt | FlowControl::Exception => Self::FarCall,
            FlowControl::Return => match instruction.code() {
                Code::Retnd
                | Code::Retnq
                | Code::Retnw
                | Code::Retnd_imm16
                | Code::Retnq_imm16
                | Code::Retnw_imm16 => Self::Return,
                _ => Self::FarReturn,
            },
            FlowControl::IndirectBranch => {
                if instruction.is_jmp_far_indirect() {
                    Self::FarJump
                } else {
                    Self::JumpIndirect
                }
            }
            FlowControl::Call => {
                if instruction.is_call_near() {
                    return Self::CallDirect;
                }

                match instruction.code() {
                    Code::Vmlaunch | Code::Vmresume => Self::FarReturn,
                    _ => Self::FarCall,
                }
            }
            FlowControl::IndirectCall => {
                if instruction.is_call_far_indirect() {
                    Self::FarCall
                } else {
                    Self::CallIndirect
                }
            }
            FlowControl::XbeginXabortXend => {
                // todo: support transactions
                Self::Other
            }
        }
    }
}

#[cfg(test)]
mod test {
    use crate::coverage_decoder::InstructionClass;
    use iced_x86::{Code, Instruction, Register};
    use std::mem;

    #[test]
    fn from_works() {
        for i in Code::Add_rm8_r8 as u16..=Code::VEX_Vsm3rnds2_xmm_xmm_xmmm128_imm8 as u16 {
            let code: Code = unsafe { mem::transmute(i) };

            // Ignore IA-64 leftovers
            if matches!(
                code,
                Code::Jmpe_disp16 | Code::Jmpe_disp32 | Code::Jmpe_rm16 | Code::Jmpe_rm32
            ) {
                continue;
            }

            // Ignore not Intel stuff (AMD SVM, Cyryx, ...)
            if matches!(
                code,
                Code::Vmrunw
                    | Code::Vmrund
                    | Code::Vmrunq
                    | Code::Vmmcall
                    | Code::Skinit
                    | Code::Vmgexit
                    | Code::Smint
                    | Code::Dmint
                    | Code::Rdm
                    | Code::Smint_0F7E
                    | Code::Altinst
                    | Code::Vmgexit_F2
            ) {
                continue;
            }

            // Ignore mvex
            if matches!(
                code,
                Code::VEX_KNC_Jkzd_kr_rel8_64
                    | Code::VEX_KNC_Jknzd_kr_rel8_64
                    | Code::VEX_KNC_Jkzd_kr_rel32_64
                    | Code::VEX_KNC_Jknzd_kr_rel32_64
            ) {
                continue;
            }

            // todo: SMM stuff
            if matches!(code, Code::Rsm) {
                continue;
            }

            //todo: TDX stuff
            if matches!(code, Code::Tdcall | Code::Seamret | Code::Seamcall) {
                continue;
            }

            let mut instruction = Instruction::new();
            instruction.set_code(code);
            assert_eq!(
                InstructionClass::from(&instruction),
                class_from_instruction_raw(&instruction),
                "{i} - {code:?}"
            );
        }
    }

    const fn class_from_instruction_raw(instruction: &Instruction) -> InstructionClass {
        use Code::*;
        match instruction.code() {
            // PTI_INST_CALL_FFr2 indirect
            Call_rm16 | Call_rm32 | Call_rm64 => InstructionClass::CallIndirect,
            // PTI_INST_CALL_E8 direct
            Call_rel16 | Call_rel32_32 | Call_rel32_64 => InstructionClass::CallDirect,
            // 0x7x PTI_INST_JCC direct
            Jo_rel8_16 | Jo_rel8_32 | Jo_rel8_64 |
            Jno_rel8_16 | Jno_rel8_32 | Jno_rel8_64 |
            Jb_rel8_16 | Jb_rel8_32 | Jb_rel8_64 |
            Jae_rel8_16 | Jae_rel8_32 | Jae_rel8_64 |
            Je_rel8_16 | Je_rel8_32 | Je_rel8_64 |
            Jne_rel8_16 | Jne_rel8_32 | Jne_rel8_64 |
            Jbe_rel8_16 | Jbe_rel8_32 | Jbe_rel8_64 |
            Ja_rel8_16 | Ja_rel8_32 | Ja_rel8_64 |
            Js_rel8_16 | Js_rel8_32 | Js_rel8_64 |
            Jns_rel8_16 | Jns_rel8_32 | Jns_rel8_64 |
            Jp_rel8_16 | Jp_rel8_32 | Jp_rel8_64 |
            Jnp_rel8_16 | Jnp_rel8_32 | Jnp_rel8_64 |
            Jl_rel8_16 | Jl_rel8_32 | Jl_rel8_64 |
            Jge_rel8_16 | Jge_rel8_32 | Jge_rel8_64 |
            Jle_rel8_16 | Jle_rel8_32 | Jle_rel8_64 |
            Jg_rel8_16 | Jg_rel8_32 | Jg_rel8_64 |
            Jne_rel16 |
            // 0x80 PTI_INST_JCC direct
            Jo_rel16 | Jo_rel32_32 | Jo_rel32_64 |
            Jno_rel16 | Jno_rel32_32 | Jno_rel32_64 |
            Jb_rel16 | Jb_rel32_32 | Jb_rel32_64 |
            Jae_rel16 | Jae_rel32_32 | Jae_rel32_64 |
            Je_rel16 | Je_rel32_32 | Je_rel32_64 |
            Jne_rel32_32 | Jne_rel32_64 |
            Jbe_rel16 | Jbe_rel32_32 | Jbe_rel32_64 |
            Ja_rel16 | Ja_rel32_32 | Ja_rel32_64 |
            Js_rel16 | Js_rel32_32 | Js_rel32_64 |
            Jns_rel16 | Jns_rel32_32 | Jns_rel32_64 |
            Jp_rel16 | Jp_rel32_32 | Jp_rel32_64 |
            Jnp_rel16 | Jnp_rel32_32 | Jnp_rel32_64 |
            Jl_rel16 | Jl_rel32_32 | Jl_rel32_64 |
            Jge_rel16 | Jge_rel32_32 | Jge_rel32_64 |
            Jle_rel16 | Jle_rel32_32 | Jle_rel32_64 |
            Jg_rel16 | Jg_rel32_32 | Jg_rel32_64 |
            // 0xe3 PTI_INST_JrCXZ direct
            Jcxz_rel8_16 | Jcxz_rel8_32 | Jecxz_rel8_16 | Jecxz_rel8_32 |
            Jecxz_rel8_64 | Jrcxz_rel8_16 | Jrcxz_rel8_64 |
            // 0xe0 PTI_INST_LOOPNE direct
            Loopne_rel8_16_CX | Loopne_rel8_16_ECX | Loopne_rel8_16_RCX |
            Loopne_rel8_32_CX | Loopne_rel8_32_ECX | Loopne_rel8_64_ECX |
            Loopne_rel8_64_RCX |
            // 0xe1 PTI_INST_LOOPE direct
            Loope_rel8_16_CX | Loope_rel8_16_ECX | Loope_rel8_16_RCX |
            Loope_rel8_32_CX | Loope_rel8_32_ECX | Loope_rel8_64_ECX |
            Loope_rel8_64_RCX |
            // 0xe2 PTI_INST_LOOP direct
            Loop_rel8_16_CX | Loop_rel8_16_ECX | Loop_rel8_16_RCX |
            Loop_rel8_32_CX | Loop_rel8_32_ECX | Loop_rel8_64_ECX |
            Loop_rel8_64_RCX => InstructionClass::CondBranch,
            // ptic_far_call
            // PTI_INST_CALL_9A
            Call_ptr1616 | Call_ptr1632 |
            // PTI_INST_CALL_FFr3
            Call_m1616 | Call_m1632 | Call_m1664 |
            // 0xCD PTI_INST_INT
            Int_imm8 |
            // 0xCC PTI_INST_INT3
            Int3 |
            // 0xCE PTI_INST_INTO
            Into |
            // 0xF1 PTI_INST_INT1
            Int1 |
            // 0x0f 0x05 PTI_INST_SYSCALL
            Syscall |
            // 0x0f 0x34 SYSENTER
            Sysenter |
            // PTI_INST_VMCALL
            Vmcall |
            Ud1_r16_rm16 | Ud0_r16_rm16 | Ud1_r32_rm32 | Ud1_r64_rm64 | Ud0_r32_rm32 | Ud2 |
            Ud0_r64_rm64 | Ud0
                => InstructionClass::FarCall,
            // PTI_INST_JMP_FFr5
            Jmp_m1616 | Jmp_m1632 | Jmp_m1664 |
            // PTI_INST_JMP_EA
            Jmp_ptr1616 | Jmp_ptr1632 => InstructionClass::FarJump,
            // PTI_INST_IRET
            Iretd | Iretw | Iretq |
            // PTI_INST_RET_CB
            Retfd | Retfw | Retfq |
            // PTI_INST_RET_CA
            Retfd_imm16 | Retfw_imm16 | Retfq_imm16 |
            // PTI_INST_SYSEXIT
            Sysexitd | Sysexitq |
            // PTI_INST_SYSRET
            Sysretd | Sysretq |
            // PTI_INST_VMLAUNCH
            Vmlaunch |
            // PTI_INST_VMRESUME
            Vmresume |
            // PTI_INST_UIRET
            Uiret |
            // PTI_INST_ERETS
            Erets |
            // PTI_INST_ERETU
            Eretu => InstructionClass::FarReturn,
            // PTI_INST_JMP_FFr4 indirect
            Jmp_rm16 | Jmp_rm32 | Jmp_rm64 => InstructionClass::JumpIndirect,
            // PTI_INST_JMP_E9 direct
            Jmp_rel16 | Jmp_rel32_32 | Jmp_rel32_64 |
            // PTI_INST_JMP_EB direct
            // todo: when iced_x86 will introduce APX (https://en.wikipedia.org/wiki/X86#APX) and REX2
            // support, also check for what in libipt they call PTI_INST_JMPABS direct but behaves like an indirect jump according to libipt
            Jmp_rel8_16 | Jmp_rel8_32 | Jmp_rel8_64 => InstructionClass::JumpDirect,
            // PTI_INST_MOV_CR3
            Mov_cr_r64 | Mov_cr_r32 if matches!(instruction.op0_register(), Register::CR3) => InstructionClass::MovCr3,
            // PTI_INST_PTWRITE
            // 0xC3 PTI_INST_RET_C3
            Retnd | Retnq | Retnw |
            // 0xC2 PTI_INST_RET_C2
            Retnd_imm16 | Retnq_imm16 | Retnw_imm16 => InstructionClass::Return,
            _ => InstructionClass::Other
        }
    }
}
