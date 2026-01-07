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
use iced_x86::{Code, FlowControl, Instruction, Register};
use std::collections::HashMap;
use std::fmt::Debug;
use std::ops::AddAssign;

#[derive(Debug, PartialEq)]
#[non_exhaustive]
pub enum PtDecoderError {
    Eof,
    IncoherentState,
    IncoherentImage,
    InvalidArgument,
    InvalidPacketSequence { packets: Vec<PtPacket> },
    MalformedInstruction,
    MalformedPacket,
    MalformedPsbPlus,
    MissingImage { address: u64 },
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

#[derive(Debug, Clone, PartialEq)]
pub struct PtCoverageDecoderBuilder {
    cpu: Option<PtCpu>, // todo: consider if caching the errata makes sense
    images: Vec<PtImage>,
    filter_vmx_non_root: bool,
}

#[derive(Debug)]
pub struct PtCoverageDecoder {
    builder: PtCoverageDecoderBuilder,

    is_syncd: bool,
    state: ExecutionState,
    proceed_inst_cache: HashMap<u64, (u64, ProceedInstStopReason)>, // todo cr3 + vmcs should be in the key as well
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
    CE: Debug + AddAssign,
{
    fn new(
        cov_dec: &mut PtCoverageDecoder,
        pt_trace: &'a [u8],
        coverage: &'a mut [CE],
    ) -> Result<Self, PtDecoderError> {
        if coverage.len() == 0 {
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
    CondBranch { to: u64 },
    FarIndirect,
    Indirect,
    MovCr3,
    Return,
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
            ret_comp_stack: Vec::new(), // const hack, Vec::with_capacity(64) should be a better fit
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

impl PtCoverageDecoderBuilder {
    pub const fn new() -> Self {
        Self {
            cpu: None,
            images: vec![],
            filter_vmx_non_root: false,
        }
    }

    pub const fn cpu(mut self, cpu: Option<PtCpu>) -> Self {
        self.cpu = cpu;
        self
    }

    pub const fn filter_vmx_non_root(mut self, filter_vmx_non_root: bool) -> Self {
        self.filter_vmx_non_root = filter_vmx_non_root;
        self
    }

    pub fn images(mut self, images: Vec<PtImage>) -> Self {
        self.images = images;
        self
    }

    pub fn build(self) -> Result<PtCoverageDecoder, PtDecoderError> {
        Ok(PtCoverageDecoder {
            builder: self,
            state: ExecutionState::new(),
            is_syncd: false,
            proceed_inst_cache: HashMap::new(),
        })
    }
}

impl Default for PtCoverageDecoderBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl PtCoverageDecoder {
    pub fn coverage<CE>(
        &mut self,
        pt_trace: &[u8],
        coverage: &mut [CE],
    ) -> Result<(), PtDecoderError>
    where
        CE: AddAssign + Debug + From<u8>,
    {
        let mut iteration_state = CovDecIterationState::new(self, pt_trace, coverage)?;

        loop {
            match self.proceed_with_trace(&mut iteration_state) {
                Ok(()) => continue,
                Err(PtDecoderError::Eof) => break Ok(()),
                Err(e) => break Err(e),
            }
        }
    }

    /// Continue decoding using PT trace.
    /// Can consume one or more PT packets.
    fn proceed_with_trace<CE: Debug + AddAssign + From<u8>>(
        &mut self,
        iteration_state: &mut CovDecIterationState<CE>,
    ) -> Result<(), PtDecoderError> {
        let packet = iteration_state.packet_decoder.next_packet()?;

        match packet {
            PtPacket::TntShort(tnt_s) => {
                self.proceed_inst_tnt(tnt_s.into_iter().into(), iteration_state)?
            }
            PtPacket::TntLong(tnt_l) => {
                self.proceed_inst_tnt(tnt_l.into_iter().into(), iteration_state)?
            }
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
            PtPacket::PsbEnd(psb_end) => {
                return Err(PtDecoderError::InvalidPacketSequence {
                    packets: vec![PtPacket::PsbEnd(psb_end)],
                });
            }
            _ => {} // Ignore other packets
        };
        Ok(())
    }

    fn handle_ovf<CE: Debug + AddAssign + From<u8>>(
        &mut self,
        iteration_state: &mut CovDecIterationState<CE>,
    ) -> Result<(), PtDecoderError> {
        #[cfg(feature = "retc")]
        self.state.ret_comp_stack.clear();

        // state.packet_en might have changed during the overflow
        match iteration_state.packet_decoder.next_packet()? {
            PtPacket::Fup(fup) => {
                self.state.packet_en = true;
                self.handle_fup_after_ovf(fup)
            }
            p => {
                self.state.packet_en = false;
                iteration_state.packet_decoder.rollback_one_packet(p)
            }
        }
    }

    fn handle_mode_tsx<CE: Debug + AddAssign + From<u8>>(
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
        if !fup.ip(&mut self.state.tip_last_ip) {
            Err(PtDecoderError::MalformedPacket)
        } else {
            self.state.ip = self.state.tip_last_ip;
            Ok(())
        }
    }

    fn handle_standalone_fup(&mut self, fup: &Fup) -> Result<(), PtDecoderError> {
        if !fup.ip(&mut self.state.tip_last_ip) {
            return Err(PtDecoderError::MalformedPacket);
        }

        match self.proceed_inst_until(Some(self.state.tip_last_ip))? {
            ProceedInstStopReason::UntilIpReached => Ok(()),
            _ => Err(PtDecoderError::IncoherentImage),
        }
    }

    fn handle_mode_exec<CE: Debug + AddAssign + From<u8>>(
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
                UntilIpReached => unreachable!("until parameter is set to None"),
            }
        }

        self.handle_async_pip(pip);
        Ok(())
    }

    fn handle_fup<CE: Debug + AddAssign + From<u8>>(
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
            match self.proceed_inst_until(Some(self.state.tip_last_ip))? {
                CondBranch { .. } | Indirect | FarIndirect | UntilIpReached | Return => Ok(()),
                MovCr3 => Err(PtDecoderError::IncoherentImage),
            }
        } else {
            // might be caused by:
            // - trace stopped manually or operational error probably there is no way to get the
            //   precise ip where tracing actually stopped... Let's ignore this case.
            // - a conditional branch (replaces TNT)
            // - Change of CPL/CR3
            match self.proceed_inst_until(None)? {
                CondBranch { .. } | Indirect | FarIndirect | MovCr3 | Return => Ok(()),
                UntilIpReached => unreachable!("until parameter is set to None"),
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

    fn proceed_inst_tip<CE: Debug + AddAssign + From<u8>>(
        &mut self,
        tip: Tip,
        iteration_state: &mut CovDecIterationState<CE>,
    ) -> Result<(), PtDecoderError> {
        use ProceedInstStopReason::*;

        match self.proceed_inst_until(None)? {
            Indirect | FarIndirect | Return => {
                if tip.ip(&mut self.state.tip_last_ip) {
                    self.add_coverage_entry(self.state.tip_last_ip, iteration_state);
                    self.state.ip = self.state.tip_last_ip;
                    Ok(())
                } else {
                    Err(PtDecoderError::MalformedPacket)
                }
            }
            CondBranch { .. } | MovCr3 => Err(PtDecoderError::IncoherentImage),
            UntilIpReached => unreachable!("until parameter is set to None"),
        }
    }

    /// Proceed decoding the instructions until next decision point, considering the current PT
    /// packet is a TNT
    fn proceed_inst_tnt<CE: Debug + AddAssign + From<u8>>(
        &mut self,
        tnt_iter: TntIter,
        iteration_state: &mut CovDecIterationState<CE>,
    ) -> Result<(), PtDecoderError> {
        use ProceedInstStopReason::*;
        #[cfg(feature = "log_packets")]
        log::trace!("TNT handling start");

        for tnt in tnt_iter {
            'inst: loop {
                match self.proceed_inst_until(None)? {
                    // TNT consumed at the current decision point
                    CondBranch { to } => {
                        if tnt {
                            self.add_coverage_entry(to, iteration_state);
                            self.state.ip = to;
                            #[cfg(feature = "log_packets")]
                            log::trace!("TNT taken to 0x{:x}", self.state.ip);
                        } else {
                            #[cfg(feature = "log_packets")]
                            log::trace!("TNT not taken");
                        }
                        break 'inst;
                    }
                    #[cfg(feature = "retc")]
                    Return => {
                        if tnt {
                            let to = self.state.ret_comp_stack.pop().expect("empty ret stack"); //todo better error handling
                            self.add_coverage_entry(to, iteration_state);
                            self.state.ip = to;
                        } else {
                            todo!("better error: broken return compression")
                        }
                        break 'inst;
                    }

                    // TNT NOT consumed at the current decision point, handle the decision point
                    // and continue in the loop without consuming the TNT
                    #[cfg_attr(feature = "retc", expect(unreachable_patterns))]
                    Indirect | FarIndirect | Return => {
                        // handle possible deferred tips
                        let deferred = iteration_state.packet_decoder.next_packet()?;
                        let tip = if let PtPacket::Tip(tip) = deferred {
                            tip
                        } else {
                            return Err(PtDecoderError::InvalidPacketSequence {
                                packets: vec![deferred],
                            }); // todo add tnt here to the sequence
                        };

                        if tip.ip(&mut self.state.tip_last_ip) {
                            self.add_coverage_entry(self.state.tip_last_ip, iteration_state);
                            self.state.ip = self.state.tip_last_ip;
                        } else {
                            return Err(PtDecoderError::MalformedPacket);
                        };
                    }
                    MovCr3 => return Err(PtDecoderError::IncoherentImage),
                    UntilIpReached => unreachable!("until parameter is set to None"),
                }
            }
        }

        #[cfg(feature = "log_packets")]
        log::trace!("TNT handling end");
        Ok(())
    }

    fn proceed_inst_until(
        &mut self,
        until: Option<u64>,
    ) -> Result<ProceedInstStopReason, PtDecoderError> {
        use ProceedInstStopReason::*;

        if !self.state.packet_en {
            return Err(PtDecoderError::IncoherentState);
        }

        // Use cache (only if until is None)
        if until.is_none()
            && let Some(&(ip, reason)) = self.proceed_inst_cache.get(&self.state.ip)
        {
            self.state.ip = ip;
            return Ok(reason);
        }

        let from = self.state.ip;
        let mut inst_decoder = self.state.new_inst_decoder(&self.builder.images)?;
        let ins = loop {
            if let Some(ip) = until
                && inst_decoder.ip() == ip
            {
                return Ok(UntilIpReached);
            }

            if !inst_decoder.can_decode() {
                inst_decoder = self
                    .state
                    .reposition_inst_decoder(inst_decoder, &self.builder.images)?;
            }

            let ins = inst_decoder.decode();
            #[cfg(feature = "log_instructions")]
            log::trace!(
                "\tip: 0x{:x}: {:?} {:?}",
                inst_decoder.ip() - ins.len() as u64,
                ins.code(),
                ins.op0_kind(),
            );
            if ins.is_invalid() {
                return Err(PtDecoderError::MalformedInstruction);
            }
            // todo log call for retcomp

            match next_ip(&ins) {
                Ok(None) => {}
                Ok(Some(ip)) => {
                    self.state.ip = ip;
                    inst_decoder = self
                        .state
                        .reposition_inst_decoder(inst_decoder, &self.builder.images)?;
                }
                Err(()) => {
                    self.state.ip = inst_decoder.ip();
                    break ins;
                }
            }
        };

        let ret = match InstructionClass::from(&ins) {
            InstructionClass::CondBranch => CondBranch {
                to: ins.near_branch64(),
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

        self.proceed_inst_cache.insert(from, (self.state.ip, ret));
        Ok(ret)
    }

    fn add_coverage_entry<CE: Debug + AddAssign + From<u8>>(
        &mut self,
        to_ip: u64,
        iteration_state: &mut CovDecIterationState<CE>,
    ) {
        if self.state.save_coverage {
            let cov_entry = coverage_entry(self.state.ip, to_ip, iteration_state.coverage.len());
            iteration_state.coverage[cov_entry] += 1.into();
        }
    }
}

/// Retuns Ok(Some(ip)) if it can compute next ip from instruction, and it is not the subsequent
/// instruction in the code. Returns Ok(None) if the next instruction is the following in the code.
///Returns Err if decoding needs trace to proceed.
fn next_ip(ins: &Instruction) -> Result<Option<u64>, ()> {
    match InstructionClass::from(ins) {
        InstructionClass::Other => Ok(None),
        InstructionClass::JumpDirect | InstructionClass::CallDirect => {
            Ok(Some(ins.near_branch_target()))
        }
        InstructionClass::JumpIndirect
        | InstructionClass::MovCr3
        | InstructionClass::CallIndirect
        | InstructionClass::CondBranch
        | InstructionClass::FarCall
        | InstructionClass::FarJump
        | InstructionClass::FarReturn
        | InstructionClass::Return => Err(()),
    }
}

const fn coverage_entry(from: u64, to: u64, map_len: usize) -> usize {
    (fmix64(from) ^ fmix64(to)) as usize % map_len
}

fn decode_psbplus<CE: Debug>(
    iteration_state: &mut CovDecIterationState<CE>,
    cpu: Option<PtCpu>,
) -> Result<ExecutionState, PtDecoderError> {
    let mut state = ExecutionState::new();

    loop {
        match iteration_state.packet_decoder.next_packet()? {
            PtPacket::PsbEnd(..) => return Ok(state),
            #[cfg(feature = "tsc")]
            PtPacket::Tsc(..) => todo!(),
            #[cfg(all(feature = "tsc", feature = "mtc"))]
            PtPacket::Tma(..) => todo!(),
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
            #[cfg(feature = "cyc")]
            PtPacket::Cyc(..) => todo!(),
            #[cfg(feature = "mtc")]
            PtPacket::Mtc(..) => todo!(),
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
