use crate::PtDecoderError;
use crate::cpu::PtCpu;
use crate::image::PtImage;
use crate::packet::PtPacket;
use crate::packet::decoder::PtPacketDecoder;
use crate::packet::mode::{AddressingMode, ModeExec, ModeTsx, TransactionState};
use crate::packet::pip::Pip;
use crate::packet::tip::{Fup, Tip, TipPgd, TipPge};
use crate::packet::tnt::TntIter;
use crate::packet::vmcs::Vmcs;
use crate::utils::fmix64;
use iced_x86::{Code, FlowControl, Instruction, Register};
use std::fmt::Debug;
use std::ops::AddAssign;

#[derive(Debug, Clone, PartialEq)]
pub struct PtCoverageDecoderBuilder {
    cpu: Option<PtCpu>, // todo: consider if caching the errata makes sense
    filter_vmx_non_root: bool,
    ignore_coverage_until: usize,
}

pub struct PtCoverageDecoder<'a, CE>
where
    CE: Debug,
{
    builder: PtCoverageDecoderBuilder,

    images: &'a [PtImage],
    state: State,
    packet_decoder: PtPacketDecoder<'a>,
    inst_decoder: (iced_x86::Decoder<'a>, &'a PtImage),

    coverage: &'a mut [CE],
}

#[derive(Debug, PartialEq)]
struct State {
    packet_en: bool,
    pip: Pip,
    tip_last_ip: u64,
    vmcs: Option<Vmcs>,
    mode_exec: ModeExec,
    mode_tsx: ModeTsx,
    save_coverage: bool,
    #[cfg(feature = "retc")]
    ret_comp_stack: Vec<u64>,
}

#[derive(Debug)]
enum ProceedInstStopReason {
    CondBranch { to: u64 },
    FarIndirect,
    Indirect,
    MovCr3,
    Return,
    UntilIpReached,
}

impl State {
    fn new() -> Self {
        Self {
            packet_en: false,
            pip: Pip { raw: [0; 6] },
            tip_last_ip: 0, // SDM 34.4.2.2 “Last IP” is initialized to zero
            vmcs: None,
            mode_exec: ModeExec::new(AddressingMode::_16, false),
            mode_tsx: ModeTsx::new(TransactionState::Commit),
            save_coverage: true,
            #[cfg(feature = "retc")]
            ret_comp_stack: Vec::with_capacity(64),
        }
    }
}

impl PtCoverageDecoderBuilder {
    // fixme: const hack
    const fn default_const() -> Self {
        Self {
            cpu: None,
            filter_vmx_non_root: false,
            ignore_coverage_until: 0,
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

    pub const fn ignore_coverage_until(mut self, ignore_coverage_until: usize) -> Self {
        self.ignore_coverage_until = ignore_coverage_until;
        self
    }

    pub fn build<'a, CE: Debug>(
        self,
        trace: &'a [u8],
        images: &'a [PtImage],
        coverage: &'a mut [CE],
    ) -> Result<PtCoverageDecoder<'a, CE>, PtDecoderError> {
        let mut packet_decoder = PtPacketDecoder::new(trace)?;
        // Ignore first PSB packet
        let _ = packet_decoder.next();
        let state = decode_psbplus(&mut packet_decoder, self.cpu)?;
        let first_image = images.first().ok_or(PtDecoderError::MissingImage)?;
        let inst_decoder = (
            iced_x86::Decoder::new(
                state.mode_exec.addressing_mode().into(),
                first_image.data(),
                iced_x86::DecoderOptions::NONE,
            ),
            first_image,
        );

        Ok(PtCoverageDecoder {
            builder: self,
            packet_decoder,
            state,
            inst_decoder,
            images,
            coverage,
        })
    }
}

impl Default for PtCoverageDecoderBuilder {
    fn default() -> Self {
        Self::default_const()
    }
}

impl<'a, CE> PtCoverageDecoder<'a, CE>
where
    CE: AddAssign + Debug + From<u8>,
{
    #[inline]
    pub const fn pkt_dec_position(&self) -> usize {
        self.packet_decoder.position()
    }

    #[inline]
    pub const fn pkt_dec_last_sync_pos(&self) -> usize {
        self.packet_decoder.last_sync_position()
    }

    pub fn coverage(&mut self) -> Result<(), PtDecoderError> {
        loop {
            match self.proceed_with_trace() {
                Ok(()) => continue,
                Err(PtDecoderError::Eof) => break Ok(()),
                Err(e) => break Err(e),
            }
        }
    }

    /// Continue decoding using PT trace.
    /// Can consume one or more PT packets.
    fn proceed_with_trace(&mut self) -> Result<(), PtDecoderError> {
        let packet = self.packet_decoder.next_packet()?;

        match packet {
            PtPacket::TntShort(tnt_s) => self.proceed_inst_tnt(tnt_s.into_iter().into())?,
            PtPacket::TntLong(tnt_l) => self.proceed_inst_tnt(tnt_l.into_iter().into())?,
            PtPacket::Tip(tip) => self.proceed_inst_tip(tip)?,
            PtPacket::TipPge(tip_pge) => self.handle_tip_pge(tip_pge)?,
            PtPacket::TipPgd(tip_pgd) => self.handle_tip_pgd(tip_pgd)?,
            PtPacket::Fup(fup) => self.handle_fup(fup)?,
            PtPacket::Pip(pip) => self.handle_pip(pip)?,
            PtPacket::ModeExec(mode_exec) => self.handle_mode_exec(mode_exec)?,
            PtPacket::ModeTsx(mode_tsx) => self.handle_mode_tsx(mode_tsx)?,
            PtPacket::TraceStop(..) => {} // todo
            PtPacket::Vmcs(..) => {}      //todo
            PtPacket::Ovf(..) => {}       //todo
            PtPacket::Psb(..) => {
                self.state = decode_psbplus(&mut self.packet_decoder, self.builder.cpu)?
            }
            PtPacket::PsbEnd(..) => return Err(PtDecoderError::InvalidPacketSequence),
            _ => {} // Ignore other packets
        };
        Ok(())
    }

    fn handle_mode_tsx(&mut self, mode_tsx: ModeTsx) -> Result<(), PtDecoderError> {
        // todo: double check this function
        if self.state.packet_en {
            match self.packet_decoder.next_packet()? {
                PtPacket::Fup(fup) => self.handle_standalone_fup(fup)?,
                _ => return Err(PtDecoderError::InvalidPacketSequence),
            }

            if mode_tsx.transaction_state() == TransactionState::Abort {
                match self.packet_decoder.next_packet()? {
                    PtPacket::Tip(tip) => self.proceed_inst_tip(tip)?,
                    PtPacket::TipPge(tip_pge) => self.handle_tip_pge(tip_pge)?,
                    PtPacket::TipPgd(tip_pgd) => self.handle_tip_pgd(tip_pgd)?,
                    _ => return Err(PtDecoderError::InvalidPacketSequence),
                }
            }
        }

        self.state.mode_tsx = mode_tsx;
        Ok(())
    }

    fn handle_standalone_fup(&mut self, fup: Fup) -> Result<(), PtDecoderError> {
        if !fup.ip(&mut self.state.tip_last_ip) {
            return Err(PtDecoderError::MalformedPacket);
        }

        if matches!(
            self.proceed_inst_until(Some(self.state.tip_last_ip))?,
            ProceedInstStopReason::UntilIpReached
        ) {
            Ok(())
        } else {
            Err(PtDecoderError::IncoherentImage)
        }
    }

    fn handle_mode_exec(&mut self, mode_exec: ModeExec) -> Result<(), PtDecoderError> {
        match self.packet_decoder.next_packet()? {
            PtPacket::Tip(tip) => self.proceed_inst_tip(tip)?,
            PtPacket::TipPge(tip_pge) => self.handle_tip_pge(tip_pge)?,
            PtPacket::Fup(fup) => self.handle_standalone_fup(fup)?,
            _ => return Err(PtDecoderError::InvalidPacketSequence),
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

    fn handle_fup(&mut self, fup: Fup) -> Result<(), PtDecoderError> {
        self.handle_standalone_fup(fup)?;
        loop {
            let packet = self.packet_decoder.next_packet()?;
            match packet {
                PtPacket::Pip(pip) => self.handle_async_pip(pip),
                PtPacket::Vmcs(..) => todo!("handle fup vmcs"),
                PtPacket::ModeExec(..) => todo!("handle fup mode exec"),
                PtPacket::Tip(tip) => break self.handle_async_tip(tip)?,
                PtPacket::TipPgd(tip_pgd) => break self.handle_async_tip_pgd(tip_pgd),
                // todo: timing packets are ok here, handle them, else invalid in fup compound packet
                _ => return Err(PtDecoderError::InvalidPacketSequence),
            }
        }
        Ok(())
    }

    fn handle_async_tip(&mut self, tip: Tip) -> Result<(), PtDecoderError> {
        if tip.ip(&mut self.state.tip_last_ip) {
            self.inst_decoder.0.set_ip(self.state.tip_last_ip);
            Ok(())
        } else {
            // we jumped somewhere but who knows where?
            Err(PtDecoderError::InvalidPacketSequence)
        }
    }

    fn handle_async_tip_pgd(&mut self, tip_pgd: TipPgd) {
        self.state.packet_en = false;
        if tip_pgd.ip(&mut self.state.tip_last_ip) {
            self.inst_decoder.0.set_ip(self.state.tip_last_ip);
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
            self.inst_decoder.0.set_ip(self.state.tip_last_ip);
            Ok(())
        } else {
            Err(PtDecoderError::MalformedPacket)
        }
    }

    fn proceed_inst_tip(&mut self, tip: Tip) -> Result<(), PtDecoderError> {
        use ProceedInstStopReason::*;

        match self.proceed_inst_until(None)? {
            Indirect | FarIndirect | Return => {
                if tip.ip(&mut self.state.tip_last_ip) {
                    self.add_coverage_entry(self.state.tip_last_ip);
                    self.inst_decoder.0.set_ip(self.state.tip_last_ip);
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
    fn proceed_inst_tnt(&mut self, mut tnt_iter: TntIter) -> Result<(), PtDecoderError> {
        use ProceedInstStopReason::*;
        #[cfg(feature = "log")]
        log::trace!("TNT handling start");

        while tnt_iter.has_next() {
            match self.proceed_inst_until(None)? {
                CondBranch { to } => {
                    if tnt_iter.next().unwrap() {
                        self.add_coverage_entry(to);
                        self.inst_decoder.0.set_ip(to);
                        #[cfg(feature = "log")]
                        log::trace!("TNT taken to 0x{:x}", self.inst_decoder.0.ip());
                    } else {
                        #[cfg(feature = "log")]
                        log::trace!("TNT not taken");
                    }
                }
                #[cfg(feature = "retc")]
                Return => {
                    if tnt_iter.next().unwrap() {
                        let to = self.state.ret_comp_stack.pop().expect("empty ret stack"); //todo better error handling
                        self.add_coverage_entry(to);
                        self.inst_decoder.0.set_ip(to);
                    } else {
                        todo!("better error: broken return compression")
                    }
                }
                #[cfg_attr(feature = "retc", expect(unreachable_patterns))]
                Indirect | FarIndirect | Return => {
                    // handle possible deferred tips
                    let deferred = self.packet_decoder.next_packet()?;
                    let tip = if let PtPacket::Tip(tip) = deferred {
                        tip
                    } else {
                        return Err(PtDecoderError::InvalidPacketSequence);
                    };

                    if tip.ip(&mut self.state.tip_last_ip) {
                        self.add_coverage_entry(self.state.tip_last_ip);
                        self.inst_decoder.0.set_ip(self.state.tip_last_ip);
                    } else {
                        return Err(PtDecoderError::MalformedPacket);
                    };
                }
                MovCr3 => return Err(PtDecoderError::IncoherentImage),
                UntilIpReached => unreachable!("until parameter is set to None"),
            }
        }

        #[cfg(feature = "log")]
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

        self.reposition_inst_decoder()?;
        let mut ins = Instruction::new();
        loop {
            if let Some(ip) = until
                && self.inst_decoder.0.ip() == ip
            {
                return Ok(UntilIpReached);
            }

            if !self.inst_decoder.0.can_decode() {
                self.reposition_inst_decoder()?;
            }

            self.inst_decoder.0.decode_out(&mut ins);
            #[cfg(feature = "log")]
            log::trace!(
                "\tip: 0x{:x}: {:?} {:?}",
                self.inst_decoder.0.ip(),
                ins.code(),
                ins.op0_kind(),
            );
            if ins.is_invalid() {
                return Err(PtDecoderError::MalformedInstruction);
            }
            // todo log call for retcomp

            if self.update_ip_needs_trace(&ins)? {
                break;
            }
        }

        Ok(match InstructionClass::from(&ins) {
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
        })
    }

    /// Position instruction decoder using the image that includes the current IP
    fn reposition_inst_decoder(&mut self) -> Result<(), PtDecoderError> {
        let (decoder, image) = &mut self.inst_decoder;
        if decoder.ip() <= image.virtual_address_start()
            || decoder
                .set_position((decoder.ip() - image.virtual_address_start()) as usize)
                .is_err()
        {
            let image = self
                .images
                .iter()
                .find(|&image| {
                    self.inst_decoder.0.ip() >= image.virtual_address_start()
                        && self.inst_decoder.0.ip() <= image.virtual_address_end()
                })
                .ok_or(PtDecoderError::MissingImage)?;

            let mut decoder = iced_x86::Decoder::with_ip(
                self.state.mode_exec.addressing_mode().into(),
                image.data(),
                self.inst_decoder.0.ip(),
                iced_x86::DecoderOptions::NONE,
            );
            decoder
            .set_position((self.inst_decoder.0.ip() - image.virtual_address_start()) as usize)
            .expect(
                "current IP should be in the current image, otherwise we should have Err before",
            );

            #[cfg(feature = "log")]
            log::trace!(
                "Using image starting at: 0x{:x}",
                image.virtual_address_start()
            );
            self.inst_decoder = (decoder, image);
        }
        Ok(())
    }

    fn add_coverage_entry(&mut self, to_ip: u64) {
        if self.state.save_coverage
            && self.packet_decoder.position() > self.builder.ignore_coverage_until
        {
            let cov_entry = coverage_entry(self.inst_decoder.0.ip(), to_ip, self.coverage.len());
            self.coverage[cov_entry] += 1.into();
        }
    }

    /// Retuns true if decoding needs trace to proceed
    fn update_ip_needs_trace(&mut self, ins: &Instruction) -> Result<bool, PtDecoderError> {
        Ok(match InstructionClass::from(ins) {
            InstructionClass::Other => false,
            InstructionClass::JumpDirect | InstructionClass::CallDirect => {
                self.inst_decoder.0.set_ip(ins.near_branch_target());
                self.reposition_inst_decoder()?;

                false
            }
            InstructionClass::JumpIndirect
            | InstructionClass::MovCr3
            | InstructionClass::CallIndirect
            | InstructionClass::CondBranch
            | InstructionClass::FarCall
            | InstructionClass::FarJump
            | InstructionClass::FarReturn
            | InstructionClass::Return => true,
        })
    }
}

const fn coverage_entry(from: u64, to: u64, map_len: usize) -> usize {
    (fmix64(from) ^ fmix64(to)) as usize % map_len
}

fn decode_psbplus(
    packet_decoder: &mut PtPacketDecoder,
    cpu: Option<PtCpu>,
) -> Result<State, PtDecoderError> {
    let mut state = State::new();

    // packet_decoder
    loop {
        match packet_decoder.next_packet()? {
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
