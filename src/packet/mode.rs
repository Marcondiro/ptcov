use crate::packet::{PtPacketParseError, SizedPtPacket};
use std::fmt::{Debug, Formatter};

pub(crate) const SIZE: usize = 2;
pub(crate) const B0: u8 = 0x99;
pub(crate) const B1_MASK: u8 = 0xe0;

#[derive(PartialEq)]
pub struct ModeExec {
    raw: u8,
}

#[derive(Debug, PartialEq)]
pub struct ModeTsx {
    transaction_state: TransactionState,
}

#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u8)]
pub enum AddressingMode {
    _16 = 0b00,
    _32 = 0b10,
    _64 = 0b01,
}

#[derive(Debug, PartialEq, Clone, Copy)]
#[repr(u8)]
pub enum TransactionState {
    /// Transaction begins, or executing transactionally
    Begin = 0b01,
    /// Transaction aborted
    Abort = 0b10,
    /// Transaction committed, or not executing transactionally
    Commit = 0b00,
}

impl ModeExec {
    pub(crate) const B1: u8 = 0x00;

    pub const fn addressing_mode(&self) -> AddressingMode {
        match self.raw & 0x03 {
            _16 if _16 == AddressingMode::_16 as u8 => AddressingMode::_16,
            _32 if _32 == AddressingMode::_32 as u8 => AddressingMode::_32,
            _64 if _64 == AddressingMode::_64 as u8 => AddressingMode::_64,
            _ => panic!("ModeExec contains an invalid address mode"),
        }
    }

    pub const fn interrupt_flag(&self) -> bool {
        self.raw & 0x04 != 0
    }

    pub(crate) const fn new(addressing_mode: AddressingMode, interrupt_flag: bool) -> Self {
        let raw = ((interrupt_flag as u8) << 2) | addressing_mode as u8;
        Self { raw }
    }

    pub(super) const fn try_from_payload(payload: u8) -> Result<Self, PtPacketParseError> {
        if payload & 0x03 == 0x03 {
            // Invalid addressing mode
            Err(PtPacketParseError::MalformedPacket)
        } else {
            Ok(Self { raw: payload })
        }
    }
}

impl ModeTsx {
    pub(crate) const B1: u8 = 0x20;

    pub const fn transaction_state(&self) -> TransactionState {
        self.transaction_state
    }

    pub(crate) const fn new(transaction_state: TransactionState) -> Self {
        Self { transaction_state }
    }

    pub(super) const fn try_from_payload(payload: u8) -> Result<Self, PtPacketParseError> {
        let transaction_state = match payload & 0x03 {
            begin if begin == TransactionState::Begin as u8 => TransactionState::Begin,
            abort if abort == TransactionState::Abort as u8 => TransactionState::Abort,
            commit if commit == TransactionState::Commit as u8 => TransactionState::Commit,
            _ => return Err(PtPacketParseError::MalformedPacket), // Invalid transaction state
        };

        Ok(Self { transaction_state })
    }
}

impl Debug for ModeExec {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let addressing_mode = self.addressing_mode();
        let interrupt_flag = self.interrupt_flag();
        write!(
            f,
            "ModeExec {{ addressing_mode: {addressing_mode:?}, interrupt_flag: {interrupt_flag:?}}}"
        )
    }
}

impl From<AddressingMode> for u32 {
    fn from(value: AddressingMode) -> Self {
        match value {
            AddressingMode::_16 => 16,
            AddressingMode::_32 => 32,
            AddressingMode::_64 => 64,
        }
    }
}

macro_rules! impl_mode_sized_pt_packet {
    ($($ty:ty),+ $(,)?) => {
        $(
            impl SizedPtPacket for $ty {
                fn original_size(&self) -> usize {
                    SIZE
                }
            }
        )+
    };
}
impl_mode_sized_pt_packet!(ModeExec, ModeTsx);
