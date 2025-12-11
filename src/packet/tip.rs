use crate::packet::{PtPacketParseError, SizedPtPacket};
use crate::utils::sign_extend_48;

#[derive(Debug, PartialEq, Clone)]
pub struct Tip {
    ip_bytes: IpBytes,
    target_ip: u64,
}

pub type TipPge = Tip;
pub type TipPgd = Tip;
pub type Fup = Tip;

#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u8)]
#[non_exhaustive]
pub enum IpBytes {
    None = IpBytes::NONE,
    _16 = IpBytes::C16,
    _32 = IpBytes::C32,
    SignExtend48 = IpBytes::SIGN_EXTEND48,
    _48 = IpBytes::C48,
    _64 = IpBytes::C64,
}

impl IpBytes {
    const NONE: u8 = 0b000 << 5;
    const C16: u8 = 0b001 << 5;
    const C32: u8 = 0b010 << 5;
    const SIGN_EXTEND48: u8 = 0b011 << 5;
    const C48: u8 = 0b100 << 5;
    const C64: u8 = 0b110 << 5;
}

impl SizedPtPacket for Tip {
    fn original_size(&self) -> usize {
        self.ip_bytes.original_size()
    }
}

impl Tip {
    const IPBYTES_MASK: u8 = 0b1110_0000;

    pub const fn ip(&self, last_tip_ip: &mut u64) -> bool {
        *last_tip_ip = match self.ip_bytes {
            IpBytes::None => return false,
            IpBytes::_16 => *last_tip_ip & 0xff_ff_ff_ff_ff_ff_00_00 | (self.target_ip & 0xff_ff),
            IpBytes::_32 => {
                *last_tip_ip & 0xff_ff_ff_ff_00_00_00_00 | (self.target_ip & 0xff_ff_ff_ff)
            }
            IpBytes::SignExtend48 => sign_extend_48(self.target_ip),
            IpBytes::_48 => {
                *last_tip_ip & 0xff_ff_00_00_00_00_00_00 | (self.target_ip & 0xff_ff_ff_ff_ff_ff)
            }
            IpBytes::_64 => self.target_ip,
        };
        true
    }

    /// Panics if input length is 0
    pub(super) fn try_from_payload(payload: &[u8]) -> Result<Self, PtPacketParseError> {
        Ok(match (payload[0] & Tip::IPBYTES_MASK, &payload[1..]) {
            (IpBytes::NONE, [..]) => Self {
                ip_bytes: IpBytes::None,
                target_ip: 0,
            },
            (IpBytes::C16, [b1, b2, ..]) => Self {
                ip_bytes: IpBytes::_16,
                target_ip: u16::from_le_bytes([*b1, *b2]) as u64,
            },
            (IpBytes::C32, [b1, b2, b3, b4, ..]) => Self {
                ip_bytes: IpBytes::_32,
                target_ip: u32::from_le_bytes([*b1, *b2, *b3, *b4]) as u64,
            },
            (IpBytes::C48, [b1, b2, b3, b4, b5, b6, ..]) => Self {
                ip_bytes: IpBytes::_48,
                target_ip: u64::from_le_bytes([*b1, *b2, *b3, *b4, *b5, *b6, 0, 0]),
            },
            (IpBytes::SIGN_EXTEND48, [b1, b2, b3, b4, b5, b6, ..]) => Self {
                ip_bytes: IpBytes::SignExtend48,
                target_ip: u64::from_le_bytes([*b1, *b2, *b3, *b4, *b5, *b6, 0, 0]),
            },
            (IpBytes::C64, [b1, b2, b3, b4, b5, b6, b7, b8, ..]) => Self {
                ip_bytes: IpBytes::_64,
                target_ip: u64::from_le_bytes([*b1, *b2, *b3, *b4, *b5, *b6, *b7, *b8]),
            },
            _ => return Err(PtPacketParseError::MalformedPacket),
        })
    }
}

impl IpBytes {
    const fn original_size(&self) -> usize {
        match self {
            IpBytes::None => 1,
            IpBytes::_16 => 3,
            IpBytes::_32 => 5,
            IpBytes::_48 | IpBytes::SignExtend48 => 7,
            IpBytes::_64 => 9,
        }
    }
}

impl TryFrom<u8> for IpBytes {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Ok(match value {
            IpBytes::NONE => IpBytes::None,
            IpBytes::C16 => IpBytes::_16,
            IpBytes::C32 => IpBytes::_32,
            IpBytes::SIGN_EXTEND48 => IpBytes::SignExtend48,
            IpBytes::C48 => IpBytes::_48,
            IpBytes::C64 => IpBytes::_64,
            _ => return Err(()),
        })
    }
}
