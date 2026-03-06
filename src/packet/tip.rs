use crate::packet::PtPacketParseError;
use crate::utils::sign_extend_48;

#[derive(Debug, PartialEq, Clone)]
pub struct Tip {
    ip_bytes: IpBytes,
    target_ip: u64,
}

pub type TipPge = Tip;
pub type TipPgd = Tip;
pub type Fup = Tip;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

impl Tip {
    const IPBYTES_MASK: u8 = 0b1110_0000;

    pub const fn original_size(&self) -> usize {
        self.ip_bytes.original_size()
    }

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

    pub(super) fn try_from_payload(b0: &u8, rest: &[u8]) -> Result<Self, PtPacketParseError> {
        let ip_bytes = IpBytes::try_from(b0 & Tip::IPBYTES_MASK)
            .map_err(|_| PtPacketParseError::MalformedPacket)?;
        if rest.len() < 8 {
            Self::try_from_payload_slow_path(ip_bytes, rest)
        } else {
            let target_ip = u64::from_le_bytes(rest[..8].try_into().unwrap());

            Ok(Self {
                ip_bytes,
                target_ip,
            })
        }
    }

    #[cold]
    fn try_from_payload_slow_path(
        ip_bytes: IpBytes,
        rest: &[u8],
    ) -> Result<Self, PtPacketParseError> {
        let payload_len = ip_bytes.original_size() - 1;
        if rest.len() < payload_len {
            return Err(PtPacketParseError::MalformedPacket);
        }

        let mut target_ip_bytes = [0; 8];
        target_ip_bytes[..payload_len].copy_from_slice(&rest[..payload_len]);
        let mut target_ip = u64::from_le_bytes(target_ip_bytes);

        if ip_bytes == IpBytes::SignExtend48 {
            target_ip = sign_extend_48(target_ip);
        }

        Ok(Self {
            ip_bytes,
            target_ip,
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
