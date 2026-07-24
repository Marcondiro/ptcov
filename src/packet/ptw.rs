use crate::packet::PtPacketParseError;

pub struct Ptw {}

impl Ptw {
    const HEADER_SIZE: usize = 2;
    pub const fn size(b1: u8) -> Result<usize, PtPacketParseError> {
        let payload_size = match (b1 >> 5) & 0b11 {
            0b00 => 4,
            0b01 => 8,
            _ => return Err(PtPacketParseError::MalformedPacket),
        };
        Ok(Self::HEADER_SIZE + payload_size)
    }
}
