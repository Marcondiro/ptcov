use crate::packet::{PtPacketParseError, SizedPtPacket};

#[derive(Debug, PartialEq, Clone)]
pub struct Tma {
    ctc: u16,
    fast_counter: u16,
}

impl SizedPtPacket for Tma {
    fn original_size(&self) -> usize {
        7
    }
}

impl Tma {
    pub(super) fn try_from_payload(payload: &[u8]) -> Result<Self, PtPacketParseError> {
        if payload.len() < 5 {
            return Err(PtPacketParseError::MalformedPacket);
        }

        if payload[2] & 0x01 != 0 {
            return Err(PtPacketParseError::MalformedPacket);
        }

        let ctc = u16::from_le_bytes([payload[0], payload[1]]);
        let fast_counter = u16::from_le_bytes([payload[3], payload[4] & 0x01]);

        Ok(Self { ctc, fast_counter })
    }
}
