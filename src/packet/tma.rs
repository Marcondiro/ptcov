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
        let raw: [u8; 5] = payload
            .get(..5)
            .ok_or(PtPacketParseError::MalformedPacket)?
            .try_into()
            .unwrap();

        if raw[2] & 0x01 != 0 {
            return Err(PtPacketParseError::MalformedPacket);
        }

        let ctc = u16::from_le_bytes([raw[0], raw[1]]);
        let fast_counter = u16::from_le_bytes([raw[3], raw[4] & 0x01]);

        Ok(Self { ctc, fast_counter })
    }
}
