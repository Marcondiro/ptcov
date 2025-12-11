use crate::packet::{PtPacketParseError, SizedPtPacket};

#[derive(Debug, PartialEq, Clone)]
pub struct Mtc {
    raw: u8,
}

impl SizedPtPacket for Mtc {
    fn original_size(&self) -> usize {
        2
    }
}

impl Mtc {
    pub(crate) fn try_from_payload(payload: &[u8]) -> Result<Self, PtPacketParseError> {
        if payload.is_empty() {
            Err(PtPacketParseError::MalformedPacket)
        } else {
            Ok(Self { raw: payload[0] })
        }
    }
}
