use crate::packet::{PtPacketParseError, SizedPtPacket};

#[derive(Debug, PartialEq)]
pub struct Trig {
    raw: [u8; 2],
}

impl SizedPtPacket for Trig {
    fn original_size(&self) -> usize {
        Self::SIZE
    }
}

impl Trig {
    pub(crate) const SIZE: usize = 3;
    pub(super) fn try_from_payload(payload: &[u8]) -> Result<Self, PtPacketParseError> {
        let raw = payload
            .get(..2)
            .ok_or(PtPacketParseError::MalformedPacket)?
            .try_into()
            .unwrap();

        Ok(Self { raw })
    }
}
