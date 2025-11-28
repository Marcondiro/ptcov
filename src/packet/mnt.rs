use crate::packet::{PtPacketParseError, SizedPtPacket};

#[derive(Debug, PartialEq)]
pub struct Mnt {
    raw: [u8; 8],
}

impl SizedPtPacket for Mnt {
    fn original_size(&self) -> usize {
        Self::SIZE
    }
}

impl Mnt {
    pub(crate) const SIZE: usize = 11;
    // pub fn payload(&self) -> &[u8] {
    //     &self.raw
    // }

    pub(super) fn try_from_payload(payload: &[u8]) -> Result<Self, PtPacketParseError> {
        let raw = payload
            .get(0..8)
            .ok_or(PtPacketParseError::MalformedPacket)?
            .try_into()
            .unwrap();

        Ok(Self { raw })
    }
}
