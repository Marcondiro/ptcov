use crate::packet::SizedPtPacket;

#[derive(Debug, PartialEq, Clone)]
pub struct Tsc {
    raw: [u8; 7],
}

impl SizedPtPacket for Tsc {
    fn original_size(&self) -> usize {
        Self::SIZE
    }
}

impl Tsc {
    pub(crate) const SIZE: usize = 8;

    // pub(super) fn try_from_payload(payload: &[u8]) -> Result<Self, PtPacketParseError> {
    //     // the try_into cannot fail, therefore the unwrap() can never panic.
    //     let raw = payload
    //         .get(..8)
    //         .ok_or(PtPacketParseError::MalformedPacket)?
    //         .try_into()
    //         .unwrap();
    //
    //     Ok(Self { raw })
    // }
}
