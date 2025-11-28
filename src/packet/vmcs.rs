use crate::packet::{PtPacketParseError, SizedPtPacket};

#[derive(Debug, PartialEq)]
#[repr(transparent)]
pub struct Vmcs {
    raw: [u8; 5],
}

impl SizedPtPacket for Vmcs {
    fn original_size(&self) -> usize {
        Self::SIZE
    }
}

impl Vmcs {
    pub(crate) const SIZE: usize = 7;
    pub(crate) const B1: u8 = 0xc8;
    // pub const fn vmcs_pointer(&self) -> u64 {
    //     let raw = [
    //         self.raw[0],
    //         self.raw[1],
    //         self.raw[2],
    //         self.raw[3],
    //         self.raw[4],
    //         0,
    //         0,
    //         0,
    //     ];
    //     u64::from_le_bytes(raw) << 12
    // }

    pub(super) fn try_from_payload(payload: &[u8]) -> Result<Self, PtPacketParseError> {
        let raw = payload
            .get(..5)
            .ok_or(PtPacketParseError::MalformedPacket)?
            .try_into()
            .unwrap();

        Ok(Self { raw })
    }
}
