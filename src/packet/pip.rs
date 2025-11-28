use crate::packet::{PtPacketParseError, SizedPtPacket};

#[derive(Debug, PartialEq)]
pub struct Pip {
    pub(crate) raw: [u8; 6],
}

impl SizedPtPacket for Pip {
    fn original_size(&self) -> usize {
        Self::SIZE
    }
}

impl Pip {
    pub(crate) const SIZE: usize = 8;
    pub(crate) const B1: u8 = 0x43;
    // pub const fn cr3(&self) -> u64 {
    //     let o = &self.raw;
    //     let extended = [o[0] & 0xfe, o[1], o[2], o[3], o[4], o[5], 0, 0];
    //
    //     u64::from_le_bytes(extended) << 5
    // }

    pub const fn non_root_vmx(&self) -> bool {
        self.raw[0] & 0x01 != 0
    }

    /// Caller must check the header and pass just the payload
    pub(super) fn try_from_payload(payload: &[u8]) -> Result<Self, PtPacketParseError> {
        let raw = payload
            .get(..6)
            .ok_or(PtPacketParseError::MalformedPacket)?
            .try_into()
            .unwrap();

        Ok(Self { raw })
    }
}
