use crate::packet::SizedPtPacket;

#[derive(Debug, PartialEq, Clone)]
#[repr(transparent)]
pub struct Vmcs {
    pub(super) raw: [u8; 5],
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
}
