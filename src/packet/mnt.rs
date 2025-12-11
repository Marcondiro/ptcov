use crate::packet::SizedPtPacket;

#[derive(Debug, PartialEq, Clone)]
pub struct Mnt {
    pub(super) raw: [u8; 8],
}

impl SizedPtPacket for Mnt {
    fn original_size(&self) -> usize {
        Self::SIZE
    }
}

impl Mnt {
    pub(crate) const SIZE: usize = 11;
}
