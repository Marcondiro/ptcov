use crate::packet::SizedPtPacket;

#[derive(Debug, PartialEq)]
pub struct Ovf {}

impl Ovf {
    pub(crate) const SIZE: usize = 2;
    pub(crate) const B1: u8 = 0xf3;
}

impl SizedPtPacket for Ovf {
    fn original_size(&self) -> usize {
        Self::SIZE
    }
}
