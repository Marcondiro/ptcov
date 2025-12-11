use crate::packet::SizedPtPacket;

#[derive(Debug, PartialEq, Clone)]
pub struct Trig {
    pub(super) raw: [u8; 2],
}

impl SizedPtPacket for Trig {
    fn original_size(&self) -> usize {
        Self::SIZE
    }
}

impl Trig {
    pub(crate) const SIZE: usize = 3;
}
