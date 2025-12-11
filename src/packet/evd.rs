use crate::packet::SizedPtPacket;

#[derive(Debug, PartialEq, Clone)]
pub struct Evd {}

impl SizedPtPacket for Evd {
    fn original_size(&self) -> usize {
        todo!()
    }
}
