use crate::packet::SizedPtPacket;

#[derive(Debug, PartialEq)]
pub struct Evd {}

impl SizedPtPacket for Evd {
    fn original_size(&self) -> usize {
        todo!()
    }
}
