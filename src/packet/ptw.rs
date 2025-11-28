use crate::packet::SizedPtPacket;

#[derive(Debug, PartialEq)]
pub struct Ptw {}

impl SizedPtPacket for Ptw {
    fn original_size(&self) -> usize {
        todo!()
    }
}
