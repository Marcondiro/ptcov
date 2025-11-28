use crate::packet::SizedPtPacket;

#[derive(Debug, PartialEq)]
pub struct Cfe {}

impl SizedPtPacket for Cfe {
    fn original_size(&self) -> usize {
        todo!()
    }
}
