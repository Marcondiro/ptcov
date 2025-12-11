use crate::packet::SizedPtPacket;

#[derive(Debug, PartialEq, Clone)]
pub struct Bbp {}

#[derive(Debug, PartialEq, Clone)]
pub struct Bep {}

// #[derive(Debug, PartialEq)]
// pub struct Bip {}

impl SizedPtPacket for Bbp {
    fn original_size(&self) -> usize {
        3
    }
}

impl SizedPtPacket for Bep {
    fn original_size(&self) -> usize {
        2
    }
}

// impl SizedPtPacket for Bip {
//     fn original_size(&self) -> usize {
//         todo!()
//     }
// }
