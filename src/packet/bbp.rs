pub struct Bbp {}

// #[derive(Debug, PartialEq, Clone)]
// pub struct Bep {}

// #[derive(Debug, PartialEq)]
// pub struct Bip {}

impl Bbp {
    pub(crate) const B1: u8 = 0x63;
    pub(crate) const SIZE: usize = 3;
}
//
// impl SizedPtPacket for Bep {
//     fn original_size(&self) -> usize {
//         2
//     }
// }
