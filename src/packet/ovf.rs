/// Overflow (OVF) packet, indicating a PT buffer overflow.
#[derive(Debug, PartialEq, Clone)]
pub struct Ovf {}

impl Ovf {
    pub(crate) const SIZE: usize = 2;
    pub(crate) const B1: u8 = 0xf3;
}
