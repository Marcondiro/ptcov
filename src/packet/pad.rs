#[derive(Debug, PartialEq)]
pub(super) struct Pad {}

impl Pad {
    pub(crate) const B0: u8 = 0x00;
    pub(crate) const SIZE: usize = 1;
}
