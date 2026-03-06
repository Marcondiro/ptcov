#[derive(Debug, PartialEq, Clone)]
pub struct Trig {
    pub(super) raw: [u8; 2],
}

impl Trig {
    pub(crate) const SIZE: usize = 3;
}
