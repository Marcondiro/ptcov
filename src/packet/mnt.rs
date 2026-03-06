#[derive(Debug, PartialEq, Clone)]
pub struct Mnt {
    pub(super) raw: [u8; 8],
}

impl Mnt {
    pub(crate) const SIZE: usize = 11;
}
