pub struct Pwrx {}
impl Pwrx {
    pub(crate) const B1: u8 = 0xa2;
    pub(crate) const SIZE: usize = 7;
}

pub struct Pwre {}
impl Pwre {
    pub(crate) const B1: u8 = 0x22;
    pub(crate) const SIZE: usize = 4;
}

pub struct Mwait {}
impl Mwait {
    pub(crate) const B1: u8 = 0xc2;
    pub(crate) const SIZE: usize = 10;
}

pub struct Exstop {}
impl Exstop {
    pub(crate) const SIZE: usize = 2;
}
