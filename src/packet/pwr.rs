use crate::packet::SizedPtPacket;

#[derive(Debug, PartialEq, Clone)]
pub struct Pwrx {}

impl SizedPtPacket for Pwrx {
    fn original_size(&self) -> usize {
        todo!()
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct Pwre {}

impl SizedPtPacket for Pwre {
    fn original_size(&self) -> usize {
        todo!()
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct Mwait {}

impl SizedPtPacket for Mwait {
    fn original_size(&self) -> usize {
        todo!()
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct Exstop {}

impl SizedPtPacket for Exstop {
    fn original_size(&self) -> usize {
        todo!()
    }
}
