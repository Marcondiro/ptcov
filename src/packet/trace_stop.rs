use crate::packet::SizedPtPacket;

#[derive(Debug, PartialEq, Clone)]
pub struct TraceStop {}

impl TraceStop {
    pub(crate) const SIZE: usize = 2;
    pub(crate) const B1: u8 = 0x83;
}

impl SizedPtPacket for TraceStop {
    fn original_size(&self) -> usize {
        Self::SIZE
    }
}
