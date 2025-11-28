use crate::packet::SizedPtPacket;

#[derive(Debug, PartialEq)]
pub struct Cbr {
    // core_bus_ratio: u8,
}

impl SizedPtPacket for Cbr {
    fn original_size(&self) -> usize {
        Self::SIZE
    }
}

impl Cbr {
    pub(crate) const B1: u8 = 0x03;
    pub(crate) const SIZE: usize = 4;

    // pub const fn core_bus_ratio(&self) -> u8 {
    //     self.core_bus_ratio
    // }

    // pub(super) fn try_from_payload(payload: &[u8]) -> Result<Self, PtPacketParseError> {
    //     let &[core_bus_ratio, _] = payload
    //         .get(0..2)
    //         .ok_or(PtPacketParseError::MalformedPacket)?
    //         .try_into()
    //         .unwrap();

    //     Ok(Self { core_bus_ratio })
    // }
}
