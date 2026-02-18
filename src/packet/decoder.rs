use crate::PtDecoderError;
use crate::packet::psb::first_psb_position;
use crate::packet::{PtPacket, SizedPtPacket};

#[derive(Debug)]
pub struct PtPacketDecoder<'a> {
    buffer: &'a [u8],
    pos: usize,
}

impl<'a> PtPacketDecoder<'a> {
    pub const fn new_not_syncd(buffer: &'a [u8]) -> Self {
        Self { buffer, pos: 0 }
    }

    pub fn new(buffer: &'a [u8]) -> Result<Self, PtDecoderError> {
        let sync = first_psb_position(buffer).ok_or(PtDecoderError::SyncFailed)?;
        Ok(Self { buffer, pos: sync })
    }

    #[inline]
    pub fn next_packet(&mut self) -> Result<PtPacket, PtDecoderError> {
        let p = PtPacket::parse(self.buffer, &mut self.pos)?;

        #[cfg(feature = "log_packets")]
        log::trace!("{:016x} PT packet: {p:x?}", self.pos);

        Ok(p)
    }

    // pub fn rollback_one_packet(&mut self, packet: PtPacket) -> Result<(), PtDecoderError> {
    //     let mut pos = self.pos.checked_sub(packet.original_size()).ok_or(
    //         PtDecoderError::InvalidPacketSequence {
    //             packets: vec![packet.clone()],
    //         },
    //     )?;
    //     let parsed = PtPacket::parse(self.buffer, &mut pos)?;
    //     if parsed == packet {
    //         self.pos -= packet.original_size();
    //         Ok(())
    //     } else {
    //         Err(PtDecoderError::InvalidPacketSequence {
    //             packets: vec![packet],
    //         })
    //     }
    // }

    pub const fn pos(&self) -> usize {
        self.pos
    }

    pub const fn set_pos(&mut self, pos: usize) {
        self.pos = pos
    }
}

impl Iterator for PtPacketDecoder<'_> {
    type Item = Result<PtPacket, PtDecoderError>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.next_packet() {
            Ok(p) => Some(Ok(p)),
            Err(PtDecoderError::Eof) => None,
            Err(e) => Some(Err(e)),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::packet::PtPacket;
    use crate::packet::decoder::PtPacketDecoder;
    use crate::packet::mode::{AddressingMode, ModeExec};
    use crate::packet::psb::{Psb, PsbEnd};
    use crate::packet::tip::{Tip, TipPgd, TipPge};
    use crate::packet::tnt::TntShort;
    use std::iter::zip;

    #[test]
    fn next() {
        let decoder = PtPacketDecoder::new(TRACE).unwrap();
        for (d, r) in zip(decoder, right()) {
            if let Ok(packet) = d {
                assert_eq!(packet, r);
            } else {
                panic!("Failed to parse {r:?}");
            }
        }
    }

    const TRACE: &[u8] = &[
        0x02, 0x82, 0x02, 0x82, 0x02, 0x82, 0x02, 0x82, 0x02, 0x82, 0x02, 0x82, 0x02, 0x82, 0x02,
        0x82, 0x02, 0x03, 0x23, 0x00, 0x02, 0x23, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x99,
        0x01, 0xd1, 0xed, 0x4d, 0x32, 0x67, 0xaf, 0x7d, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0xcd, 0x9c, 0x76, 0x6b, 0x37, 0x72, 0x5d, 0x00, 0x00, 0x2d, 0xc4, 0x76, 0x4d,
        0xda, 0xe6, 0x4b, 0x37, 0x0a, 0x4d, 0xf4, 0x55, 0x46, 0x37, 0x06, 0x00, 0x2d, 0x37, 0x5f,
        0x2d, 0x4f, 0x5f, 0x00, 0x00, 0x2d, 0x62, 0xce, 0x2d, 0x30, 0x61, 0x00, 0x00, 0x2d, 0x41,
        0x61, 0x4d, 0xa0, 0xab, 0x7b, 0x37, 0xf2, 0x2d, 0xee, 0xab, 0x00, 0x00, 0x00, 0x00, 0x4d,
        0xc4, 0xf9, 0x42, 0x37, 0x00, 0x00, 0x00, 0x4d, 0x66, 0xe5, 0x46, 0x37, 0x00, 0x00, 0x00,
        0x4d, 0xdb, 0xa0, 0x48, 0x37, 0x0a, 0x00, 0x00, 0x4d, 0x2a, 0xfc, 0x42, 0x37, 0x00, 0x00,
        0x00, 0x4d, 0xe5, 0xa0, 0x48, 0x37, 0x00, 0x00, 0x00, 0x4d, 0xf0, 0xc3, 0x4c, 0x37, 0x00,
        0x00, 0x00, 0x4d, 0xda, 0x12, 0x48, 0x37, 0x2d, 0x05, 0xa1, 0x4d, 0xc0, 0xda, 0x7b, 0x37,
        0x00, 0x00, 0x00, 0x4d, 0x15, 0xa1, 0x48, 0x37, 0x2a, 0x00, 0x00, 0x4d, 0xda, 0xc9, 0x44,
        0x37, 0x00, 0x00, 0x00, 0x4d, 0x36, 0xa1, 0x48, 0x37, 0x00, 0x00, 0x00, 0x4d, 0x4e, 0x61,
        0x46, 0x37, 0x2d, 0x07, 0xc5, 0x4d, 0x50, 0x73, 0x52, 0x37, 0x2e, 0x00, 0x00, 0x2d, 0xcb,
        0x73, 0x00, 0x00, 0x00, 0x00, 0xcd, 0x00, 0x94, 0x38, 0x67, 0xaf, 0x7d, 0x00, 0x00, 0x08,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xcd, 0xdf, 0x73, 0x52, 0x37, 0x72, 0x5d, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xcd, 0xe0, 0x8c, 0x2a, 0x67, 0xaf, 0x7d, 0x00,
        0x00, 0x06, 0x01, 0x31, 0xfc, 0x8c, 0x04, 0x00, 0xcd, 0xd4, 0x74, 0x52, 0x37, 0x72, 0x5d,
        0x00, 0x00, 0x4d, 0x10, 0xc5, 0x46, 0x37, 0x2d, 0x97, 0xce, 0x06, 0x2d, 0x76, 0x56, 0x04,
        0x00, 0x00, 0x00, 0x4d, 0x80, 0xe8, 0x4b, 0x37, 0x2d, 0xad, 0xe8, 0x4d, 0xd0, 0x76, 0x6b,
        0x37, 0x00, 0x00, 0xcd, 0xb0, 0x4d, 0x32, 0x67, 0xaf, 0x7d, 0x00, 0x00, 0x01, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    fn right() -> Box<[PtPacket]> {
        Box::new([
            PtPacket::Psb(Psb {}),
            PtPacket::PsbEnd(PsbEnd {}),
            PtPacket::ModeExec(ModeExec::new(AddressingMode::_64, false)),
            PtPacket::TipPge(TipPge::try_from_payload(&TRACE[0x1f], &TRACE[0x20..]).unwrap()),
            PtPacket::Tnt(TntShort::new(&[false, false]).into_iter()),
            PtPacket::Tip(Tip::try_from_payload(&TRACE[0x2f], &TRACE[0x30..]).unwrap()),
            PtPacket::Tip(Tip::try_from_payload(&TRACE[0x38], &TRACE[0x39..]).unwrap()),
            PtPacket::Tip(Tip::try_from_payload(&TRACE[0x3b], &TRACE[0x3c..]).unwrap()),
            PtPacket::Tnt(TntShort::new(&[false, true]).into_iter()),
            PtPacket::Tip(Tip::try_from_payload(&TRACE[0x41], &TRACE[0x42..]).unwrap()),
            PtPacket::Tnt(TntShort::new(&[true]).into_iter()),
            PtPacket::Tip(Tip::try_from_payload(&TRACE[0x48], &TRACE[0x49..]).unwrap()),
            PtPacket::Tip(Tip::try_from_payload(&TRACE[0x4b], &TRACE[0x4c..]).unwrap()),
            PtPacket::Tip(Tip::try_from_payload(&TRACE[0x50], &TRACE[0x51..]).unwrap()),
            PtPacket::Tip(Tip::try_from_payload(&TRACE[0x53], &TRACE[0x54..]).unwrap()),
            PtPacket::Tip(Tip::try_from_payload(&TRACE[0x58], &TRACE[0x59..]).unwrap()),
            PtPacket::Tip(Tip::try_from_payload(&TRACE[0x5b], &TRACE[0x5c..]).unwrap()),
            PtPacket::Tnt(TntShort::new(&[true, true, true, false, false, true]).into_iter()),
            PtPacket::Tip(Tip::try_from_payload(&TRACE[0x61], &TRACE[0x62..]).unwrap()),
            PtPacket::Tip(Tip::try_from_payload(&TRACE[0x68], &TRACE[0x69..]).unwrap()),
            PtPacket::Tip(Tip::try_from_payload(&TRACE[0x70], &TRACE[0x71..]).unwrap()),
            PtPacket::Tip(Tip::try_from_payload(&TRACE[0x78], &TRACE[0x79..]).unwrap()),
            PtPacket::Tnt(TntShort::new(&[false, true]).into_iter()),
            PtPacket::Tip(Tip::try_from_payload(&TRACE[0x80], &TRACE[0x81..]).unwrap()),
            PtPacket::Tip(Tip::try_from_payload(&TRACE[0x88], &TRACE[0x89..]).unwrap()),
            PtPacket::Tip(Tip::try_from_payload(&TRACE[0x90], &TRACE[0x91..]).unwrap()),
            PtPacket::Tip(Tip::try_from_payload(&TRACE[0x98], &TRACE[0x99..]).unwrap()),
            PtPacket::Tip(Tip::try_from_payload(&TRACE[0x9d], &TRACE[0x9e..]).unwrap()),
            PtPacket::Tip(Tip::try_from_payload(&TRACE[0xa0], &TRACE[0xa1..]).unwrap()),
            PtPacket::Tip(Tip::try_from_payload(&TRACE[0xa8], &TRACE[0xa9..]).unwrap()),
            PtPacket::Tnt(TntShort::new(&[false, true, false, true]).into_iter()),
            PtPacket::Tip(Tip::try_from_payload(&TRACE[0xb0], &TRACE[0xb1..]).unwrap()),
            PtPacket::Tip(Tip::try_from_payload(&TRACE[0xb8], &TRACE[0xb9..]).unwrap()),
            PtPacket::Tip(Tip::try_from_payload(&TRACE[0xc0], &TRACE[0xc1..]).unwrap()),
            PtPacket::Tip(Tip::try_from_payload(&TRACE[0xc5], &TRACE[0xc6..]).unwrap()),
            PtPacket::Tip(Tip::try_from_payload(&TRACE[0xc8], &TRACE[0xc9..]).unwrap()),
            PtPacket::Tnt(TntShort::new(&[false, true, true, true]).into_iter()),
            PtPacket::Tip(Tip::try_from_payload(&TRACE[0xd0], &TRACE[0xd1..]).unwrap()),
            PtPacket::Tip(Tip::try_from_payload(&TRACE[0xd7], &TRACE[0xd8..]).unwrap()),
            PtPacket::Tnt(TntShort::new(&[false, false]).into_iter()),
            PtPacket::Tip(Tip::try_from_payload(&TRACE[0xe7], &TRACE[0xe8..]).unwrap()),
            PtPacket::Tip(Tip::try_from_payload(&TRACE[0xf7], &TRACE[0xf8..]).unwrap()),
            PtPacket::Tnt(TntShort::new(&[true]).into_iter()),
            PtPacket::TipPgd(TipPgd::try_from_payload(&TRACE[0x101], &TRACE[0x102..]).unwrap()),
            PtPacket::TipPge(TipPge::try_from_payload(&TRACE[0x102], &TRACE[0x103..]).unwrap()),
            PtPacket::Tnt(TntShort::new(&[false]).into_iter()),
            PtPacket::Tip(Tip::try_from_payload(&TRACE[0x107], &TRACE[0x108..]).unwrap()),
            PtPacket::Tip(Tip::try_from_payload(&TRACE[0x110], &TRACE[0x111..]).unwrap()),
            PtPacket::Tip(Tip::try_from_payload(&TRACE[0x115], &TRACE[0x116..]).unwrap()),
            PtPacket::Tnt(TntShort::new(&[true]).into_iter()),
            PtPacket::Tip(Tip::try_from_payload(&TRACE[0x119], &TRACE[0x11a..]).unwrap()),
            PtPacket::Tnt(TntShort::new(&[false]).into_iter()),
            PtPacket::Tip(Tip::try_from_payload(&TRACE[0x120], &TRACE[0x121..]).unwrap()),
            PtPacket::Tip(Tip::try_from_payload(&TRACE[0x125], &TRACE[0x126..]).unwrap()),
            PtPacket::Tip(Tip::try_from_payload(&TRACE[0x128], &TRACE[0x129..]).unwrap()),
            PtPacket::Tip(Tip::try_from_payload(&TRACE[0x12f], &TRACE[0x130..]).unwrap()),
            PtPacket::TipPgd(TipPgd::try_from_payload(&TRACE[0x138], &TRACE[0x139..]).unwrap()),
        ])
    }
}
