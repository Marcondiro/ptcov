use crate::PtDecoderError;
use crate::packet::PtPacket;
use crate::packet::psb::{first_psb_position, Psb};

#[derive(Debug)]
pub struct PtPacketDecoder<'a> {
    buffer: &'a [u8],
    pos: usize,
    last_psb: usize,
}

impl<'a> PtPacketDecoder<'a> {
    pub fn new(buffer: &'a [u8]) -> Result<Self, PtDecoderError> {
        let sync = first_psb_position(buffer).ok_or(PtDecoderError::SyncFailed)?;
        Ok(Self {
            buffer,
            pos: sync,
            last_psb: sync,
        })
    }

    pub fn next_packet(&mut self) -> Result<PtPacket, PtDecoderError> {
        let p = PtPacket::parse(self.buffer, &mut self.pos)?;
        if matches!(p, PtPacket::Psb(..)) {
            self.last_psb = self.pos - Psb::SIZE;
        }

        #[cfg(feature = "log")]
        log::trace!("PT packet: {p:x?}");

        Ok(p)
    }

    pub const fn position(&self) -> usize {
        self.pos
    }

    pub const fn last_sync_position(&self) -> usize {
        self.last_psb
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
            PtPacket::TipPge(TipPge::try_from_payload(&TRACE[0x1f..]).unwrap()),
            PtPacket::TntShort(TntShort::new(&[false, false])),
            PtPacket::Tip(Tip::try_from_payload(&TRACE[0x2f..]).unwrap()),
            PtPacket::Tip(Tip::try_from_payload(&TRACE[0x38..]).unwrap()),
            PtPacket::Tip(Tip::try_from_payload(&TRACE[0x3b..]).unwrap()),
            PtPacket::TntShort(TntShort::new(&[false, true])),
            PtPacket::Tip(Tip::try_from_payload(&TRACE[0x41..]).unwrap()),
            PtPacket::TntShort(TntShort::new(&[true])),
            PtPacket::Tip(Tip::try_from_payload(&TRACE[0x48..]).unwrap()),
            PtPacket::Tip(Tip::try_from_payload(&TRACE[0x4b..]).unwrap()),
            PtPacket::Tip(Tip::try_from_payload(&TRACE[0x50..]).unwrap()),
            PtPacket::Tip(Tip::try_from_payload(&TRACE[0x53..]).unwrap()),
            PtPacket::Tip(Tip::try_from_payload(&TRACE[0x58..]).unwrap()),
            PtPacket::Tip(Tip::try_from_payload(&TRACE[0x5b..]).unwrap()),
            PtPacket::TntShort(TntShort::new(&[true, true, true, false, false, true])),
            PtPacket::Tip(Tip::try_from_payload(&TRACE[0x61..]).unwrap()),
            PtPacket::Tip(Tip::try_from_payload(&TRACE[0x68..]).unwrap()),
            PtPacket::Tip(Tip::try_from_payload(&TRACE[0x70..]).unwrap()),
            PtPacket::Tip(Tip::try_from_payload(&TRACE[0x78..]).unwrap()),
            PtPacket::TntShort(TntShort::new(&[false, true])),
            PtPacket::Tip(Tip::try_from_payload(&TRACE[0x80..]).unwrap()),
            PtPacket::Tip(Tip::try_from_payload(&TRACE[0x88..]).unwrap()),
            PtPacket::Tip(Tip::try_from_payload(&TRACE[0x90..]).unwrap()),
            PtPacket::Tip(Tip::try_from_payload(&TRACE[0x98..]).unwrap()),
            PtPacket::Tip(Tip::try_from_payload(&TRACE[0x9d..]).unwrap()),
            PtPacket::Tip(Tip::try_from_payload(&TRACE[0xa0..]).unwrap()),
            PtPacket::Tip(Tip::try_from_payload(&TRACE[0xa8..]).unwrap()),
            PtPacket::TntShort(TntShort::new(&[false, true, false, true])),
            PtPacket::Tip(Tip::try_from_payload(&TRACE[0xb0..]).unwrap()),
            PtPacket::Tip(Tip::try_from_payload(&TRACE[0xb8..]).unwrap()),
            PtPacket::Tip(Tip::try_from_payload(&TRACE[0xc0..]).unwrap()),
            PtPacket::Tip(Tip::try_from_payload(&TRACE[0xc5..]).unwrap()),
            PtPacket::Tip(Tip::try_from_payload(&TRACE[0xc8..]).unwrap()),
            PtPacket::TntShort(TntShort::new(&[false, true, true, true])),
            PtPacket::Tip(Tip::try_from_payload(&TRACE[0xd0..]).unwrap()),
            PtPacket::Tip(Tip::try_from_payload(&TRACE[0xd7..]).unwrap()),
            PtPacket::TntShort(TntShort::new(&[false, false])),
            PtPacket::Tip(Tip::try_from_payload(&TRACE[0xe7..]).unwrap()),
            PtPacket::Tip(Tip::try_from_payload(&TRACE[0xf7..]).unwrap()),
            PtPacket::TntShort(TntShort::new(&[true])),
            PtPacket::TipPgd(TipPgd::try_from_payload(&TRACE[0x101..]).unwrap()),
            PtPacket::TipPge(TipPge::try_from_payload(&TRACE[0x102..]).unwrap()),
            PtPacket::TntShort(TntShort::new(&[false])),
            PtPacket::Tip(Tip::try_from_payload(&TRACE[0x107..]).unwrap()),
            PtPacket::Tip(Tip::try_from_payload(&TRACE[0x110..]).unwrap()),
            PtPacket::Tip(Tip::try_from_payload(&TRACE[0x115..]).unwrap()),
            PtPacket::TntShort(TntShort::new(&[true])),
            PtPacket::Tip(Tip::try_from_payload(&TRACE[0x119..]).unwrap()),
            PtPacket::TntShort(TntShort::new(&[false])),
            PtPacket::Tip(Tip::try_from_payload(&TRACE[0x120..]).unwrap()),
            PtPacket::Tip(Tip::try_from_payload(&TRACE[0x125..]).unwrap()),
            PtPacket::Tip(Tip::try_from_payload(&TRACE[0x128..]).unwrap()),
            PtPacket::Tip(Tip::try_from_payload(&TRACE[0x12f..]).unwrap()),
            PtPacket::TipPgd(TipPgd::try_from_payload(&TRACE[0x138..]).unwrap()),
        ])
    }
}
