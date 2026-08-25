use crate::packet::PtPacketParseError;

/// Cycle Count (CYC) packet.
#[derive(Debug, PartialEq, Clone)]
pub struct Cyc {
    raw: [u8; 15], // according to Intel's libipt max len 15, SDM says: "The size of the counter is implementation specific"
    len: usize,
}

impl Cyc {
    /// Returns the encoded packet size in bytes.
    pub const fn original_size(&self) -> usize {
        self.len
    }
}

impl Cyc {
    // pub fn cycle_counter(&self) -> u64 {
    //     let mut counter = (self.raw[0] >> 3) as u64;
    //
    //     for i in 1..self.len {
    //         counter |= ((self.raw[i] & 0xfe) as u64) << 4 << (7 * (i - 1));
    //     }
    //
    //     counter
    // }

    /// Caller must check the header
    ///
    /// Panics if input len is 0
    #[inline]
    pub(super) fn try_from_payload(input: &[u8]) -> Result<Self, PtPacketParseError> {
        let mut raw = [input[0], 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let mut len = 1;

        if input[0] & 0x04 != 0 {
            loop {
                len += 1;
                if input.len() < len || raw.len() < len {
                    return Err(PtPacketParseError::MalformedPacket);
                }
                raw[len - 1] = input[len - 1];
                if input[len - 1] & 0x01 == 0 {
                    break;
                }
            }
        };

        Ok(Self { raw, len })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cyc_original_size() {
        let raws = [
            [0b1111_1011u8].as_slice(),
            [0b1111_1111u8, 0].as_slice(),
            [0b1111_1111u8, 0b1, 0].as_slice(),
            [0b1111_1111u8, 0b1010_1011, 0b1111_1110].as_slice(),
            [0b111u8, 0b1, 0b1, 0b1, 0b1, 0b10].as_slice(),
            // longest counter that fits in `Cyc::raw`
            [
                0b1111_1111u8,
                0b1,
                0b1,
                0b1,
                0b1,
                0b1,
                0b1,
                0b1,
                0b1,
                0b1,
                0b1,
                0b1,
                0b1,
                0b1,
                0b0,
            ]
            .as_slice(),
        ];

        for raw in raws {
            let p = Cyc::try_from_payload(raw).unwrap();
            assert_eq!(p.original_size(), raw.len(), "{raw:x?}");
            assert_eq!(&p.raw[..p.original_size()], raw, "{raw:x?}");
        }

        let malformed = [
            // the header announces a counter payload, but the buffer ends right after it
            [0b0000_0111u8].as_slice(),
            // the counter continues past the end of the buffer
            [0b1111_1111u8, 0b1, 0b1].as_slice(),
            // the counter is longer than the 15 bytes `Cyc::raw` can hold
            [
                0b1111_1111u8,
                0b1,
                0b1,
                0b1,
                0b1,
                0b1,
                0b1,
                0b1,
                0b1,
                0b1,
                0b1,
                0b1,
                0b1,
                0b1,
                0b1,
                0b0,
            ]
            .as_slice(),
        ];

        for raw in malformed {
            assert_eq!(
                Cyc::try_from_payload(raw),
                Err(PtPacketParseError::MalformedPacket),
                "{raw:x?}"
            );
        }
    }

    // #[test]
    // fn cycle_counter() {
    //     let raws = [
    //         ([0b1111_1011u8].as_slice(), 0x1f),
    //         ([0b1111_1111u8, 0].as_slice(), 0x1f),
    //         ([0b1111_1111u8, 0b10].as_slice(), 0x3f),
    //     ];
    //
    //     for (raw, right) in raws {
    //         let p = Cyc::try_from_payload(raw).unwrap();
    //         assert_eq!(p.cycle_counter(), right);
    //     }
    // }
}
