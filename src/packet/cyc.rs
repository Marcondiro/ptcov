use crate::packet::{PtPacketParseError, SizedPtPacket};

#[derive(Debug, PartialEq)]
pub struct Cyc {
    raw: [u8; 15], // according to Intel's libipt max len 15, SDM says: "The size of the counter is implementation specific"
    len: usize,
}

impl SizedPtPacket for Cyc {
    fn original_size(&self) -> usize {
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
            if input.len() < 2 {
                return Err(PtPacketParseError::MalformedPacket);
            }
            raw[1] = input[1];

            while input[len] & 0x01 != 0 && len < raw.len() {
                len += 1;
                if input.len() <= len {
                    return Err(PtPacketParseError::MalformedPacket);
                }
                raw[len] = input[len];
            }
            len += 1;
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
        ];

        for raw in raws {
            let p = Cyc::try_from_payload(raw).unwrap();
            assert_eq!(p.original_size(), raw.len());
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
