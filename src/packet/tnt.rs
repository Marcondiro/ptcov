use crate::packet::SizedPtPacket;
use std::fmt::{Debug, Formatter};

#[derive(Clone, PartialEq)]
pub struct TntShort {
    pub(super) raw: u8,
}

#[derive(Debug, Clone, PartialEq)]
pub struct TntLong {
    pub(super) raw: [u8; 6],
}

#[derive(Debug, PartialEq)]
pub enum TntIter {
    TntShortIter(TntShortIter),
    TntLongIter(TntLongIter),
}

#[derive(Debug, PartialEq)]
pub struct TntShortIter {
    tnt: TntShort,
    mask: u8,
}

#[derive(Debug, PartialEq)]
pub struct TntLongIter {
    tnt: TntLong,
    mask: u64,
}

impl Debug for TntShort {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let tnt_str = self
            .clone()
            .into_iter()
            .map(|e| if e { 'T' } else { 'N' })
            .fold(String::new(), |mut acc, e| {
                acc.push(e);
                acc
            });
        write!(f, "TntShort {{ {tnt_str:?} }}")
    }
}

impl IntoIterator for TntShort {
    type Item = bool;
    type IntoIter = TntShortIter;

    fn into_iter(self) -> Self::IntoIter {
        let mask = 1u8 << (7 - self.raw.leading_zeros());
        Self::IntoIter { tnt: self, mask }
    }
}

impl IntoIterator for TntLong {
    type Item = bool;
    type IntoIter = TntLongIter;

    fn into_iter(self) -> Self::IntoIter {
        let mask = 1u64 << (63 - self.payload_as_u64().leading_zeros());
        Self::IntoIter { tnt: self, mask }
    }
}

impl TntShort {
    pub(super) const SIZE: usize = 1;

    #[cfg(test)]
    pub(super) fn new(taken_not_taken: &[bool]) -> Self {
        assert!(!taken_not_taken.is_empty());
        assert!(taken_not_taken.len() < 7);

        let mut raw = 0b10 << taken_not_taken.len();
        for (i, &is_taken) in taken_not_taken.iter().rev().enumerate() {
            raw |= if is_taken { 0b10 << i } else { 0 };
        }

        Self { raw }
    }
}

impl TntLong {
    pub(super) const SIZE: usize = 8;
    pub(super) const B1: u8 = 0xa3;

    const fn payload_as_u64(&self) -> u64 {
        u64::from_le_bytes([
            self.raw[0],
            self.raw[1],
            self.raw[2],
            self.raw[3],
            self.raw[4],
            self.raw[5],
            0,
            0,
        ])
    }
}

impl SizedPtPacket for TntShort {
    fn original_size(&self) -> usize {
        Self::SIZE
    }
}

impl SizedPtPacket for TntLong {
    fn original_size(&self) -> usize {
        Self::SIZE
    }
}

impl Iterator for TntIter {
    type Item = bool;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            TntIter::TntLongIter(l) => l.next(),
            TntIter::TntShortIter(s) => s.next(),
        }
    }
}

impl From<TntShortIter> for TntIter {
    fn from(value: TntShortIter) -> Self {
        Self::TntShortIter(value)
    }
}

impl From<TntLongIter> for TntIter {
    fn from(value: TntLongIter) -> Self {
        Self::TntLongIter(value)
    }
}

impl Iterator for TntShortIter {
    type Item = bool;

    fn next(&mut self) -> Option<Self::Item> {
        self.mask >>= 1;
        if self.mask <= 0b1 {
            None
        } else {
            Some(self.tnt.raw & self.mask != 0)
        }
    }
}

impl Iterator for TntLongIter {
    type Item = bool;

    fn next(&mut self) -> Option<Self::Item> {
        self.mask >>= 1;
        if self.mask == 0 {
            None
        } else {
            Some(self.tnt.payload_as_u64() & self.mask != 0)
        }
    }
}

// impl TntIter {
//     pub const fn has_next(&self) -> bool {
//         match self {
//             Self::TntShortIter(s) => s.has_next(),
//             Self::TntLongIter(l) => l.has_next(),
//         }
//     }
// }
//
// impl TntShortIter {
//     pub const fn has_next(&self) -> bool {
//         self.mask >> 1 > 0b1
//     }
// }
//
// impl TntLongIter {
//     pub const fn has_next(&self) -> bool {
//         self.mask >> 1 > 0
//     }
// }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iterate_tnt_short() {
        let raw = 0b00110100u8;
        let p = TntShort { raw };

        let right = vec![true, false].repeat(2);

        assert_eq!(p.into_iter().collect::<Vec<_>>(), right);
    }

    #[test]
    fn iterate_tnt_long() {
        let raw = [0b10101010, 0b10101010, 0b10101010, 0b10101010, 0, 0];
        let p = TntLong { raw };

        let mut right = vec![false, true].repeat(15);
        right.push(false);

        assert_eq!(p.clone().into_iter().collect::<Vec<_>>().len(), right.len());
        assert_eq!(p.into_iter().collect::<Vec<_>>(), right);
    }
}
