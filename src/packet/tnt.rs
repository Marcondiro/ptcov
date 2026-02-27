use std::fmt::{Debug, Formatter};

#[derive(Clone, Copy, PartialEq)]
pub struct TntShort {
    pub(super) raw: u8,
}

#[derive(Debug, Clone, PartialEq)]
pub struct TntLong {
    pub(super) raw: [u8; 6],
}

#[derive(Debug, Clone, PartialEq)]
pub struct TntIter {
    inner: u64,
}

impl Debug for TntShort {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let tnt_str = self.into_iter().map(|e| if e { 'T' } else { 'N' }).fold(
            String::new(),
            |mut acc, e| {
                acc.push(e);
                acc
            },
        );
        write!(f, "TntShort {{ {tnt_str:?} }}")
    }
}

impl IntoIterator for TntShort {
    type Item = bool;
    type IntoIter = TntIter;

    fn into_iter(self) -> Self::IntoIter {
        let raw64 = self.raw as u64;
        let inner = (raw64 | 1) << raw64.leading_zeros() << 1;
        Self::IntoIter { inner }
    }
}

impl IntoIterator for TntLong {
    type Item = bool;
    type IntoIter = TntIter;

    fn into_iter(self) -> Self::IntoIter {
        let raw_wit_trailing = self.payload_as_u64_with_trailing();
        let inner = raw_wit_trailing << raw_wit_trailing.leading_zeros() << 1;
        Self::IntoIter { inner }
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

    const fn payload_as_u64_with_trailing(&self) -> u64 {
        u64::from_le_bytes([
            0,
            0x80,
            self.raw[0],
            self.raw[1],
            self.raw[2],
            self.raw[3],
            self.raw[4],
            self.raw[5],
        ])
    }
}

impl Iterator for TntIter {
    type Item = bool;

    fn next(&mut self) -> Option<Self::Item> {
        const MASK: u64 = 1 << 63;
        let res = (self.inner & MASK) != 0;
        self.inner <<= 1;

        if self.inner != 0 { Some(res) } else { None }
    }
}

impl TntIter {
    /// Check if the iterator has space for at least one more TntShort
    pub const fn can_push_tnt_short(&self) -> bool {
        // tnt short contains at most 6 tnt bits
        self.inner & 0x3f == 0
    }

    /// SAFETY: the caller must make sure that the iterator has enough space, the last 6 bits of
    /// self.inner must be zero.
    #[inline(always)]
    pub unsafe fn push(&mut self, tnt: TntShort) {
        let free = self.inner.trailing_zeros();

        // clear the trailing end flag
        self.inner &= self.inner - 1;

        let tnt64 = tnt.raw as u64;
        // push the tnt content and the trailing
        self.inner |= ((tnt64 | 1) << tnt64.leading_zeros() << 1).rotate_right(63 - free);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iterate_tnt_short() {
        let raw = 0b00110100u8;
        let p = TntShort { raw };
        let p2 = p.clone();
        let mut iter = p.into_iter();

        let right = vec![true, false].repeat(2);
        assert_eq!(iter.clone().collect::<Vec<_>>(), right);

        assert!(iter.can_push_tnt_short());
        unsafe {
            iter.push(p2);
        }

        let right = vec![true, false].repeat(2).repeat(2);
        assert_eq!(iter.collect::<Vec<_>>(), right);
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
