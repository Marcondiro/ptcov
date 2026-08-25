use core::fmt::{Debug, Formatter};

/// Short TNT packet (1 byte), carrying up to 6 taken/not-taken decisions.
#[derive(Clone, Copy, PartialEq)]
pub struct TntShort {
    pub(crate) raw: u8,
}

/// Long TNT packet (8 bytes), carrying up to 47 taken/not-taken decisions.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct TntLong {
    pub(super) raw: [u8; 6],
}

/// Iterator over taken/not-taken decisions from a TNT packet.
///
/// `true` means taken, `false` means not taken.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TntIter {
    inner: u64,
}

impl Debug for TntShort {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
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
        let raw32 = u32::from(self.raw);
        let inner = (((raw32 | 1) << raw32.leading_zeros() << 1) as u64) << 32;
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
    pub(crate) fn new(taken_not_taken: &[bool]) -> Self {
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
        let res = (self.inner >> 63) != 0;
        self.inner <<= 1;

        if self.inner != 0 { Some(res) } else { None }
    }

    fn nth(&mut self, n: usize) -> Option<Self::Item> {
        self.inner <<= n;
        self.next()
    }
}

// todo: this should be split between a builder with the push method and a consumer with the next
// method since can_push_tnt_short() on a fully consumed TntIter returns true but does not make sure
// that there is a trailing bit to 1
impl TntIter {
    /// Check if the iterator has space for at least one more `TntShort`
    pub const fn can_push_tnt_short(&self) -> bool {
        // tnt short contains at most 6 tnt bits
        self.inner.trailing_zeros() >= 6
    }

    /// SAFETY: the caller must make sure that the iterator has enough space, the last 6 bits of
    /// self.inner must be zero.
    pub unsafe fn push(&mut self, tnt: TntShort) {
        let free = self.inner.trailing_zeros();

        // clear the trailing end flag
        self.inner &= self.inner.wrapping_sub(1);

        let tnt64 = tnt.raw as u64;
        // push the tnt content and the trailing
        self.inner |= ((tnt64 | 1) << tnt64.leading_zeros() << 1) >> (63 - free);
    }

    /// Returns the number of remaining taken/not-taken decisions.
    pub const fn len(&self) -> u32 {
        63u32.saturating_sub(self.inner.trailing_zeros())
    }

    /// Returns `true` if there are remaining decisions.
    pub const fn has_next(&self) -> bool {
        self.inner.trailing_zeros() < 63
    }

    /// Returns the next decision without consuming it.
    pub const fn peek(&self) -> Option<bool> {
        let res = (self.inner >> 63) != 0;
        if (self.inner << 1) != 0 {
            Some(res)
        } else {
            None
        }
    }

    /// Advance the iterator by one position without returning the value
    ///
    /// If the iterator is empty, this will have no effect and the iterator will remain empty.
    pub const fn advance(&mut self) {
        self.inner <<= 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iterate_tnt_short() {
        let raw = 0b00110100u8;
        let p = TntShort { raw };
        let p2 = p;
        let mut iter = p.into_iter();

        let right = [true, false].repeat(2);
        assert_eq!(iter.collect::<Vec<_>>(), right);

        assert!(iter.can_push_tnt_short());
        unsafe {
            iter.push(p2);
        }

        let right = [true, false].repeat(2).repeat(2);
        assert_eq!(iter.collect::<Vec<_>>(), right);
    }

    #[test]
    fn iterate_tnt_long() {
        let raw = [0b10101010, 0b10101010, 0b10101010, 0b10101010, 0, 0];
        let p = TntLong { raw };

        let mut right = [false, true].repeat(15);
        right.push(false);

        assert_eq!(p.into_iter().collect::<Vec<_>>().len(), right.len());
        assert_eq!(p.into_iter().collect::<Vec<_>>(), right);
    }
}
