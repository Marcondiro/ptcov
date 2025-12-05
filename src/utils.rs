/// Sign-extends a 48-bit value to a full 64-bit.
pub const fn sign_extend_48(x: u64) -> u64 {
    ((x << 16) as i64 >> 16) as u64
}

/// Murmur3 finalizer (mixer)
/// 
/// Bit shuffler for u64 that has a good avalanche effect.
pub const fn fmix64(mut k: u64) -> u64 {
    k ^= k >> 33;
    k = k.wrapping_mul(0xff51afd7ed558ccd);
    k ^= k >> 33;
    k = k.wrapping_mul(0xc4ceb9fe1a85ec53);
    k ^= k >> 33;

    k
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_extend_48_works() {
        let positive = 0x7fff_ffff_ffff;
        let result = sign_extend_48(positive);
        assert_eq!(result, positive);

        let negative = 0x8000_0000_0000;
        let result = sign_extend_48(negative);
        assert_eq!(result, 0xffff << 48 | negative);
    }
}
