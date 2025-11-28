pub(crate) const fn sign_extend_48(x: u64) -> u64 {
    ((x << 16) as i64 >> 16) as u64
}

/// Murmur3 finalizer (mixer)
pub(crate) const fn fmix64(mut k: u64) -> u64 {
    k ^= k >> 33;
    k = k.wrapping_mul(0xff51afd7ed558ccd);
    k ^= k >> 33;
    k = k.wrapping_mul(0xc4ceb9fe1a85ec53);
    k ^= k >> 33;

    k
}
