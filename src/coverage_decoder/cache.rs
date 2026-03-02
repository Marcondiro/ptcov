use super::ProceedInstStopReason;

pub type Cache = LinearCache<0x10_000, InstCacheKey, InstCacheValue>;

#[derive(Debug)]
pub struct LinearCache<const SIZE: usize, K, V>
where
    K: Copy + From<u64> + PartialEq,
{
    inner: Box<[(K, V); SIZE]>,
}

impl<const SIZE: usize, K, V> LinearCache<SIZE, K, V>
where
    K: Copy + From<u64> + PartialEq,
    u64: From<K>,
{
    const MASK: usize = SIZE - 1;
    // todo: assert SIZE is pow of 2

    pub fn new() -> Self {
        let inner = unsafe {
            let mut inner_uninit = Box::<[(K, V); SIZE]>::new_zeroed();
            // The 1 makes sure that the entry won't match any key and the cache will act as empty
            inner_uninit.assume_init_mut()[0].0 = K::from(1);
            inner_uninit.assume_init()
        };

        Self { inner }
    }

    #[inline]
    pub fn get(&self, key: K) -> Option<&V> {
        let entry = &self.inner[u64::from(key) as usize & Self::MASK];
        if entry.0 == key { Some(&entry.1) } else { None }
    }

    pub fn insert(&mut self, key: K, value: V) {
        let entry = &mut self.inner[u64::from(key) as usize & Self::MASK];
        entry.0 = key;
        entry.1 = value;
    }
}

impl<const SIZE: usize, K, V> Default for LinearCache<SIZE, K, V>
where
    K: Copy + From<u64> + PartialEq,
    u64: From<K>,
{
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq)]
pub struct InstCacheKey {
    pub from: u64,
    // todo: cr3
    // vmcs: Option<Vmcs>,
}

impl From<u64> for InstCacheKey {
    fn from(value: u64) -> Self {
        Self { from: value }
    }
}

impl From<InstCacheKey> for u64 {
    fn from(value: InstCacheKey) -> Self {
        value.from
    }
}

#[derive(Debug)]
pub struct InstCacheValue {
    pub to: u64,
    pub stop_reason: ProceedInstStopReason,
    #[cfg(feature = "retc")]
    pub retc_stack_size_diff: i8,
    #[cfg(feature = "retc")]
    pub retc_stack_diff: Vec<u64>,
}
