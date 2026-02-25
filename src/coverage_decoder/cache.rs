use super::ProceedInstStopReason;

pub type Cache = LinearCache;

#[derive(Debug)]
pub struct LinearCache {
    inner: Box<[(InstCacheKey, InstCacheValue); Self::SIZE]>,
}

impl LinearCache {
    const SIZE: usize = 0x10_000;
    const MASK: usize = Self::SIZE - 1;

    pub fn new() -> Self {
        let inner = unsafe {
            let mut inner_uninit =
                Box::<[(InstCacheKey, InstCacheValue); Self::SIZE]>::new_zeroed();
            // The 1 makes sure that the entry won't match any key and the cache will act as empty
            inner_uninit.assume_init_mut()[0].0 = InstCacheKey { from: 1 };
            inner_uninit.assume_init()
        };

        Self { inner }
    }

    #[inline]
    pub fn get(&self, key: &InstCacheKey) -> Option<&InstCacheValue> {
        let entry = &self.inner[key.from as usize & Self::MASK];
        if entry.0.from == key.from {
            Some(&entry.1)
        } else {
            None
        }
    }

    pub fn insert(&mut self, key: InstCacheKey, value: InstCacheValue) {
        let entry = &mut self.inner[key.from as usize & Self::MASK];
        entry.0 = key;
        entry.1 = value;
    }
}

impl Default for LinearCache {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct InstCacheKey {
    pub from: u64,
    // todo: cr3
    // vmcs: Option<Vmcs>,
}

#[derive(Debug)]
pub struct InstCacheValue {
    // todo just for comparison with libxdc
    pub last_ins_len: u64,
    pub to: u64,
    pub stop_reason: ProceedInstStopReason,
    #[cfg(feature = "retc")]
    pub retc_stack_size_diff: i8,
    #[cfg(feature = "retc")]
    pub retc_stack_diff: Vec<u64>,
}
