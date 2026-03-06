use super::{CoverageIndex, ProceedInstStopReason};
use crate::packet::tnt::TntIter;

pub type InstCache = hashbrown::HashMap<InstCacheKey, InstCacheValue>;
pub type TntCache = hashbrown::HashMap<TntCacheKey, TntCacheValue>;

#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq)]
pub struct InstCacheKey {
    pub from: u64,
    // todo: cr3
    // vmcs: Option<Vmcs>,
}

#[derive(Debug)]
pub struct InstCacheValue {
    pub to: u64,
    pub stop_reason: ProceedInstStopReason,
    #[cfg(feature = "retc")]
    pub retc_stack_diff: Vec<u64>,
}

#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq)]
pub struct TntCacheKey {
    pub from: u64,
    pub tnt: TntIter,
}

#[derive(Debug)]
pub struct TntCacheValue {
    coverage: [CoverageIndex; 8 * size_of::<TntIter>()],
    coverage_entries: usize,
    to: u64,
}

#[derive(Debug)]
pub struct TntCacheValueBuilder {
    coverage: [CoverageIndex; 8 * size_of::<TntIter>()],
    coverage_entries: usize,
}

impl TntCacheValue {
    pub fn builder() -> TntCacheValueBuilder {
        TntCacheValueBuilder::new()
    }

    pub fn coverage(&self) -> &[CoverageIndex] {
        &self.coverage[0..self.coverage_entries]
    }

    pub const fn coverage_len(&self) -> usize {
        self.coverage_entries
    }

    pub const fn to(&self) -> u64 {
        self.to
    }
}

impl TntCacheValueBuilder {
    pub fn new() -> Self {
        Self {
            coverage_entries: 0,
            coverage: [CoverageIndex::default(); 8 * size_of::<TntIter>()],
        }
    }

    pub const fn add(&mut self, coverage_index: CoverageIndex) {
        self.coverage[self.coverage_entries] = coverage_index;
        self.coverage_entries += 1;
    }

    pub fn build(self, to: u64) -> TntCacheValue {
        TntCacheValue {
            to,
            coverage_entries: self.coverage_entries,
            coverage: self.coverage,
        }
    }

    pub const fn coverage_len(&self) -> usize {
        self.coverage_entries
    }
}

impl Default for TntCacheValueBuilder {
    fn default() -> Self {
        Self::new()
    }
}
