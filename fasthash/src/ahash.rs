//! `aHash`
//!
use ahash;

pub use ahash::*;

use crate::hasher::{FastHash, FastHasher, StreamHasher};
use std::hash::BuildHasher;

/// `aHash` 64-bit hash functions
#[derive(Clone)]
pub struct Hash64;

impl FastHash for Hash64 {
    type Hash = u64;
    type Seed = (u64, u64, u64, u64);

    #[inline(always)]
    fn hash_with_seed<T: AsRef<[u8]>>(bytes: T, seed: (u64, u64, u64, u64)) -> u64 {
        let hasher = RandomState::with_seeds(seed.0, seed.1, seed.2, seed.3).build_hasher();
        bytes.as_ref().get_hash(hasher)
    }

    #[inline(always)]
    fn hash<T: AsRef<[u8]>>(bytes: T) -> u64 {
        let hasher = AHasher::default();
        bytes.as_ref().get_hash(hasher)
    }
}

impl_build_hasher!(AHasher, Hash64);

impl FastHasher for AHasher {
    type Seed = (u64, u64, u64, u64);
    type Output = u64;

    #[inline(always)]
    fn new() -> Self {
        AHasher::default()
    }

    #[inline(always)]
    fn with_seed(seed: Self::Seed) -> Self {
        RandomState::with_seeds(seed.0, seed.1, seed.2, seed.3).build_hasher()
    }
}

impl StreamHasher for AHasher {}

/// `aHash` 64-bit hash function using supplied seed..
#[inline(always)]
pub fn hash_with_seed<T: AsRef<[u8]>>(v: T, seeds: (u64, u64, u64, u64)) -> u64 {
    Hash64::hash_with_seed(v, seeds)
}

#[cfg(test)]
mod tests {
    use std::hash::Hasher;

    use super::AHasher;

    #[test]
    fn test_ahash() {
        let mut hasher_1 = AHasher::default();
        let mut hasher_2 = AHasher::default();

        hasher_1.write_u32(1234);
        hasher_2.write_u32(1234);

        assert_eq!(hasher_1.finish(), hasher_2.finish());
    }
}
