//! `aHash`
//!
use ahash;

pub use ahash::*;

use crate::hasher::{FastHash, FastHasher, StreamHasher};
use std::hash::Hasher;

/// `aHash` 64-bit hash functions
#[derive(Clone)]
pub struct Hash64;

impl FastHash for Hash64 {
    type Hash = u64;
    type Seed = (u128, u128);

    #[inline(always)]
    fn hash_with_seed<T: AsRef<[u8]>>(bytes: T, seed: (u128, u128)) -> u64 {
        let mut hasher = AHasher::new_with_keys(seed.0, seed.1);
        hasher.write(bytes.as_ref());
        hasher.finish()
    }

    #[inline(always)]
    fn hash<T: AsRef<[u8]>>(bytes: T) -> u64 {
        let mut hasher = AHasher::default();
        hasher.write(bytes.as_ref());
        hasher.finish()
    }
}

impl_build_hasher!(AHasher, Hash64);

impl FastHasher for AHasher {
    type Seed = (u128, u128);
    type Output = u64;

    #[inline(always)]
    fn new() -> Self {
        AHasher::default()
    }

    #[inline(always)]
    fn with_seed(seed: Self::Seed) -> Self {
        AHasher::new_with_keys(seed.0, seed.1)
    }
}

impl StreamHasher for AHasher {}

/// `aHash` 64-bit hash function using supplied seed..
#[inline(always)]
pub fn hash_with_seed<T: AsRef<[u8]>>(v: T, seeds: (u128, u128)) -> u64 {
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
