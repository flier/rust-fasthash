//! `aHash`
//!
use std::hash::Hasher;

use crate::hasher::{FastHash, FastHasher, StreamHasher};

pub use ahash::AHasher;

/// `aHash` 64-bit hash functions
///
/// # Example
///
/// ```
/// use fasthash::{ahash::Hash64, FastHash};
///
/// assert_eq!(Hash64::hash(b"hello"), 15194610732995203403);
/// assert_eq!(Hash64::hash_with_seed(b"world", (123, 456)), 8477115286135125610);
/// assert_eq!(Hash64::hash(b"helloworld"), 4140107389523680759);
/// ```
#[derive(Clone)]
pub struct Hash64;

impl FastHash for Hash64 {
    type Hash = u64;
    type Seed = (u128, u128);

    #[inline(always)]
    fn hash_with_seed<T: AsRef<[u8]>>(bytes: T, seed: (u128, u128)) -> u64 {
        let mut h = AHasher::new_with_keys(seed.0, seed.1);
        h.write(bytes.as_ref());
        h.finish()
    }

    #[inline(always)]
    fn hash<T: AsRef<[u8]>>(bytes: T) -> u64 {
        let mut h = AHasher::new_with_keys(0, 0);
        h.write(bytes.as_ref());
        h.finish()
    }
}

impl_build_hasher!(AHasher, Hash64);

impl FastHasher for AHasher {
    type Seed = (u128, u128);
    type Output = u64;

    #[inline(always)]
    fn new() -> Self {
        AHasher::new_with_keys(0, 0)
    }

    #[inline(always)]
    fn with_seed(seed: Self::Seed) -> Self {
        AHasher::new_with_keys(seed.0, seed.1)
    }
}

impl StreamHasher for AHasher {}

/// `aHash` 64-bit hash function using supplied seed..
///
/// # Example
///
/// ```
/// use fasthash::ahash::hash64_with_seed;
///
/// assert_eq!(hash64_with_seed(b"helloworld", (123, 456)), 5694414323515700605);
/// ```
#[inline(always)]
pub fn hash64_with_seed<T: AsRef<[u8]>>(v: T, seeds: (u128, u128)) -> u64 {
    Hash64::hash_with_seed(v, seeds)
}
