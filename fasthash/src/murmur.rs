//! Murmur, a suite of non-cryptographic hash functions that was used for hash-based lookups.
//!
//! by Austin Appleby (aappleby (AT) gmail)
//!
//! https://sites.google.com/site/murmurhash/
//!
//! Extremely simple - compiles down to ~52 instructions on x86.
//!
//! Excellent distribution - Passes chi-squared tests for practically all keysets & bucket sizes.
//!
//! Excellent avalanche behavior - Maximum bias is under 0.5%.
//!
//! Excellent collision resistance - Passes Bob Jenkin's frog.c torture-test.
//! No collisions possible for 4-byte keys, no small (1- to 7-bit) differentials.
//!
//! Excellent performance - measured on an Intel Core 2 Duo @ 2.4 ghz
//!
//!    - OneAtATime - 354.163715 mb/sec
//!    - FNV - 443.668038 mb/sec
//!    - SuperFastHash - 985.335173 mb/sec
//!    - lookup3 - 988.080652 mb/sec
//!    - MurmurHash 1.0 - 1363.293480 mb/sec
//!    - MurmurHash 2.0 - 2056.885653 mb/sec
//!
//! # Example
//!
//! ```
//! use std::hash::{Hash, Hasher};
//!
//! use fasthash::{murmur, MurmurHasher};
//!
//! fn hash<T: Hash>(t: &T) -> u64 {
//!     let mut s = MurmurHasher::new();
//!     t.hash(&mut s);
//!     s.finish()
//! }
//!
//! let h = murmur::hash32(b"hello world\xff");
//!
//! assert_eq!(h, hash(&"hello world") as u32);
//! ```
//!
use std::os::raw::c_void;

use ffi;

use hasher::FastHash;

/// MurmurHash 32-bit hash functions
pub struct Murmur {}

impl FastHash for Murmur {
    type Value = u32;
    type Seed = u32;

    #[inline]
    fn hash_with_seed<T: AsRef<[u8]>>(bytes: &T, seed: u32) -> u32 {
        unsafe {
            ffi::MurmurHash1(bytes.as_ref().as_ptr() as *const c_void,
                             bytes.as_ref().len() as i32,
                             seed)
        }
    }
}

impl_hasher!(MurmurHasher, Murmur);

/// MurmurHash 32-bit aligned hash functions
pub struct MurmurAligned {}

impl FastHash for MurmurAligned {
    type Value = u32;
    type Seed = u32;

    #[inline]
    fn hash_with_seed<T: AsRef<[u8]>>(bytes: &T, seed: u32) -> u32 {
        unsafe {
            ffi::MurmurHash1Aligned(bytes.as_ref().as_ptr() as *const c_void,
                                    bytes.as_ref().len() as i32,
                                    seed)
        }
    }
}

impl_hasher!(MurmurAlignedHasher, MurmurAligned);

/// MurmurHash 32-bit hash functions for a byte array.
#[inline]
pub fn hash32<T: AsRef<[u8]>>(v: &T) -> u32 {
    Murmur::hash(v)
}

/// MurmurHash 32-bit hash function for a byte array.
/// For convenience, a 32-bit seed is also hashed into the result.
#[inline]
pub fn hash32_with_seed<T: AsRef<[u8]>>(v: &T, seed: u32) -> u32 {
    Murmur::hash_with_seed(v, seed)
}

/// MurmurHash 32-bit aligned hash functions for a byte array.
#[inline]
pub fn hash32_aligned<T: AsRef<[u8]>>(v: &T) -> u32 {
    MurmurAligned::hash(v)
}

/// MurmurHash 32-bit aligned hash function for a byte array.
/// For convenience, a 32-bit seed is also hashed into the result.
#[inline]
pub fn hash32_aligned_with_seed<T: AsRef<[u8]>>(v: &T, seed: u32) -> u32 {
    MurmurAligned::hash_with_seed(v, seed)
}

#[cfg(test)]
mod tests {
    use std::hash::Hasher;

    use hasher::FastHash;
    use super::*;

    #[test]
    fn test_murmur() {
        assert_eq!(Murmur::hash(b"hello"), 1773990585);
        assert_eq!(Murmur::hash_with_seed(b"hello", 123), 2155802495);
        assert_eq!(Murmur::hash(b"helloworld"), 567127608);

        let mut h = MurmurHasher::new();

        h.write(b"hello");
        assert_eq!(h.finish(), 1773990585);

        h.write(b"world");
        assert_eq!(h.finish(), 567127608);
    }

    #[test]
    fn test_murmur_aligned() {
        assert_eq!(MurmurAligned::hash(b"hello"), 1773990585);
        assert_eq!(MurmurAligned::hash_with_seed(b"hello", 123), 2155802495);
        assert_eq!(MurmurAligned::hash(b"helloworld"), 567127608);

        let mut h = MurmurAlignedHasher::new();

        h.write(b"hello");
        assert_eq!(h.finish(), 1773990585);

        h.write(b"world");
        assert_eq!(h.finish(), 567127608);
    }
}
