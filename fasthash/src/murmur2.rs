//! Murmur, a suite of  non-cryptographic hash functions that was used for hash-based lookups.
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
//! # Variants
//!
//! The current version is `MurmurHash3`, which yields a 32-bit or 128-bit hash value.
//!
//! The older `MurmurHash2` yields a 32-bit or 64-bit value.
//! Slower versions of `MurmurHash2` are available for big-endian and aligned-only machines.
//! The `MurmurHash2A` variant adds the Merkle–Damgård construction
//! so that it can be called incrementally.
//! There are two variants which generate 64-bit values; `MurmurHash64A`,
//! which is optimized for 64-bit processors, and `MurmurHash64B`, for 32-bit ones.
//!
//! # Attacks
//!
//! MurmurHash was a recommended hash function for hash table implementations.
//! Jean-Philippe Aumasson and Daniel J. Bernstein were able to show
//! that even randomized implementations of MurmurHash are vulnerable to so-called [HashDoS attacks]
//! (https://emboss.github.io/blog/2012/12/14/breaking-murmur-hash-flooding-dos-reloaded/).
//! With the use of differential cryptanalysis they were able to generate inputs
//! that would lead to a hash collision.
//! This can be abused to cause very slow operations of a hash table implementation.
//! The authors of the attack recommend to use `SipHash` instead.
//!
//! # Example
//!
//! ```
//! use std::hash::{Hash, Hasher};
//!
//! use fasthash::{murmur2, Murmur2Hasher};
//!
//! fn hash<T: Hash>(t: &T) -> u64 {
//!     let mut s = Murmur2Hasher::new();
//!     t.hash(&mut s);
//!     s.finish()
//! }
//!
//! let h = murmur2::hash64(b"hello world\xff");
//!
//! assert_eq!(h, hash(&"hello world"));
//! ```
//!
#![allow(non_camel_case_types)]
use std::os::raw::c_void;

use ffi;

use hasher::FastHash;

/// MurmurHash2 32-bit hash functions
pub struct Murmur2 {}

impl FastHash for Murmur2 {
    type Value = u32;
    type Seed = u32;

    #[inline]
    fn hash_with_seed<T: AsRef<[u8]>>(bytes: &T, seed: u32) -> u32 {
        unsafe {
            ffi::MurmurHash2(bytes.as_ref().as_ptr() as *const c_void,
                             bytes.as_ref().len() as i32,
                             seed)
        }
    }
}

impl_hasher!(MurmurHasher2, Murmur2);

/// MurmurHash2A 32-bit hash functions
pub struct Murmur2A {}

impl FastHash for Murmur2A {
    type Value = u32;
    type Seed = u32;

    #[inline]
    fn hash_with_seed<T: AsRef<[u8]>>(bytes: &T, seed: u32) -> u32 {
        unsafe {
            ffi::MurmurHash2A(bytes.as_ref().as_ptr() as *const c_void,
                              bytes.as_ref().len() as i32,
                              seed)
        }
    }
}

impl_hasher!(MurmurHasher2A, Murmur2A);

/// MurmurHash2 32-bit neutral hash functions for the (slower) endian-neutral implementation
pub struct MurmurNeutral2 {}

impl FastHash for MurmurNeutral2 {
    type Value = u32;
    type Seed = u32;

    #[inline]
    fn hash_with_seed<T: AsRef<[u8]>>(bytes: &T, seed: u32) -> u32 {
        unsafe {
            ffi::MurmurHashNeutral2(bytes.as_ref().as_ptr() as *const c_void,
                                    bytes.as_ref().len() as i32,
                                    seed)
        }
    }
}

impl_hasher!(MurmurNeutral2Hasher, MurmurNeutral2);

/// MurmurHash2 32-bit aligned hash functions for the little-endian aligned-read-only implementation
pub struct MurmurAligned2 {}

impl FastHash for MurmurAligned2 {
    type Value = u32;
    type Seed = u32;

    #[inline]
    fn hash_with_seed<T: AsRef<[u8]>>(bytes: &T, seed: u32) -> u32 {
        unsafe {
            ffi::MurmurHashAligned2(bytes.as_ref().as_ptr() as *const c_void,
                                    bytes.as_ref().len() as i32,
                                    seed)
        }
    }
}

impl_hasher!(MurmurAligned2Hasher, MurmurAligned2);

/// MurmurHash2 64-bit hash functions for 64-bit processors
pub struct Murmur2_x64_64 {}

impl FastHash for Murmur2_x64_64 {
    type Value = u64;
    type Seed = u64;

    #[inline]
    fn hash_with_seed<T: AsRef<[u8]>>(bytes: &T, seed: u64) -> u64 {
        unsafe {
            ffi::MurmurHash64A(bytes.as_ref().as_ptr() as *const c_void,
                               bytes.as_ref().len() as i32,
                               seed)
        }
    }
}

impl_hasher!(Murmur2Hasher_x64_64, Murmur2_x64_64);

/// MurmurHash2 64-bit hash functions for 32-bit processors
pub struct Murmur2_x86_64 {}

impl FastHash for Murmur2_x86_64 {
    type Value = u64;
    type Seed = u64;

    #[inline]
    fn hash_with_seed<T: AsRef<[u8]>>(bytes: &T, seed: u64) -> u64 {
        unsafe {
            ffi::MurmurHash64B(bytes.as_ref().as_ptr() as *const c_void,
                               bytes.as_ref().len() as i32,
                               seed)
        }
    }
}

impl_hasher!(Murmur2Hasher_x86_64, Murmur2_x86_64);

/// MurmurHash2 32-bit hash functions for a byte array.
#[inline]
pub fn hash32<T: AsRef<[u8]>>(v: &T) -> u32 {
    Murmur2::hash(v)
}

/// MurmurHash2 32-bit hash function for a byte array.
/// For convenience, a 32-bit seed is also hashed into the result.
#[inline]
pub fn hash32_with_seed<T: AsRef<[u8]>>(v: &T, seed: u32) -> u32 {
    Murmur2::hash_with_seed(v, seed)
}

/// MurmurHash2 64-bit hash functions for a byte array.
#[inline]
pub fn hash64<T: AsRef<[u8]>>(v: &T) -> u64 {
    Murmur2_x64_64::hash(v)
}

/// MurmurHash2 64-bit hash function for a byte array.
/// For convenience, a 64-bit seed is also hashed into the result.
#[inline]
pub fn hash64_with_seed<T: AsRef<[u8]>>(v: &T, seed: u64) -> u64 {
    Murmur2_x64_64::hash_with_seed(v, seed)
}

#[cfg(test)]
mod tests {
    use std::hash::Hasher;

    use hasher::FastHash;
    use super::*;

    #[test]
    fn test_murmur2() {
        assert_eq!(Murmur2::hash(b"hello"), 3848350155);
        assert_eq!(Murmur2::hash_with_seed(b"hello", 123), 2385981934);
        assert_eq!(Murmur2::hash(b"helloworld"), 2155944146);

        let mut h = MurmurHasher2::new();

        h.write(b"hello");
        assert_eq!(h.finish(), 3848350155);

        h.write(b"world");
        assert_eq!(h.finish(), 2155944146);
    }

    #[test]
    fn test_murmur2a() {
        assert_eq!(Murmur2A::hash(b"hello"), 259931098);
        assert_eq!(Murmur2A::hash_with_seed(b"hello", 123), 509510832);
        assert_eq!(Murmur2A::hash(b"helloworld"), 403945221);

        let mut h = MurmurHasher2A::new();

        h.write(b"hello");
        assert_eq!(h.finish(), 259931098);

        h.write(b"world");
        assert_eq!(h.finish(), 403945221);
    }

    #[test]
    fn test_murmur2_neutral() {
        assert_eq!(MurmurNeutral2::hash(b"hello"), 3848350155);
        assert_eq!(MurmurNeutral2::hash_with_seed(b"hello", 123), 2385981934);
        assert_eq!(MurmurNeutral2::hash(b"helloworld"), 2155944146);

        let mut h = MurmurNeutral2Hasher::new();

        h.write(b"hello");
        assert_eq!(h.finish(), 3848350155);

        h.write(b"world");
        assert_eq!(h.finish(), 2155944146);
    }

    #[test]
    fn test_murmur2_aligned() {
        assert_eq!(MurmurAligned2::hash(b"hello"), 3848350155);
        assert_eq!(MurmurAligned2::hash_with_seed(b"hello", 123), 2385981934);
        assert_eq!(MurmurAligned2::hash(b"helloworld"), 2155944146);

        let mut h = MurmurAligned2Hasher::new();

        h.write(b"hello");
        assert_eq!(h.finish(), 3848350155);

        h.write(b"world");
        assert_eq!(h.finish(), 2155944146);
    }

    #[test]
    fn test_murmur2_x64_64() {
        assert_eq!(Murmur2_x64_64::hash(b"hello"), 2191231550387646743);
        assert_eq!(Murmur2_x64_64::hash_with_seed(b"hello", 123),
                   2597646618390559622);
        assert_eq!(Murmur2_x64_64::hash(b"helloworld"), 2139823713852166039);

        let mut h = Murmur2Hasher_x64_64::new();

        h.write(b"hello");
        assert_eq!(h.finish(), 2191231550387646743);

        h.write(b"world");
        assert_eq!(h.finish(), 2139823713852166039);
    }

    #[test]
    fn test_murmur2_x86_64() {
        assert_eq!(Murmur2_x86_64::hash(b"hello"), 17658855022785723775);
        assert_eq!(Murmur2_x86_64::hash_with_seed(b"hello", 123),
                   1883382312211796549);
        assert_eq!(Murmur2_x86_64::hash(b"helloworld"), 14017254558097603378);

        let mut h = Murmur2Hasher_x86_64::new();

        h.write(b"hello");
        assert_eq!(h.finish(), 17658855022785723775);

        h.write(b"world");
        assert_eq!(h.finish(), 14017254558097603378);
    }
}
