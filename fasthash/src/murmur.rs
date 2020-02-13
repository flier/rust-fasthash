//! `Murmur`, a suite of non-cryptographic hash functions that was used for hash-based lookups.
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
//! use fasthash::{murmur, MurmurHasher, FastHasher};
//!
//! fn hash<T: Hash>(t: &T) -> u64 {
//!     let mut s: MurmurHasher = MurmurHasher::new();
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

use crate::ffi;

use crate::hasher::FastHash;

/// `MurmurHash` 32-bit hash functions
///
/// # Example
///
/// ```
/// use fasthash::{murmur::Hash32, FastHash};
///
/// assert_eq!(Hash32::hash(b"hello"), 1773990585);
/// assert_eq!(Hash32::hash_with_seed(b"hello", 123), 2155802495);
/// assert_eq!(Hash32::hash(b"helloworld"), 567127608);
/// ```
#[derive(Clone, Default)]
pub struct Hash32;

impl FastHash for Hash32 {
    type Hash = u32;
    type Seed = u32;

    #[inline(always)]
    fn hash_with_seed<T: AsRef<[u8]>>(bytes: T, seed: u32) -> u32 {
        unsafe {
            ffi::MurmurHash1(
                bytes.as_ref().as_ptr() as *const c_void,
                bytes.as_ref().len() as i32,
                seed,
            )
        }
    }
}

trivial_hasher! {
    /// # Example
    ///
    /// ```
    /// use std::hash::Hasher;
    ///
    /// use fasthash::{murmur::Hasher32, FastHasher};
    ///
    /// let mut h = Hasher32::new();
    ///
    /// h.write(b"hello");
    /// assert_eq!(h.finish(), 1773990585);
    ///
    /// h.write(b"world");
    /// assert_eq!(h.finish(), 567127608);
    /// ```
    Hasher32(Hash32) -> u32
}

/// `MurmurHash` 32-bit aligned hash functions
///
/// # Example
///
/// ```
/// use fasthash::{murmur::Hash32Aligned, FastHash};
///
/// assert_eq!(Hash32Aligned::hash(b"hello"), 1773990585);
/// assert_eq!(Hash32Aligned::hash_with_seed(b"hello", 123), 2155802495);
/// assert_eq!(Hash32Aligned::hash(b"helloworld"), 567127608);
/// ```
#[derive(Clone, Default)]
pub struct Hash32Aligned;

impl FastHash for Hash32Aligned {
    type Hash = u32;
    type Seed = u32;

    #[inline(always)]
    fn hash_with_seed<T: AsRef<[u8]>>(bytes: T, seed: u32) -> u32 {
        unsafe {
            ffi::MurmurHash1Aligned(
                bytes.as_ref().as_ptr() as *const c_void,
                bytes.as_ref().len() as i32,
                seed,
            )
        }
    }
}

trivial_hasher! {
    /// # Example
    ///
    /// ```
    /// use std::hash::Hasher;
    ///
    /// use fasthash::{murmur::Hasher32Aligned, FastHasher};
    ///
    /// let mut h = Hasher32Aligned::new();
    ///
    /// h.write(b"hello");
    /// assert_eq!(h.finish(), 1773990585);
    ///
    /// h.write(b"world");
    /// assert_eq!(h.finish(), 567127608);
    /// ```
    Hasher32Aligned(Hash32Aligned) -> u32
}

/// `MurmurHash` 32-bit hash functions for a byte array.
#[inline(always)]
pub fn hash32<T: AsRef<[u8]>>(v: T) -> u32 {
    Hash32::hash(v)
}

/// `MurmurHash` 32-bit hash function for a byte array.
/// For convenience, a 32-bit seed is also hashed into the result.
#[inline(always)]
pub fn hash32_with_seed<T: AsRef<[u8]>>(v: T, seed: u32) -> u32 {
    Hash32::hash_with_seed(v, seed)
}

/// `MurmurHash` 32-bit aligned hash functions for a byte array.
#[inline(always)]
pub fn hash32_aligned<T: AsRef<[u8]>>(v: T) -> u32 {
    Hash32Aligned::hash(v)
}

/// `MurmurHash` 32-bit aligned hash function for a byte array.
/// For convenience, a 32-bit seed is also hashed into the result.
#[inline(always)]
pub fn hash32_aligned_with_seed<T: AsRef<[u8]>>(v: T, seed: u32) -> u32 {
    Hash32Aligned::hash_with_seed(v, seed)
}
