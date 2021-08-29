//! `wyhash` and `wyrand` are the ideal 64-bit hash function and PRNG respectively:
//!
//! by Wang Yi <godspeed_china@yeah.net>
//!
//! https://github.com/wangyi-fudan/wyhash
//!
//! - solid: wyhash passed SMHasher, wyrand passed BigCrush, practrand.
//! - portable: 64-bit/32-bit system, big/little endian.
//! - fastest: Efficient on 64-bit machines, especially for short keys.
//! - simplest: In the sense of code size.
//!
//! # Example
//!
//! ```
//! use std::hash::{Hash, Hasher};
//!
//! use fasthash::wy;
//!
//! fn hash<T: Hash>(t: &T) -> u64 {
//!     let mut s: wy::Hasher64 = Default::default();
//!     t.hash(&mut s);
//!     s.finish()
//! }
//!
//! let h = wy::hash64(b"hello world\xff");
//!
//! assert_eq!(h, hash(&"hello world"));
//! ```
//!
use crate::ffi;

use crate::hasher::FastHash;

/// `whhash` 64-bit hash functions
///
/// # Example
///
/// ```
/// use fasthash::{wy::Hash64, FastHash};
///
/// assert_eq!(Hash64::hash(b"hello"), 18063072054746964485);
/// assert_eq!(Hash64::hash_with_seed(b"hello", 123), 13299223181586284300);
/// assert_eq!(Hash64::hash(b"helloworld"), 13016868308130960481);
/// ```
#[derive(Clone, Default)]
pub struct Hash64;

impl FastHash for Hash64 {
    type Hash = u64;
    type Seed = u64;

    #[inline(always)]
    fn hash_with_seed<T: AsRef<[u8]>>(bytes: T, seed: Self::Seed) -> Self::Hash {
        unsafe {
            ffi::wyhash64(
                bytes.as_ref().as_ptr() as *const _,
                bytes.as_ref().len() as _,
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
    /// use fasthash::{wy::Hasher64, FastHasher};
    ///
    /// let mut h = Hasher64::new();
    ///
    /// h.write(b"hello");
    /// assert_eq!(h.finish(), 18063072054746964485);
    ///
    /// h.write(b"world");
    /// assert_eq!(h.finish(), 13016868308130960481);
    /// ```
    Hasher64(Hash64) -> u64
}

/// `wyhash` 64-bit hash functions for a byte array.
#[inline(always)]
pub fn hash64<T: AsRef<[u8]>>(v: T) -> u64 {
    Hash64::hash(v)
}

/// `wyhash` 64-bit hash function for a byte array.
/// For convenience, a 32-bit seed is also hashed into the result.
#[inline(always)]
pub fn hash64_with_seed<T: AsRef<[u8]>>(v: T, seed: u64) -> u64 {
    Hash64::hash_with_seed(v, seed)
}
