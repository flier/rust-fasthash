//! `pengyhash` - Fast 64-bit non-cryptographic hash algorithm
//!
//! <https://github.com/tinypeng/pengyhash>

use crate::ffi;
use crate::hasher::FastHash;

/// `pengyhash` 64-bit hash functions
///
/// # Example
///
/// ```
/// use fasthash::{pengy::Hash64, FastHash};
///
/// assert_eq!(Hash64::hash(b"hello"), 16216849072302672261);
/// assert_eq!(Hash64::hash_with_seed(b"hello", 123), 9079223790445393170);
/// assert_eq!(Hash64::hash(b"helloworld"), 3542539606493928684);
/// ```
#[derive(Clone, Default)]
pub struct Hash64;

impl FastHash for Hash64 {
    type Hash = u64;
    type Seed = u32;

    #[inline(always)]
    fn hash_with_seed<T: AsRef<[u8]>>(bytes: T, seed: u32) -> u64 {
        unsafe {
            ffi::pengyhash(
                bytes.as_ref().as_ptr() as *const _,
                bytes.as_ref().len(),
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
    /// use fasthash::{pengy::Hasher64, FastHasher};
    ///
    /// let mut h = Hasher64::new();
    ///
    /// h.write(b"hello");
    /// assert_eq!(h.finish(), 16216849072302672261);
    ///
    /// h.write(b"world");
    /// assert_eq!(h.finish(), 3542539606493928684);
    /// ```
    Hasher64(Hash64) -> u64
}

/// `pengyhash` 64-bit hash functions for a byte array.
///
/// # Example
///
/// ```
/// use fasthash::pengy;
///
/// assert_eq!(pengy::hash64(b"hello"), 16216849072302672261);
/// ```
#[inline(always)]
pub fn hash64<T: AsRef<[u8]>>(v: T) -> u64 {
    Hash64::hash(v)
}

/// `pengyhash` 64-bit hash function for a byte array.
/// For convenience, a 64-bit seed is also hashed into the result.
///
/// # Example
///
/// ```
/// use fasthash::pengy;
///
/// assert_eq!(pengy::hash64_with_seed(b"hello", 123), 9079223790445393170);
/// ```
#[inline(always)]
pub fn hash64_with_seed<T: AsRef<[u8]>>(v: T, seed: u32) -> u64 {
    Hash64::hash_with_seed(v, seed)
}
