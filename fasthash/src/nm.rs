//! `nmhash`
//!
//! <https://github.com/gzm55/hash-garage>
//!
//! 32bit hash, the core loop is constructed of invertible operations, and the multiplications are limited to 16x16->16.
//! For better speed on short keys, the limitation is loosen to 32x32->32 multiplication in the NMHASH32X variant
//! when hashing the short keys or avalanching the final result of the core loop.
use crate::ffi;

use crate::hasher::FastHash;

/// `nmhash` 32-bit hash functions
///
/// # Example
///
/// ```
/// use fasthash::{nm::Hash32, FastHash};
///
/// assert_eq!(Hash32::hash(b"hello"), 1473846654);
/// assert_eq!(Hash32::hash_with_seed(b"hello", 123), 1550836310);
/// assert_eq!(Hash32::hash(b"helloworld"), 827440361);
/// ```
#[derive(Clone, Default)]
pub struct Hash32;

impl FastHash for Hash32 {
    type Hash = u32;
    type Seed = u32;

    #[inline(always)]
    fn hash_with_seed<T: AsRef<[u8]>>(bytes: T, seed: u32) -> u32 {
        unsafe {
            ffi::NMHASH32_(
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
    /// use fasthash::{nm::Hasher32, FastHasher};
    ///
    /// let mut h = Hasher32::new();
    ///
    /// h.write(b"hello");
    /// assert_eq!(h.finish(), 1473846654);
    ///
    /// h.write(b"world");
    /// assert_eq!(h.finish(), 827440361);
    /// ```
    Hasher32(Hash32) -> u32
}

/// `nmhash` 32-bit hash functions for a byte array.
///
/// # Example
///
/// ```
/// use fasthash::nm;
///
/// assert_eq!(nm::hash32(b"hello"), 1473846654);
/// ```
#[inline(always)]
pub fn hash32<T: AsRef<[u8]>>(v: T) -> u32 {
    Hash32::hash(v)
}

/// `nmhash` 32-bit hash function for a byte array.
/// For convenience, a 32-bit seed is also hashed into the result.
///
/// # Example
///
/// ```
/// use fasthash::nm;
///
/// assert_eq!(nm::hash32_with_seed(b"hello", 123), 1550836310);
/// ```
#[inline(always)]
pub fn hash32_with_seed<T: AsRef<[u8]>>(v: T, seed: u32) -> u32 {
    Hash32::hash_with_seed(v, seed)
}
