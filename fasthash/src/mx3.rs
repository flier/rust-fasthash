//! `mx3` - A bit mixer, pseudo random number generator and a hash function.
//!
//! <https://github.com/jonmaiga/mx3>
//!
//! Repo with non-cryptographic bit mixer, pseudo random number generator and a hash function.
//! The functions were found semi-algorithmically as detailed in those posts:
//!
//! - [The construct of a bit mixer](http://jonkagstrom.com/bit-mixer-construction/index.html)
//! - [Tuning bit mixers](http://jonkagstrom.com/tuning-bit-mixers/index.html)
//! - [The mx3 mix/prng/hash functions](http://jonkagstrom.com/mx3/index.html)
//! - [Improved mx3 and the RRC test](http://jonkagstrom.com/mx3/mx3_rev2.html)
//!
//! In short, first procedurally generated stack machines were used to find good mixer constructions.
//! Then each construction was tuned to see how far it could be pushed and finally I decided to take
//! the simplest most promising mixer and publish the result here.

use crate::ffi;
use crate::hasher::FastHash;

/// `mx3hash` 64-bit hash functions
///
/// # Example
///
/// ```
/// use fasthash::{mx3::Hash64, FastHash};
///
/// assert_eq!(Hash64::hash(b"hello"), 14956223317391262345);
/// assert_eq!(Hash64::hash_with_seed(b"hello", 123), 17861786974470549617);
/// assert_eq!(Hash64::hash(b"helloworld"), 12076870245923524935);
/// ```
#[derive(Clone, Default)]
pub struct Hash64;

impl FastHash for Hash64 {
    type Hash = u64;
    type Seed = u64;

    #[inline(always)]
    fn hash_with_seed<T: AsRef<[u8]>>(bytes: T, seed: u64) -> u64 {
        unsafe { ffi::mx3hash(bytes.as_ref().as_ptr(), bytes.as_ref().len(), seed) }
    }
}

trivial_hasher! {
    /// # Example
    ///
    /// ```
    /// use std::hash::Hasher;
    ///
    /// use fasthash::{mx3::Hasher64, FastHasher};
    ///
    /// let mut h = Hasher64::new();
    ///
    /// h.write(b"hello");
    /// assert_eq!(h.finish(), 14956223317391262345);
    ///
    /// h.write(b"world");
    /// assert_eq!(h.finish(), 12076870245923524935);
    /// ```
    Hasher64(Hash64) -> u64
}

/// `mx3hash` 64-bit hash functions for a byte array.
///
/// # Example
///
/// ```
/// use fasthash::mx3;
///
/// assert_eq!(mx3::hash64(b"hello"), 14956223317391262345);
/// ```
#[inline(always)]
pub fn hash64<T: AsRef<[u8]>>(v: T) -> u64 {
    Hash64::hash(v)
}

/// `mx3hash` 64-bit hash function for a byte array.
/// For convenience, a 64-bit seed is also hashed into the result.
///
/// # Example
///
/// ```
/// use fasthash::mx3;
///
/// assert_eq!(mx3::hash64_with_seed(b"hello", 123), 17861786974470549617);
/// ```
#[inline(always)]
pub fn hash64_with_seed<T: AsRef<[u8]>>(v: T, seed: u64) -> u64 {
    Hash64::hash_with_seed(v, seed)
}
