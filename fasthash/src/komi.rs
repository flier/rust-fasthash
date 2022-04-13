//! KOMIHASH - version 4.3
//!
//! Description is available at https://github.com/avaneev/komihash
//!
//! The komihash() function available in the komihash.h file implements a very fast 64-bit hash function,
//! mainly designed for hash-table and hash-map uses; produces identical hashes on both big- and little-endian systems.
//! Function's code is portable, scalar.
//!
//! This function features both a high large-block hashing performance (26 GB/s on Ryzen 3700X) and
//! a high hashing throughput for small messages (about 11 cycles/hash for 0-15-byte messages).
//! Performance on 32-bit systems is, however, quite low.
//! Also, large-block hashing performance on big-endian systems may be lower due to the need of byte-swapping.
//!
//! Technically, komihash is close to the class of hash functions like wyhash and CircleHash,
//! which are, in turn, close to the lehmer64 PRNG. However, komihash is structurally different to them in
//! that it accumulates the full 128-bit multiplication result, without "compression" into a single 64-bit state variable.
//! Thus komihash does not lose differentiation between consecutive states while others may.
//! Another important difference in komihash is that it parses the input message without overlaps.
//! While overlaps allow a function to have fewer code branches, they are considered "non-ideal",
//! potentially causing collisions and seed value flaws. Beside that, komihash features superior seed value handling
//! and Perlin Noise hashing.
//!
//! Note that this function is not cryptographically-secure: in open systems it should only be used with a secret seed,
//! to minimize the chance of a collision attack.
//!
//! This function passes all SMHasher tests.

#![allow(non_camel_case_types)]
use std::os::raw::c_void;

use crate::ffi;
use crate::hasher::FastHash;

/// `KomiHash` 64-bit hash functions
///
/// # Example
///
/// ```
/// use fasthash::{komi::Hash64, FastHash};
///
/// assert_eq!(Hash64::hash(b"hello"), 13600937942708275382);
/// assert_eq!(Hash64::hash_with_seed(b"hello", 123), 2999297757959586272);
/// assert_eq!(Hash64::hash(b"helloworld"), 201326005067243850);
/// ```
#[derive(Clone, Default)]
pub struct Hash64;

impl FastHash for Hash64 {
    type Hash = u64;
    type Seed = u64;

    #[inline(always)]
    fn hash_with_seed<T: AsRef<[u8]>>(bytes: T, seed: u64) -> u64 {
        unsafe {
            ffi::komihash64(
                bytes.as_ref().as_ptr() as *const c_void,
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
    /// use fasthash::{komi::Hasher64, FastHasher};
    ///
    /// let mut h = Hasher64::new();
    ///
    /// h.write(b"hello");
    /// assert_eq!(h.finish(), 13600937942708275382);
    ///
    /// h.write(b"world");
    /// assert_eq!(h.finish(), 201326005067243850);
    /// ```
    Hasher64(Hash64) -> u64
}

/// `KomiHash` 64-bit hash functions for a byte array.
///
/// # Example
///
/// ```
/// use fasthash::komi;
///
/// assert_eq!(komi::hash64(b"hello"), 13600937942708275382);
/// ```
#[inline(always)]
pub fn hash64<T: AsRef<[u8]>>(v: T) -> u64 {
    Hash64::hash(v)
}

/// `KomiHash` 64-bit hash function for a byte array.
/// For convenience, a 64-bit seed is also hashed into the result.
///
/// # Example
///
/// ```
/// use fasthash::komi;
///
/// assert_eq!(komi::hash64_with_seed(b"hello", 123), 2999297757959586272);
/// ```
#[inline(always)]
pub fn hash64_with_seed<T: AsRef<[u8]>>(v: T, seed: u64) -> u64 {
    Hash64::hash_with_seed(v, seed)
}
