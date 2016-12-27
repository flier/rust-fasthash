//! Lookup3, non-cryptographic hash.
//!
//! by Bob Jekins
//!
//! http://burtleburtle.net/bob/c/lookup3.c
//!
//!
//! # Example
//!
//! ```
//! use std::hash::{Hash, Hasher};
//!
//! use fasthash::{lookup3, Lookup3Hasher};
//!
//! fn hash<T: Hash>(t: &T) -> u64 {
//!     let mut s: Lookup3Hasher = Default::default();
//!     t.hash(&mut s);
//!     s.finish()
//! }
//!
//! let h = lookup3::hash32(b"hello world\xff");
//!
//! assert_eq!(h, hash(&"hello world") as u32);
//! ```
//!
use std::os::raw::c_void;

use ffi;

use hasher::{FastHash, FastHasher};

/// Lookup3 32-bit hash functions
pub struct Lookup3 {}

impl FastHash for Lookup3 {
    type Value = u32;
    type Seed = u32;

    #[inline]
    fn hash_with_seed<T: AsRef<[u8]>>(bytes: &T, seed: u32) -> u32 {
        unsafe {
            ffi::lookup3(bytes.as_ref().as_ptr() as *const c_void,
                         bytes.as_ref().len() as i32,
                         seed)
        }
    }
}

impl_hasher!(Lookup3Hasher, Lookup3);

/// Lookup3 32-bit hash functions for a byte array.
#[inline]
pub fn hash32<T: AsRef<[u8]>>(v: &T) -> u32 {
    Lookup3::hash(v)
}

/// Lookup3 32-bit hash function for a byte array.
/// For convenience, a 32-bit seed is also hashed into the result.
#[inline]
pub fn hash32_with_seed<T: AsRef<[u8]>>(v: &T, seed: u32) -> u32 {
    Lookup3::hash_with_seed(v, seed)
}

#[cfg(test)]
mod tests {
    use std::hash::Hasher;

    use hasher::{FastHash, FastHasher};
    use super::*;

    #[test]
    fn test_lookup3() {
        assert_eq!(Lookup3::hash(b"hello"), 885767278);
        assert_eq!(Lookup3::hash_with_seed(b"hello", 123), 632258402);
        assert_eq!(Lookup3::hash(b"helloworld"), 1392336737);

        let mut h = Lookup3Hasher::new();

        h.write(b"hello");
        assert_eq!(h.finish(), 885767278);

        h.write(b"world");
        assert_eq!(h.finish(), 1392336737);
    }
}
