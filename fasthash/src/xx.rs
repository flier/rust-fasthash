//! `xxHash` - Extremely fast hash algorithm
//!
//! by Yann Collet
//!
//! http://cyan4973.github.io/xxHash/
//!
//! xxHash is an Extremely fast Hash algorithm, running at RAM speed limits.
//! It successfully completes the `SMHasher` test suite which evaluates collision,
//! dispersion and randomness qualities of hash functions. Code is highly portable,
//! and hashes are identical on all platforms (little / big endian).
//!
//!
//! # Example
//!
//! ```
//! use std::hash::{Hash, Hasher};
//!
//! use fasthash::{xx, XXHasher};
//!
//! fn hash<T: Hash>(t: &T) -> u64 {
//!     let mut s: XXHasher = Default::default();
//!     t.hash(&mut s);
//!     s.finish()
//! }
//!
//! let h = xx::hash64(b"hello world\xff");
//!
//! assert_eq!(h, hash(&"hello world"));
//! ```
//!
use std::hash::Hasher;
use std::os::raw::c_void;

use ffi;

use hasher::{FastHash, FastHasher, StreamHasher};

/// xxHash 32-bit hash functions
pub struct XXHash32 {}

impl FastHash for XXHash32 {
    type Value = u32;
    type Seed = u32;

    #[inline]
    fn hash_with_seed<T: AsRef<[u8]>>(bytes: &T, seed: u32) -> u32 {
        unsafe {
            ffi::XXH32(bytes.as_ref().as_ptr() as *const c_void,
                       bytes.as_ref().len(),
                       seed)
        }
    }
}

/// xxHash 64-bit hash functions
pub struct XXHash64 {}

impl FastHash for XXHash64 {
    type Value = u64;
    type Seed = u64;

    #[inline]
    fn hash_with_seed<T: AsRef<[u8]>>(bytes: &T, seed: u64) -> u64 {
        unsafe {
            ffi::XXH64(bytes.as_ref().as_ptr() as *const c_void,
                       bytes.as_ref().len(),
                       seed)
        }
    }
}

/// xxHash 32-bit hash functions for a byte array.
#[inline]
pub fn hash32<T: AsRef<[u8]>>(v: &T) -> u32 {
    XXHash32::hash(v)
}

/// xxHash 32-bit hash function for a byte array.
/// For convenience, a 32-bit seed is also hashed into the result.
#[inline]
pub fn hash32_with_seed<T: AsRef<[u8]>>(v: &T, seed: u32) -> u32 {
    XXHash32::hash_with_seed(v, seed)
}

/// xxHash 64-bit hash functions for a byte array.
#[inline]
pub fn hash64<T: AsRef<[u8]>>(v: &T) -> u64 {
    XXHash64::hash(v)
}

/// xxHash 64-bit hash function for a byte array.
/// For convenience, a 64-bit seed is also hashed into the result.
#[inline]
pub fn hash64_with_seed<T: AsRef<[u8]>>(v: &T, seed: u64) -> u64 {
    XXHash64::hash_with_seed(v, seed)
}

/// An implementation of `std::hash::Hasher`.
pub struct XXHasher32(*mut ffi::XXH32_state_t);

impl Default for XXHasher32 {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for XXHasher32 {
    #[inline]
    fn drop(&mut self) {
        unsafe {
            ffi::XXH32_freeState(self.0);
        }
    }
}

impl Hasher for XXHasher32 {
    #[inline]
    fn finish(&self) -> u64 {
        unsafe { ffi::XXH32_digest(self.0) as u64 }
    }

    #[inline]
    fn write(&mut self, bytes: &[u8]) {
        unsafe {
            ffi::XXH32_update(self.0,
                              bytes.as_ref().as_ptr() as *const c_void,
                              bytes.as_ref().len());
        }
    }
}

impl FastHasher for XXHasher32 {
    type Seed = u32;

    #[inline]
    fn with_seed(seed: u32) -> Self {
        let h = unsafe { ffi::XXH32_createState() };

        unsafe {
            ffi::XXH32_reset(h, seed);
        }

        XXHasher32(h)
    }
}

impl StreamHasher for XXHasher32 {}

impl_fasthash!(XXHasher32, XXHash32);

/// An implementation of `std::hash::Hasher`.
pub struct XXHasher64(*mut ffi::XXH64_state_t);

impl Default for XXHasher64 {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for XXHasher64 {
    fn drop(&mut self) {
        unsafe {
            ffi::XXH64_freeState(self.0);
        }
    }
}

impl Hasher for XXHasher64 {
    #[inline]
    fn finish(&self) -> u64 {
        unsafe { ffi::XXH64_digest(self.0) }
    }

    #[inline]
    fn write(&mut self, bytes: &[u8]) {
        unsafe {
            ffi::XXH64_update(self.0,
                              bytes.as_ref().as_ptr() as *const c_void,
                              bytes.as_ref().len());
        }
    }
}

impl FastHasher for XXHasher64 {
    type Seed = u64;

    #[inline]
    fn with_seed(seed: u64) -> Self {
        let h = unsafe { ffi::XXH64_createState() };

        unsafe {
            ffi::XXH64_reset(h, seed);
        }

        XXHasher64(h)
    }
}

impl StreamHasher for XXHasher64 {}

impl_fasthash!(XXHasher64, XXHash64);

#[cfg(test)]
mod tests {
    use std::io::Cursor;
    use std::hash::Hasher;

    use hasher::{FastHash, FastHasher, StreamHasher};
    use super::*;

    #[test]
    fn test_xxh32() {
        assert_eq!(XXHash32::hash(b"hello"), 4211111929);
        assert_eq!(XXHash32::hash_with_seed(b"hello", 123), 2147069998);
        assert_eq!(XXHash32::hash(b"helloworld"), 593682946);

        let mut h = XXHasher32::new();

        h.write(b"hello");
        assert_eq!(h.finish(), 4211111929);

        h.write(b"world");
        assert_eq!(h.finish(), 593682946);

        h.write_stream(&mut Cursor::new(&[0_u8; 4567][..])).unwrap();
        assert_eq!(h.finish(), 2113960620);
    }

    #[test]
    fn test_xxh64() {
        assert_eq!(XXHash64::hash(b"hello"), 2794345569481354659);
        assert_eq!(XXHash64::hash_with_seed(b"hello", 123), 2900467397628653179);
        assert_eq!(XXHash64::hash(b"helloworld"), 9228181307863624271);

        let mut h = XXHasher64::new();

        h.write(b"hello");
        assert_eq!(h.finish(), 2794345569481354659);

        h.write(b"world");
        assert_eq!(h.finish(), 9228181307863624271);

        h.write_stream(&mut Cursor::new(&[0_u8; 4567][..])).unwrap();
        assert_eq!(h.finish(), 6304142433100597454);
    }
}
