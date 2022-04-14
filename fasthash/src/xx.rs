//! `xxHash` - Extremely fast hash algorithm
//!
//! by Yann Collet
//!
//! <http://cyan4973.github.io/xxHash/>
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
use std::ptr::NonNull;

use crate::ffi;

use crate::hasher::{FastHash, FastHasher, StreamHasher};

/// xxHash 32-bit hash functions
///
/// # Example
///
/// ```
/// use fasthash::{xx::Hash32, FastHash};
///
/// assert_eq!(Hash32::hash(b"hello"), 4211111929);
/// assert_eq!(Hash32::hash_with_seed(b"hello", 123), 2147069998);
/// assert_eq!(Hash32::hash(b"helloworld"), 593682946);
/// ```
#[derive(Clone, Default)]
pub struct Hash32;

impl FastHash for Hash32 {
    type Hash = u32;
    type Seed = u32;

    #[inline(always)]
    fn hash_with_seed<T: AsRef<[u8]>>(bytes: T, seed: u32) -> u32 {
        unsafe {
            ffi::XXH32(
                bytes.as_ref().as_ptr() as *const _,
                bytes.as_ref().len(),
                seed,
            )
        }
    }
}

/// xxHash 64-bit hash functions
///
/// # Example
///
/// ```
/// use fasthash::{xx::Hash64, FastHash};
///
/// assert_eq!(Hash64::hash(b"hello"), 2794345569481354659);
/// assert_eq!(Hash64::hash_with_seed(b"hello", 123), 2900467397628653179);
/// assert_eq!(Hash64::hash(b"helloworld"), 9228181307863624271);
/// ```
#[derive(Clone, Default)]
pub struct Hash64;

impl FastHash for Hash64 {
    type Hash = u64;
    type Seed = u64;

    #[inline(always)]
    fn hash_with_seed<T: AsRef<[u8]>>(bytes: T, seed: u64) -> u64 {
        unsafe {
            ffi::XXH64(
                bytes.as_ref().as_ptr() as *const _,
                bytes.as_ref().len(),
                seed,
            )
        }
    }
}

/// xxHash 32-bit hash functions for a byte array.
#[inline(always)]
pub fn hash32<T: AsRef<[u8]>>(v: T) -> u32 {
    Hash32::hash(v)
}

/// xxHash 32-bit hash function for a byte array.
/// For convenience, a 32-bit seed is also hashed into the result.
#[inline(always)]
pub fn hash32_with_seed<T: AsRef<[u8]>>(v: T, seed: u32) -> u32 {
    Hash32::hash_with_seed(v, seed)
}

/// xxHash 64-bit hash functions for a byte array.
#[inline(always)]
pub fn hash64<T: AsRef<[u8]>>(v: T) -> u64 {
    Hash64::hash(v)
}

/// xxHash 64-bit hash function for a byte array.
/// For convenience, a 64-bit seed is also hashed into the result.
#[inline(always)]
pub fn hash64_with_seed<T: AsRef<[u8]>>(v: T, seed: u64) -> u64 {
    Hash64::hash_with_seed(v, seed)
}

/// An implementation of `std::hash::Hasher`.
///
/// # Example
///
/// ```
/// use std::hash::Hasher;
/// use std::io::Cursor;
///
/// use fasthash::{xx::Hasher32, FastHasher, StreamHasher};
///
/// let mut h = Hasher32::new();
///
/// h.write(b"hello");
/// assert_eq!(h.finish(), 4211111929);
///
/// h.write(b"world");
/// assert_eq!(h.finish(), 593682946);
///
/// h.write_stream(&mut Cursor::new(&[0_u8; 4567][..])).unwrap();
/// assert_eq!(h.finish(), 2113960620);
/// ```
pub struct Hasher32(NonNull<ffi::XXH32_state_t>);

impl Default for Hasher32 {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for Hasher32 {
    #[inline(always)]
    fn drop(&mut self) {
        unsafe {
            ffi::XXH32_freeState(self.0.as_ptr());
        }
    }
}

impl Clone for Hasher32 {
    fn clone(&self) -> Self {
        unsafe {
            let state = ffi::XXH32_createState();

            ffi::XXH32_copyState(state, self.0.as_ptr());

            Hasher32(NonNull::new_unchecked(state))
        }
    }
}

impl Hasher for Hasher32 {
    #[inline(always)]
    fn finish(&self) -> u64 {
        unsafe { u64::from(ffi::XXH32_digest(self.0.as_ptr())) }
    }

    #[inline(always)]
    fn write(&mut self, bytes: &[u8]) {
        unsafe {
            ffi::XXH32_update(self.0.as_ptr(), bytes.as_ptr() as *const _, bytes.len());
        }
    }
}

impl FastHasher for Hasher32 {
    type Seed = u32;
    type Output = u32;

    #[inline(always)]
    fn with_seed(seed: u32) -> Self {
        unsafe {
            let h = ffi::XXH32_createState();

            ffi::XXH32_reset(h, seed);

            Hasher32(NonNull::new_unchecked(h))
        }
    }
}

impl StreamHasher for Hasher32 {}

impl_build_hasher!(Hasher32, Hash32);

/// An implementation of `std::hash::Hasher`.
///
/// # Example
///
/// ```
/// use std::hash::Hasher;
/// use std::io::Cursor;
///
/// use fasthash::{xx::Hasher64, FastHasher, StreamHasher};
///
/// let mut h = Hasher64::new();
///
/// h.write(b"hello");
/// assert_eq!(h.finish(), 2794345569481354659);
///
/// h.write(b"world");
/// assert_eq!(h.finish(), 9228181307863624271);
///
/// h.write_stream(&mut Cursor::new(&[0_u8; 4567][..])).unwrap();
/// assert_eq!(h.finish(), 6304142433100597454);
/// ```
pub struct Hasher64(NonNull<ffi::XXH64_state_t>);

impl Default for Hasher64 {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for Hasher64 {
    fn drop(&mut self) {
        unsafe {
            ffi::XXH64_freeState(self.0.as_ptr());
        }
    }
}

impl Clone for Hasher64 {
    fn clone(&self) -> Self {
        unsafe {
            let state = ffi::XXH64_createState();

            ffi::XXH64_copyState(state, self.0.as_ptr());

            Hasher64(NonNull::new_unchecked(state))
        }
    }
}

impl Hasher for Hasher64 {
    #[inline(always)]
    fn finish(&self) -> u64 {
        unsafe { ffi::XXH64_digest(self.0.as_ptr()) }
    }

    #[inline(always)]
    fn write(&mut self, bytes: &[u8]) {
        unsafe {
            ffi::XXH64_update(self.0.as_ptr(), bytes.as_ptr() as *const _, bytes.len());
        }
    }
}

impl FastHasher for Hasher64 {
    type Seed = u64;
    type Output = u64;

    #[inline(always)]
    fn with_seed(seed: u64) -> Self {
        unsafe {
            let h = ffi::XXH64_createState();

            ffi::XXH64_reset(h, seed);

            Hasher64(NonNull::new_unchecked(h))
        }
    }
}

impl StreamHasher for Hasher64 {}

impl_build_hasher!(Hasher64, Hash64);
