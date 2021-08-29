//! `Meow` - A Fast Non-cryptographic Hash
//!
//! (C) Copyright 2018-2019 by Molly Rocket, Inc. (https://mollyrocket.com)
//!
//! See https://mollyrocket.com/meowhash for details.
//!
//! # Example
//!
//! ```
//! use std::hash::Hash;
//!
//! use fasthash::{meow, HasherExt};
//!
//! fn hash<T: Hash>(t: &T) -> u128 {
//!     let mut s: meow::Hasher = Default::default();
//!     t.hash(&mut s);
//!     s.finish_ext()
//! }
//!
//! let h = meow::hash128(b"hello world\xff");
//!
//! assert_eq!(h, hash(&"hello world"));
//! ```
//!
use std::mem;
use std::os::raw::c_void;

use derive_more::{Deref, From, Into};
use rand::Rng;

use crate::ffi;
use crate::hasher::{self, FastHash};

/// Generate hash seeds for `meow`
#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deref, From, Into)]
pub struct Seed(pub [u8; 128]);

impl Default for Seed {
    fn default() -> Self {
        Seed([
            0x32, 0x43, 0xF6, 0xA8, 0x88, 0x5A, 0x30, 0x8D, 0x31, 0x31, 0x98, 0xA2, 0xE0, 0x37,
            0x07, 0x34, 0x4A, 0x40, 0x93, 0x82, 0x22, 0x99, 0xF3, 0x1D, 0x00, 0x82, 0xEF, 0xA9,
            0x8E, 0xC4, 0xE6, 0xC8, 0x94, 0x52, 0x82, 0x1E, 0x63, 0x8D, 0x01, 0x37, 0x7B, 0xE5,
            0x46, 0x6C, 0xF3, 0x4E, 0x90, 0xC6, 0xCC, 0x0A, 0xC2, 0x9B, 0x7C, 0x97, 0xC5, 0x0D,
            0xD3, 0xF8, 0x4D, 0x5B, 0x5B, 0x54, 0x70, 0x91, 0x79, 0x21, 0x6D, 0x5D, 0x98, 0x97,
            0x9F, 0xB1, 0xBD, 0x13, 0x10, 0xBA, 0x69, 0x8D, 0xFB, 0x5A, 0xC2, 0xFF, 0xD7, 0x2D,
            0xBD, 0x01, 0xAD, 0xFB, 0x7B, 0x8E, 0x1A, 0xFE, 0xD6, 0xA2, 0x67, 0xE9, 0x6B, 0xA7,
            0xC9, 0x04, 0x5F, 0x12, 0xC7, 0xF9, 0x92, 0x4A, 0x19, 0x94, 0x7B, 0x39, 0x16, 0xCF,
            0x70, 0x80, 0x1F, 0x2E, 0x28, 0x58, 0xEF, 0xC1, 0x66, 0x36, 0x92, 0x0D, 0x87, 0x15,
            0x74, 0xE6,
        ])
    }
}

impl From<u64> for Seed {
    fn from(seed: u64) -> Self {
        let mut b = [0; 128];
        unsafe {
            ffi::MeowHashExpandSeed(
                mem::size_of::<u64>() as u64,
                &seed as *const _ as *mut _,
                b.as_mut_ptr(),
            );
        }
        Seed(b)
    }
}

impl From<u128> for Seed {
    fn from(seed: u128) -> Self {
        let mut b = [0; 128];
        unsafe {
            ffi::MeowHashExpandSeed(
                mem::size_of::<u128>() as u64,
                &seed as *const _ as *mut _,
                b.as_mut_ptr(),
            );
        }
        Seed(b)
    }
}

impl From<hasher::Seed> for Seed {
    #[inline(always)]
    fn from(mut seed: hasher::Seed) -> Seed {
        let mut b = [0; 128];
        seed.fill(&mut b);
        Seed(b)
    }
}

/// `Meow` 128-bit hash functions
///
/// # Example
///
/// ```
/// use fasthash::{meow::Hash128, FastHash};
///
/// assert_eq!(Hash128::hash(b"hello"), 287823689163471951033538203431451692478);
/// assert_eq!(Hash128::hash_with_seed(b"hello", 123u64.into()), 60552855887416612272420513695414607282);
/// assert_eq!(Hash128::hash(b"helloworld"), 149236362065540004012572291671223589700);
/// ```
#[derive(Clone, Default)]
pub struct Hash128;

impl FastHash for Hash128 {
    type Hash = u128;
    type Seed = Seed;

    #[inline(always)]
    fn hash_with_seed<T: AsRef<[u8]>>(bytes: T, seed: Seed) -> u128 {
        let mut hash = 0u128;
        unsafe {
            ffi::MeowHash128(
                bytes.as_ref().as_ptr() as *const _,
                bytes.as_ref().len() as i32,
                seed.as_ptr() as *mut c_void,
                (&mut hash) as *mut _ as *mut _,
            )
        }
        hash
    }
}

trivial_hasher! {
    /// # Example
    ///
    /// ```
    /// use std::hash::Hasher as _;
    ///
    /// use fasthash::{meow::Hasher, FastHasher, HasherExt};
    ///
    /// let mut h = Hasher::new();
    ///
    /// h.write(b"hello");
    /// assert_eq!(h.finish_ext(), 287823689163471951033538203431451692478);
    ///
    /// h.write(b"world");
    /// assert_eq!(h.finish_ext(), 149236362065540004012572291671223589700);
    /// ```
    Hasher(Hash128) -> u128
}

/// `Meow` 128-bit hash functions for a byte array.
///
/// # Example
///
/// ```
/// use fasthash::meow::hash128;
///
/// assert_eq!(hash128("helloworld"), 149236362065540004012572291671223589700);
/// ```
#[inline(always)]
pub fn hash128<T: AsRef<[u8]>>(v: T) -> u128 {
    Hash128::hash(v)
}

/// `Meow` 128-bit hash function for a byte array.
/// For convenience, a 1024-bit seed is also hashed into the result.
///
/// # Example
///
/// ```
/// use fasthash::meow::hash128_with_seed;
///
/// assert_eq!(hash128_with_seed("helloworld", 123u64), 170522160844008905659318271476576158043);
/// ```
#[inline(always)]
pub fn hash128_with_seed<T: AsRef<[u8]>, S: Into<Seed>>(v: T, seed: S) -> u128 {
    Hash128::hash_with_seed(v, seed.into())
}
