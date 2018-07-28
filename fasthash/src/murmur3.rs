//! `Murmur3`, a suite of non-cryptographic hash functions that was used for hash-based lookups.
//!
//! by Austin Appleby (aappleby (AT) gmail)
//!
//! https://sites.google.com/site/murmurhash/
//!
//! # Note
//!
//! The x86 and x64 versions do _not_ produce the same results, as the
//! algorithms are optimized for their respective platforms. You can still
//! compile and run any of them on any platform, but your performance with the
//! non-native version will be less than optimal.
//!
//! # Example
//!
//! ```
//! use std::hash::{Hash, Hasher};
//!
//! use fasthash::{murmur3, Murmur3Hasher};
//!
//! fn hash<T: Hash>(t: &T) -> u64 {
//!     let mut s: Murmur3Hasher = Default::default();
//!     t.hash(&mut s);
//!     s.finish()
//! }
//!
//! let h = murmur3::hash128(b"hello world\xff");
//!
//! assert_eq!(h as u64, hash(&"hello world"));
//! ```
//!
#![allow(non_camel_case_types)]
use std::os::raw::c_void;

use ffi;

use hasher::{FastHash, FastHasher};

/// `MurmurHash3` 32-bit hash functions
pub struct Murmur3_x86_32 {}

impl FastHash for Murmur3_x86_32 {
    type Value = u32;
    type Seed = u32;

    #[inline]
    fn hash_with_seed<T: AsRef<[u8]>>(bytes: &T, seed: u32) -> u32 {
        unsafe {
            let mut hash = 0_u32;

            ffi::MurmurHash3_x86_32(
                bytes.as_ref().as_ptr() as *const c_void,
                bytes.as_ref().len() as i32,
                seed,
                &mut hash as *mut u32 as *mut c_void,
            );

            hash
        }
    }
}

impl_hasher!(Murmur3Hasher_x86_32, Murmur3_x86_32);

/// `MurmurHash3` 128-bit hash functions for 32-bit processors
pub struct Murmur3_x86_128 {}

impl FastHash for Murmur3_x86_128 {
    type Value = u128;
    type Seed = u32;

    #[inline]
    fn hash_with_seed<T: AsRef<[u8]>>(bytes: &T, seed: u32) -> u128 {
        unsafe {
            let mut hash = 0;

            ffi::MurmurHash3_x86_128(
                bytes.as_ref().as_ptr() as *const c_void,
                bytes.as_ref().len() as i32,
                seed,
                &mut hash as *mut u128 as *mut c_void,
            );

            hash
        }
    }
}

impl_hasher_ext!(Murmur3Hasher_x86_128, Murmur3_x86_128);

/// `MurmurHash3` 128-bit hash functions for 64-bit processors
pub struct Murmur3_x64_128 {}

impl FastHash for Murmur3_x64_128 {
    type Value = u128;
    type Seed = u32;

    #[inline]
    fn hash_with_seed<T: AsRef<[u8]>>(bytes: &T, seed: u32) -> u128 {
        unsafe {
            let mut hash = 0;

            ffi::MurmurHash3_x64_128(
                bytes.as_ref().as_ptr() as *const c_void,
                bytes.as_ref().len() as i32,
                seed,
                &mut hash as *mut u128 as *mut c_void,
            );

            hash
        }
    }
}

impl_hasher_ext!(Murmur3Hasher_x64_128, Murmur3_x64_128);

/// `MurmurHash3` 32-bit hash functions for a byte array.
#[inline]
pub fn hash32<T: AsRef<[u8]>>(v: &T) -> u32 {
    Murmur3_x86_32::hash(v)
}

/// `MurmurHash3` 32-bit hash functions for a byte array.
/// For convenience, a 32-bit seed is also hashed into the result.
#[inline]
pub fn hash32_with_seed<T: AsRef<[u8]>>(v: &T, seed: u32) -> u32 {
    Murmur3_x86_32::hash_with_seed(v, seed)
}

/// `MurmurHash3` 128-bit hash functions for a byte array.
#[inline]
pub fn hash128<T: AsRef<[u8]>>(v: &T) -> u128 {
    Murmur3_x64_128::hash(v)
}

/// `MurmurHash3` 128-bit hash functions for a byte array.
/// For convenience, a 32-bit seed is also hashed into the result.
#[inline]
pub fn hash128_with_seed<T: AsRef<[u8]>>(v: &T, seed: u32) -> u128 {
    Murmur3_x64_128::hash_with_seed(v, seed)
}

#[cfg(test)]
mod tests {
    use std::hash::Hasher;

    use super::*;
    use hasher::{FastHash, FastHasher, HasherExt};

    #[test]
    fn test_murmur3_x86_32() {
        assert_eq!(Murmur3_x86_32::hash(b"hello"), 613153351);
        assert_eq!(Murmur3_x86_32::hash_with_seed(b"hello", 123), 1573043710);
        assert_eq!(Murmur3_x86_32::hash(b"helloworld"), 2687965642);

        let mut h = Murmur3Hasher_x86_32::new();

        h.write(b"hello");
        assert_eq!(h.finish(), 613153351);

        h.write(b"world");
        assert_eq!(h.finish(), 2687965642);
    }

    #[test]
    fn test_murmur3_x86_128() {
        assert_eq!(
            Murmur3_x86_128::hash(b"hello"),
            205839232668418009241864179939306390688
        );
        assert_eq!(
            Murmur3_x86_128::hash_with_seed(b"hello", 123),
            39646137218600763345533167485429249129
        );
        assert_eq!(
            Murmur3_x86_128::hash(b"helloworld"),
            83212725615010754952022132390053357814
        );

        let mut h = Murmur3Hasher_x86_128::new();

        h.write(b"hello");
        assert_eq!(h.finish_ext(), 205839232668418009241864179939306390688);

        h.write(b"world");
        assert_eq!(h.finish_ext(), 83212725615010754952022132390053357814);
    }

    #[test]
    fn test_murmur3_x64_128() {
        assert_eq!(
            Murmur3_x64_128::hash(b"hello"),
            121118445609844952839898260755277781762
        );
        assert_eq!(
            Murmur3_x64_128::hash_with_seed(b"hello", 123),
            19243349499071459060235768594146641163
        );
        assert_eq!(
            Murmur3_x64_128::hash(b"helloworld"),
            216280293825344914020777844322685271162
        );

        let mut h = Murmur3Hasher_x64_128::new();

        h.write(b"hello");
        assert_eq!(h.finish_ext(), 121118445609844952839898260755277781762);

        h.write(b"world");
        assert_eq!(h.finish_ext(), 216280293825344914020777844322685271162);
    }
}
