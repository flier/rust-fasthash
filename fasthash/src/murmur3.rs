//! Murmur, a suite of non-cryptographic hash functions that was used for hash-based lookups.
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
//!     let mut s = Murmur3Hasher::new();
//!     t.hash(&mut s);
//!     s.finish()
//! }
//!
//! let h = murmur3::hash128(b"hello world\xff").low64();
//!
//! assert_eq!(h, hash(&"hello world"));
//! ```
//!
#![allow(non_camel_case_types)]
use std::mem;
use std::os::raw::c_void;

use extprim::u128::u128;

use ffi;

use hasher::FastHash;

/// MurmurHash3 32-bit hash functions
pub struct Murmur3_x86_32 {}

impl FastHash for Murmur3_x86_32 {
    type Value = u32;
    type Seed = u32;

    #[inline]
    fn hash_with_seed<T: AsRef<[u8]>>(bytes: &T, seed: u32) -> u32 {
        unsafe {
            let mut hash = 0_u32;

            ffi::MurmurHash3_x86_32(bytes.as_ref().as_ptr() as *const c_void,
                                    bytes.as_ref().len() as i32,
                                    seed,
                                    mem::transmute(&mut hash));

            hash
        }
    }
}

impl_hasher!(Murmur3Hasher_x86_32, Murmur3_x86_32);

/// MurmurHash3 128-bit hash functions for 32-bit processors
pub struct Murmur3_x86_128 {}

impl FastHash for Murmur3_x86_128 {
    type Value = u128;
    type Seed = u32;

    #[inline]
    fn hash_with_seed<T: AsRef<[u8]>>(bytes: &T, seed: u32) -> u128 {
        unsafe {
            let mut hash = u128::zero();

            ffi::MurmurHash3_x86_128(bytes.as_ref().as_ptr() as *const c_void,
                                     bytes.as_ref().len() as i32,
                                     seed,
                                     mem::transmute(&mut hash));

            hash
        }
    }
}

impl_hasher_ext!(Murmur3Hasher_x86_128, Murmur3_x86_128);

/// MurmurHash3 128-bit hash functions for 64-bit processors
pub struct Murmur3_x64_128 {}

impl FastHash for Murmur3_x64_128 {
    type Value = u128;
    type Seed = u32;

    #[inline]
    fn hash_with_seed<T: AsRef<[u8]>>(bytes: &T, seed: u32) -> u128 {
        unsafe {
            let mut hash = u128::zero();

            ffi::MurmurHash3_x64_128(bytes.as_ref().as_ptr() as *const c_void,
                                     bytes.as_ref().len() as i32,
                                     seed,
                                     mem::transmute(&mut hash));

            hash
        }
    }
}

impl_hasher_ext!(Murmur3Hasher_x64_128, Murmur3_x64_128);

/// MurmurHash3 32-bit hash functions for a byte array.
#[inline]
pub fn hash32<T: AsRef<[u8]>>(v: &T) -> u32 {
    Murmur3_x86_32::hash(v)
}

/// MurmurHash3 32-bit hash functions for a byte array.
/// For convenience, a 32-bit seed is also hashed into the result.
#[inline]
pub fn hash32_with_seed<T: AsRef<[u8]>>(v: &T, seed: u32) -> u32 {
    Murmur3_x86_32::hash_with_seed(v, seed)
}

/// MurmurHash3 128-bit hash functions for a byte array.
#[inline]
pub fn hash128<T: AsRef<[u8]>>(v: &T) -> u128 {
    Murmur3_x64_128::hash(v)
}

/// MurmurHash3 128-bit hash functions for a byte array.
/// For convenience, a 32-bit seed is also hashed into the result.
#[inline]
pub fn hash128_with_seed<T: AsRef<[u8]>>(v: &T, seed: u32) -> u128 {
    Murmur3_x64_128::hash_with_seed(v, seed)
}


#[cfg(test)]
mod tests {
    use std::hash::Hasher;

    use extprim::u128::u128;

    use hasher::{FastHash, HasherExt};
    use super::*;

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
        assert_eq!(Murmur3_x86_128::hash(b"hello"),
                   u128::from_parts(11158567162092401078, 15821672119091348640));
        assert_eq!(Murmur3_x86_128::hash_with_seed(b"hello", 123),
                   u128::from_parts(2149221405153268091, 10130600740778964073));
        assert_eq!(Murmur3_x86_128::hash(b"helloworld"),
                   u128::from_parts(4510970894511742178, 13166749202678098166));

        let mut h = Murmur3Hasher_x86_128::new();

        h.write(b"hello");
        assert_eq!(h.finish_ext(),
                   u128::from_parts(11158567162092401078, 15821672119091348640));

        h.write(b"world");
        assert_eq!(h.finish_ext(),
                   u128::from_parts(4510970894511742178, 13166749202678098166));
    }

    #[test]
    fn test_murmur3_x64_128() {
        assert_eq!(Murmur3_x64_128::hash(b"hello"),
                   u128::from_parts(6565844092913065241, 14688674573012802306));
        assert_eq!(Murmur3_x64_128::hash_with_seed(b"hello", 123),
                   u128::from_parts(1043184066639555970, 3016954156110693643));
        assert_eq!(Murmur3_x64_128::hash(b"helloworld"),
                   u128::from_parts(11724578221562109303, 10256632503372987514));

        let mut h = Murmur3Hasher_x64_128::new();

        h.write(b"hello");
        assert_eq!(h.finish_ext(),
                   u128::from_parts(6565844092913065241, 14688674573012802306));

        h.write(b"world");
        assert_eq!(h.finish_ext(),
                   u128::from_parts(11724578221562109303, 10256632503372987514));
    }
}
