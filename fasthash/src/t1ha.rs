//! Fast Positive Hash, aka "Позитивный Хэш"
//!
//! by Positive Technologies.
//!
//! https://github.com/leo-yuriev/t1ha
//!
//! Briefly, it is a 64-bit Hash Function:
//!
//! Created for 64-bit little-endian platforms, in predominantly for `x86_64`,
//! but without penalties could runs on any 64-bit CPU.
//! In most cases up to 15% faster than City64, xxHash, mum-hash,
//! metro-hash and all others which are not use specific hardware tricks.
//! Not suitable for cryptography.
//! Please see t1ha.c for implementation details.
//!
//! Acknowledgement:
//!
//! The t1ha was originally developed by Leonid Yuriev (Леонид Юрьев)
//! for The 1Hippeus project - zerocopy messaging in the spirit of Sparta!
//!
//! Requirements and Portability:
//!
//! t1ha designed for modern 64-bit architectures. But on the other hand,
//! t1ha doesn't uses any one tricks nor instructions specific to any particular architecture:
//! therefore t1ha could be used on any CPU for which GCC provides support 64-bit arithmetics.
//! but unfortunately t1ha could be dramatically slowly on architectures
//! without native 64-bit operations.
//! This implementation of t1ha requires modern GNU C compatible compiler,
//! includes Clang/LLVM; or MSVC++ 14.0 (Visual Studio 2015).
//!
//! # Example
//!
//! ```
//! use std::hash::{Hash, Hasher};
//!
//! use fasthash::{t1ha, T1haHasher};
//!
//! fn hash<T: Hash>(t: &T) -> u64 {
//!     let mut s: T1haHasher = Default::default();
//!     t.hash(&mut s);
//!     s.finish()
//! }
//!
//! let h = t1ha::hash64(b"hello world\xff");
//!
//! assert_eq!(h, hash(&"hello world"));
//! ```
//!
use std::os::raw::c_void;

use ffi;

use hasher::{FastHash, FastHasher};

/// The at-once variant with 64-bit result
pub struct T1ha2_64 {}

impl FastHash for T1ha2_64 {
    type Value = u64;
    type Seed = u64;

    #[inline]
    fn hash_with_seed<T: AsRef<[u8]>>(bytes: &T, seed: u64) -> u64 {
        unsafe {
            ffi::t1ha2_atonce(
                bytes.as_ref().as_ptr() as *const c_void,
                bytes.as_ref().len(),
                seed,
            )
        }
    }
}

impl_hasher!(T1ha2Hasher64, T1ha2_64);

/// The at-once variant with 64-bit result
pub struct T1ha2_128 {}

impl FastHash for T1ha2_128 {
    type Value = u128;
    type Seed = u64;

    #[inline]
    fn hash_with_seed<T: AsRef<[u8]>>(bytes: &T, seed: u64) -> u128 {
        let mut hi = 0;

        let lo = unsafe {
            ffi::t1ha2_atonce128(
                &mut hi,
                bytes.as_ref().as_ptr() as *const c_void,
                bytes.as_ref().len(),
                seed,
            )
        };

        u128::from(hi).wrapping_shl(64) + u128::from(lo)
    }
}

impl_hasher_ext!(T1ha2Hasher128, T1ha2_128);

/// `T1Hash` 64-bit hash functions for 64-bit little-endian platforms.
pub struct T1ha1_64Le {}

impl FastHash for T1ha1_64Le {
    type Value = u64;
    type Seed = u64;

    #[inline]
    fn hash_with_seed<T: AsRef<[u8]>>(bytes: &T, seed: u64) -> u64 {
        unsafe {
            ffi::t1ha1_le(
                bytes.as_ref().as_ptr() as *const c_void,
                bytes.as_ref().len(),
                seed,
            )
        }
    }
}

impl_hasher!(T1ha1Hasher64Le, T1ha1_64Le);

/// `T1Hash` 64-bit hash functions for 64-bit big-endian platforms.
pub struct T1ha1_64Be {}

impl FastHash for T1ha1_64Be {
    type Value = u64;
    type Seed = u64;

    #[inline]
    fn hash_with_seed<T: AsRef<[u8]>>(bytes: &T, seed: u64) -> u64 {
        unsafe {
            ffi::t1ha1_be(
                bytes.as_ref().as_ptr() as *const c_void,
                bytes.as_ref().len(),
                seed,
            )
        }
    }
}

impl_hasher!(T1ha1Hasher64Be, T1ha1_64Be);

/// `T1Hash` 32-bit hash functions for 32-bit little-endian platforms.
pub struct T1ha0_32Le {}

impl FastHash for T1ha0_32Le {
    type Value = u64;
    type Seed = u64;

    #[inline]
    fn hash_with_seed<T: AsRef<[u8]>>(bytes: &T, seed: u64) -> u64 {
        unsafe {
            ffi::t1ha0_32le(
                bytes.as_ref().as_ptr() as *const c_void,
                bytes.as_ref().len(),
                seed,
            )
        }
    }
}

impl_hasher!(T1ha0Hasher32Le, T1ha0_32Le);

/// `T1Hash` 32-bit hash functions for 32-bit big-endian platforms.
pub struct T1ha0_32Be {}

impl FastHash for T1ha0_32Be {
    type Value = u64;
    type Seed = u64;

    #[inline]
    fn hash_with_seed<T: AsRef<[u8]>>(bytes: &T, seed: u64) -> u64 {
        unsafe {
            ffi::t1ha0_32be(
                bytes.as_ref().as_ptr() as *const c_void,
                bytes.as_ref().len(),
                seed,
            )
        }
    }
}

impl_hasher!(T1ha0Hasher32Be, T1ha0_32Be);

/// `T1Hash` 64-bit hash functions.
pub struct T1ha0_64 {}

impl FastHash for T1ha0_64 {
    type Value = u64;
    type Seed = u64;

    #[inline]
    fn hash_with_seed<T: AsRef<[u8]>>(bytes: &T, seed: u64) -> u64 {
        unsafe {
            ffi::t1ha0_64(
                bytes.as_ref().as_ptr() as *const c_void,
                bytes.as_ref().len(),
                seed,
            )
        }
    }
}

impl_hasher!(T1ha0Hasher64, T1ha0_64);

/// `T1Hash` 32-bit hash functions for a byte array.
#[inline]
pub fn hash32<T: AsRef<[u8]>>(v: &T) -> u64 {
    T1ha0_32Le::hash(v)
}

/// `T1Hash` 32-bit hash function for a byte array.
/// For convenience, a 32-bit seed is also hashed into the result.
#[inline]
pub fn hash32_with_seed<T: AsRef<[u8]>>(v: &T, seed: u64) -> u64 {
    T1ha0_32Le::hash_with_seed(v, seed)
}

/// `T1Hash` 64-bit hash functions for a byte array.
#[inline]
pub fn hash64<T: AsRef<[u8]>>(v: &T) -> u64 {
    T1ha2_64::hash(v)
}

/// `T1Hash` 64-bit hash function for a byte array.
/// For convenience, a 64-bit seed is also hashed into the result.
#[inline]
pub fn hash64_with_seed<T: AsRef<[u8]>>(v: &T, seed: u64) -> u64 {
    T1ha2_64::hash_with_seed(v, seed)
}

#[cfg(test)]
mod tests {
    use std::hash::Hasher;

    use super::*;
    use hasher::{FastHash, FastHasher, HasherExt};

    #[test]
    fn test_t1ha0_32_le() {
        assert_eq!(T1ha0_32Le::hash(b"hello"), 11895187617783960984);
        assert_eq!(
            T1ha0_32Le::hash_with_seed(b"hello", 123),
            13558580374828082753
        );
        assert_eq!(T1ha0_32Le::hash(b"helloworld"), 8503803101881974809);

        let mut h = T1ha0Hasher32Le::new();

        h.write(b"hello");
        assert_eq!(h.finish(), 11895187617783960984);

        h.write(b"world");
        assert_eq!(h.finish(), 8503803101881974809);
    }

    #[test]
    fn test_t1ha0_32_be() {
        assert_eq!(T1ha0_32Be::hash(b"hello"), 14067757663807345410);
        assert_eq!(
            T1ha0_32Be::hash_with_seed(b"hello", 123),
            8517748423110957049
        );
        assert_eq!(T1ha0_32Be::hash(b"helloworld"), 3041108372210049528);

        let mut h = T1ha0Hasher32Be::new();

        h.write(b"hello");
        assert_eq!(h.finish(), 14067757663807345410);

        h.write(b"world");
        assert_eq!(h.finish(), 3041108372210049528);
    }

    #[test]
    fn test_t1ha0_64() {
        assert_eq!(T1ha0_64::hash(b"hello"), 3053206065578472372);
        assert_eq!(
            T1ha0_64::hash_with_seed(b"hello", 123),
            14202271713409552392
        );
        assert_eq!(T1ha0_64::hash(b"helloworld"), 15302361616348747620);

        let mut h = T1ha0Hasher64::new();

        h.write(b"hello");
        assert_eq!(h.finish(), 3053206065578472372);

        h.write(b"world");
        assert_eq!(h.finish(), 15302361616348747620);
    }

    #[test]
    fn test_t1ha1_64le() {
        assert_eq!(T1ha1_64Le::hash(b"hello"), 12810198970222070563);
        assert_eq!(
            T1ha1_64Le::hash_with_seed(b"hello", 123),
            7105133355958514544
        );
        assert_eq!(T1ha1_64Le::hash(b"helloworld"), 16997942636322422782);

        let mut h = T1ha1Hasher64Le::new();

        h.write(b"hello");
        assert_eq!(h.finish(), 12810198970222070563);

        h.write(b"world");
        assert_eq!(h.finish(), 16997942636322422782);
    }

    #[test]
    fn test_t1ha1_64be() {
        assert_eq!(T1ha1_64Be::hash(b"hello"), 14880640220959195744);
        assert_eq!(
            T1ha1_64Be::hash_with_seed(b"hello", 123),
            1421069625385545216
        );
        assert_eq!(T1ha1_64Be::hash(b"helloworld"), 15825971635414726702);

        let mut h = T1ha1Hasher64Be::new();

        h.write(b"hello");
        assert_eq!(h.finish(), 14880640220959195744);

        h.write(b"world");
        assert_eq!(h.finish(), 15825971635414726702);
    }

    #[test]
    fn test_t1ha2_64() {
        assert_eq!(T1ha2_64::hash(b"hello"), 3053206065578472372);
        assert_eq!(
            T1ha2_64::hash_with_seed(b"hello", 123),
            14202271713409552392
        );
        assert_eq!(T1ha2_64::hash(b"helloworld"), 15302361616348747620);

        let mut h = T1ha2Hasher64::new();

        h.write(b"hello");
        assert_eq!(h.finish(), 3053206065578472372);

        h.write(b"world");
        assert_eq!(h.finish(), 15302361616348747620);
    }

    #[test]
    fn test_t1ha2_128() {
        assert_eq!(
            T1ha2_128::hash(b"hello"),
            181522150951767732353014146495581994137
        );
        assert_eq!(
            T1ha2_128::hash_with_seed(b"hello", 123),
            116090820602478335969970261629923046941
        );
        assert_eq!(
            T1ha2_128::hash(b"helloworld"),
            315212713565720527393405448145758944961
        );

        let mut h = T1ha2Hasher128::new();

        h.write(b"hello");
        assert_eq!(h.finish_ext(), 181522150951767732353014146495581994137);

        h.write(b"world");
        assert_eq!(h.finish_ext(), 315212713565720527393405448145758944961);
    }
}
