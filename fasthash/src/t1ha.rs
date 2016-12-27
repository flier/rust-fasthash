//! Fast Positive Hash, aka "Позитивный Хэш"
//!
//! by Positive Technologies.
//!
//! https://github.com/leo-yuriev/t1ha
//!
//! Briefly, it is a 64-bit Hash Function:
//!
//! Created for 64-bit little-endian platforms, in predominantly for x86_64,
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
//!     let mut s = T1haHasher::new();
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

use hasher::FastHash;

/// T1ha 64-bit hash functions for 64-bit little-endian platforms.
pub struct T1ha64Le {}

impl FastHash for T1ha64Le {
    type Value = u64;
    type Seed = u64;

    #[inline]
    fn hash_with_seed<T: AsRef<[u8]>>(bytes: &T, seed: u64) -> u64 {
        unsafe {
            ffi::t1ha(bytes.as_ref().as_ptr() as *const c_void,
                      bytes.as_ref().len(),
                      seed)
        }
    }
}

impl_hasher!(T1ha64LeHasher, T1ha64Le);

/// T1ha 64-bit hash functions for 64-bit big-endian platforms.
pub struct T1ha64Be {}

impl FastHash for T1ha64Be {
    type Value = u64;
    type Seed = u64;

    #[inline]
    fn hash_with_seed<T: AsRef<[u8]>>(bytes: &T, seed: u64) -> u64 {
        unsafe {
            ffi::t1ha_64be(bytes.as_ref().as_ptr() as *const c_void,
                           bytes.as_ref().len(),
                           seed)
        }
    }
}

impl_hasher!(T1ha64BeHasher, T1ha64Be);

/// T1ha 32-bit hash functions for 32-bit little-endian platforms.
pub struct T1ha32Le {}

impl FastHash for T1ha32Le {
    type Value = u64;
    type Seed = u64;

    #[inline]
    fn hash_with_seed<T: AsRef<[u8]>>(bytes: &T, seed: u64) -> u64 {
        unsafe {
            ffi::t1ha_32le(bytes.as_ref().as_ptr() as *const c_void,
                           bytes.as_ref().len(),
                           seed)
        }
    }
}

impl_hasher!(T1ha32LeHasher, T1ha32Le);

/// T1ha 32-bit hash functions for 32-bit big-endian platforms.
pub struct T1ha32Be {}

impl FastHash for T1ha32Be {
    type Value = u64;
    type Seed = u64;

    #[inline]
    fn hash_with_seed<T: AsRef<[u8]>>(bytes: &T, seed: u64) -> u64 {
        unsafe {
            ffi::t1ha_32be(bytes.as_ref().as_ptr() as *const c_void,
                           bytes.as_ref().len(),
                           seed)
        }
    }
}

impl_hasher!(T1ha32BeHasher, T1ha32Be);

/// T1ha 64-bit hash functions using HW CRC instruction for 64-bit little-endian platforms.
#[cfg(feature = "sse42")]
pub struct T1ha64Crc {}

#[cfg(feature = "sse42")]
impl FastHash for T1ha64Crc {
    type Value = u64;
    type Seed = u64;

    #[inline]
    fn hash_with_seed<T: AsRef<[u8]>>(bytes: &T, seed: u64) -> u64 {
        unsafe {
            ffi::t1ha_ia32crc(bytes.as_ref().as_ptr() as *const c_void,
                              bytes.as_ref().len(),
                              seed)
        }
    }
}

#[cfg(feature = "sse42")]
impl_hasher!(T1ha64CrcHasher, T1ha64Crc);

/// T1Hash 32-bit hash functions for a byte array.
#[inline]
pub fn hash32<T: AsRef<[u8]>>(v: &T) -> u64 {
    T1ha32Le::hash(v)
}

/// T1Hash 32-bit hash function for a byte array.
/// For convenience, a 32-bit seed is also hashed into the result.
#[inline]
pub fn hash32_with_seed<T: AsRef<[u8]>>(v: &T, seed: u64) -> u64 {
    T1ha32Le::hash_with_seed(v, seed)
}

/// T1Hash 64-bit hash functions for a byte array.
#[cfg(not(feature = "sse42"))]
#[inline]
pub fn hash64<T: AsRef<[u8]>>(v: &T) -> u64 {
    T1ha64Le::hash(v)
}

/// T1Hash 64-bit hash function for a byte array.
/// For convenience, a 64-bit seed is also hashed into the result.
#[cfg(not(feature = "sse42"))]
#[inline]
pub fn hash64_with_seed<T: AsRef<[u8]>>(v: &T, seed: u64) -> u64 {
    T1ha64Le::hash_with_seed(v, seed)
}

/// T1Hash 64-bit hash function for a byte array using HW CRC instruction.
/// That require SSE4.2 instructions to be available.
#[cfg(any(feature = "doc", feature = "sse42"))]
#[inline]
pub fn hash64<T: AsRef<[u8]>>(v: &T) -> u64 {
    T1ha64Crc::hash(v)
}

/// T1Hash 64-bit hash function for a byte array using HW CRC instruction.
/// That require SSE4.2 instructions to be available.
/// For convenience, a 64-bit seed is also hashed into the result.
#[cfg(any(feature = "doc", feature = "sse42"))]
#[inline]
pub fn hash64_with_seed<T: AsRef<[u8]>>(v: &T, seed: u64) -> u64 {
    T1ha64Crc::hash_with_seed(v, seed)
}

#[cfg(test)]
mod tests {
    use std::hash::Hasher;

    use hasher::FastHash;
    use super::*;

    #[test]
    fn test_t1ha_32_le() {
        assert_eq!(T1ha32Le::hash(b"hello"), 1026677640742993727);
        assert_eq!(T1ha32Le::hash_with_seed(b"hello", 123), 9601366527779802491);
        assert_eq!(T1ha32Le::hash(b"helloworld"), 15938092988918204794);

        let mut h = T1ha32LeHasher::new();

        h.write(b"hello");
        assert_eq!(h.finish(), 1026677640742993727);

        h.write(b"world");
        assert_eq!(h.finish(), 15938092988918204794);
    }

    #[test]
    fn test_t1ha_32_be() {
        assert_eq!(T1ha32Be::hash(b"hello"), 14968514543474807977);
        assert_eq!(T1ha32Be::hash_with_seed(b"hello", 123),
                   18258318775703579484);
        assert_eq!(T1ha32Be::hash(b"helloworld"), 6104456647282750739);

        let mut h = T1ha32BeHasher::new();

        h.write(b"hello");
        assert_eq!(h.finish(), 14968514543474807977);

        h.write(b"world");
        assert_eq!(h.finish(), 6104456647282750739);
    }

    #[test]
    fn test_t1ha_64_le() {
        assert_eq!(T1ha64Le::hash(b"hello"), 12810198970222070563);
        assert_eq!(T1ha64Le::hash_with_seed(b"hello", 123), 7105133355958514544);
        assert_eq!(T1ha64Le::hash(b"helloworld"), 16997942636322422782);

        let mut h = T1ha64LeHasher::new();

        h.write(b"hello");
        assert_eq!(h.finish(), 12810198970222070563);

        h.write(b"world");
        assert_eq!(h.finish(), 16997942636322422782);
    }

    #[test]
    fn test_t1ha_64_be() {
        assert_eq!(T1ha64Be::hash(b"hello"), 14880640220959195744);
        assert_eq!(T1ha64Be::hash_with_seed(b"hello", 123), 1421069625385545216);
        assert_eq!(T1ha64Be::hash(b"helloworld"), 15825971635414726702);

        let mut h = T1ha64BeHasher::new();

        h.write(b"hello");
        assert_eq!(h.finish(), 14880640220959195744);

        h.write(b"world");
        assert_eq!(h.finish(), 15825971635414726702);
    }

    #[test]
    fn test_t1ha_64_crc() {
        assert_eq!(T1ha64Crc::hash(b"hello"), 12810198970222070563);
        assert_eq!(T1ha64Crc::hash_with_seed(b"hello", 123),
                   7105133355958514544);
        assert_eq!(T1ha64Crc::hash(b"helloworld"), 16997942636322422782);

        let mut h = T1ha64CrcHasher::new();

        h.write(b"hello");
        assert_eq!(h.finish(), 12810198970222070563);

        h.write(b"world");
        assert_eq!(h.finish(), 16997942636322422782);
    }
}
