//! CityHash, a family of hash functions for strings.
//!
//! by Geoff Pike and Jyrki Alakuijala
//!
//! https://github.com/google/cityhash
//!
//! Introduction
//! ============
//! CityHash provides hash functions for strings.  The functions mix the
//! input bits thoroughly but are not suitable for cryptography.  See
//! "Hash Quality," below, for details on how CityHash was tested and so on.
//!
//! We provide reference implementations in C++, with a friendly MIT license.
//!
//! `CityHash32` returns a 32-bit hash.
//!
//! `CityHash64` and similar return a 64-bit hash.
//!
//! `CityHash128` and similar return a 128-bit hash and are tuned for
//! strings of at least a few hundred bytes.  Depending on your compiler
//! and hardware, it's likely faster than `CityHash64` on sufficiently long
//! strings.  It's slower than necessary on shorter strings, but we expect
//! that case to be relatively unimportant.
//!
//! `CityHashCrc128` and similar are variants of `CityHash128` that depend
//! on _mm_crc32_u64(), an intrinsic that compiles to a CRC32 instruction
//! on some CPUs.  However, none of the functions we provide are CRCs.
//!
//! `CityHashCrc256` is a variant of `CityHashCrc128` that also depends
//! on _mm_crc32_u64().  It returns a 256-bit hash.
//!
//! All members of the CityHash family were designed with heavy reliance
//! on previous work by Austin Appleby, Bob Jenkins, and others.
//! For example, CityHash32 has many similarities with Murmur3a.
//!
//! Performance on long strings: 64-bit CPUs
//! ========================================
//!
//! We are most excited by the performance of `CityHash64` and its variants on
//! short strings, but long strings are interesting as well.
//!
//! CityHash is intended to be fast, under the constraint that it hash very
//! well.  For CPUs with the CRC32 instruction, CRC is speedy, but CRC wasn't
//! designed as a hash function and shouldn't be used as one.  `CityHashCrc128`
//! is not a CRC, but it uses the CRC32 machinery.
//!
//! On a single core of a 2.67GHz Intel Xeon X5550, `CityHashCrc256` peaks at about
//! 5 to 5.5 bytes/cycle.  The other CityHashCrc functions are wrappers around
//! `CityHashCrc256` and should have similar performance on long strings.
//! (`CityHashCrc256` in v1.0.3 was even faster, but we decided it wasn't as thorough
//! as it should be.)  CityHash128 peaks at about 4.3 bytes/cycle.  The fastest
//! Murmur variant on that hardware, Murmur3F, peaks at about 2.4 bytes/cycle.
//! We expect the peak speed of CityHash128 to dominate CityHash64, which is
//! aimed more toward short strings or use in hash tables.
//!
//! For long strings, a new function by Bob Jenkins, SpookyHash, is just
//! slightly slower than CityHash128 on Intel x86-64 CPUs, but noticeably
//! faster on AMD x86-64 CPUs.  For hashing long strings on AMD CPUs
//! and/or CPUs without the CRC instruction, SpookyHash may be just as
//! good or better than any of the CityHash variants.
//!
//! Performance on short strings: 64-bit CPUs
//! =========================================
//!
//! For short strings, e.g., most hash table keys, CityHash64 is faster than
//! CityHash128, and probably faster than all the aforementioned functions,
//! depending on the mix of string lengths.  Here are a few results from that
//! same hardware, where we (unrealistically) tested a single string length over
//! and over again:
//!
//! Hash              Results
//! ------------------------------------------------------------------------------
//! CityHash64 v1.0.3 7ns for 1 byte, or 6ns for 8 bytes, or 9ns for 64 bytes
//! Murmur2 (64-bit)  6ns for 1 byte, or 6ns for 8 bytes, or 15ns for 64 bytes
//! Murmur3F          14ns for 1 byte, or 15ns for 8 bytes, or 23ns for 64 bytes
//!
//! We don't have CityHash64 benchmarks results for v1.1, but we expect the
//! numbers to be similar.
//!
//! Performance: 32-bit CPUs
//! ========================
//!
//! CityHash32 is the newest variant of CityHash.  It is intended for
//! 32-bit hardware in general but has been mostly tested on x86.  Our benchmarks
//! suggest that Murmur3 is the nearest competitor to CityHash32 on x86.
//! We don't know of anything faster that has comparable quality.  The speed rankings
//! in our testing: CityHash32 > Murmur3f > Murmur3a (for long strings), and
//! CityHash32 > Murmur3a > Murmur3f (for short strings).
//!
//! Limitations
//! ===========
//!
//! 1) CityHash32 is intended for little-endian 32-bit code, and everything else in
//! the current version of CityHash is intended for little-endian 64-bit CPUs.
//!
//! All functions that don't use the CRC32 instruction should work in
//! little-endian 32-bit or 64-bit code.  CityHash should work on big-endian CPUs
//! as well, but we haven't tested that very thoroughly yet.
//!
//! 2) CityHash is fairly complex.  As a result of its complexity, it may not
//! perform as expected on some compilers.  For example, preliminary reports
//! suggest that some Microsoft compilers compile CityHash to assembly that's
//! 10-20% slower than it could be.
//!
//! # Example
//!
//! ```
//! use std::hash::{Hash, Hasher};
//!
//! use fasthash::{city, CityHasher};
//!
//! fn hash<T: Hash>(t: &T) -> u64 {
//!     let mut s: CityHasher = Default::default();
//!     t.hash(&mut s);
//!     s.finish()
//! }
//!
//! let h = city::hash64(b"hello world\xff");
//!
//! assert_eq!(h, hash(&"hello world"));
//! ```
//!
use std::mem;

use extprim::u128::u128;

use ffi;

use hasher::{FastHash, FastHasher};

/// CityHash 32-bit hash functions
pub struct CityHash32 {}

impl FastHash for CityHash32 {
    type Value = u32;
    type Seed = u32;

    #[inline]
    fn hash_with_seed<T: AsRef<[u8]>>(bytes: &T, seed: u32) -> u32 {
        unsafe {
            ffi::CityHash32WithSeed(bytes.as_ref().as_ptr() as *const i8,
                                    bytes.as_ref().len(),
                                    seed)
        }
    }
}

impl_hasher!(CityHasher32, CityHash32);

/// CityHash 64-bit hash functions
pub struct CityHash64 {}

impl CityHash64 {
    #[inline]
    pub fn hash_with_seeds<T: AsRef<[u8]>>(bytes: &T, seed0: u64, seed1: u64) -> u64 {
        unsafe {
            ffi::CityHash64WithSeeds(bytes.as_ref().as_ptr() as *const i8,
                                     bytes.as_ref().len(),
                                     seed0,
                                     seed1)
        }
    }
}

impl FastHash for CityHash64 {
    type Value = u64;
    type Seed = u64;

    #[inline]
    fn hash<T: AsRef<[u8]>>(bytes: &T) -> u64 {
        unsafe { ffi::CityHash64(bytes.as_ref().as_ptr() as *const i8, bytes.as_ref().len()) }
    }

    #[inline]
    fn hash_with_seed<T: AsRef<[u8]>>(bytes: &T, seed: u64) -> u64 {
        unsafe {
            ffi::CityHash64WithSeed(bytes.as_ref().as_ptr() as *const i8,
                                    bytes.as_ref().len(),
                                    seed)
        }
    }
}

impl_hasher!(CityHasher64, CityHash64);

/// CityHash 128-bit hash functions
pub struct CityHash128 {}

impl FastHash for CityHash128 {
    type Value = u128;
    type Seed = u128;

    #[inline]
    fn hash<T: AsRef<[u8]>>(bytes: &T) -> u128 {
        unsafe {
            mem::transmute(ffi::CityHash128(bytes.as_ref().as_ptr() as *const i8,
                                            bytes.as_ref().len()))
        }
    }

    #[inline]
    fn hash_with_seed<T: AsRef<[u8]>>(bytes: &T, seed: u128) -> u128 {
        unsafe {
            mem::transmute(ffi::CityHash128WithSeed(bytes.as_ref().as_ptr() as *const i8,
                                                    bytes.as_ref().len(),
                                                    mem::transmute(seed)))
        }
    }
}

impl_hasher_ext!(CityHasher128, CityHash128);

/// CityHash 128-bit hash functions using HW CRC instruction.
#[cfg(feature = "sse42")]
pub struct CityHashCrc128 {}

#[cfg(feature = "sse42")]
impl FastHash for CityHashCrc128 {
    type Value = u128;
    type Seed = u128;

    #[inline]
    fn hash<T: AsRef<[u8]>>(bytes: &T) -> u128 {
        unsafe {
            mem::transmute(ffi::CityHashCrc128(bytes.as_ref().as_ptr() as *const i8,
                                               bytes.as_ref().len()))
        }
    }

    #[inline]
    fn hash_with_seed<T: AsRef<[u8]>>(bytes: &T, seed: u128) -> u128 {
        unsafe {
            mem::transmute(ffi::CityHashCrc128WithSeed(bytes.as_ref().as_ptr() as *const i8,
                                                       bytes.as_ref().len(),
                                                       mem::transmute(seed)))
        }
    }
}

#[cfg(feature = "sse42")]
impl_hasher_ext!(CityHasherCrc128, CityHashCrc128);

/// CityHash 32-bit hash functions for a byte array.
#[inline]
pub fn hash32<T: AsRef<[u8]>>(v: &T) -> u32 {
    CityHash32::hash(v)
}

/// CityHash 32-bit hash function for a byte array.
/// For convenience, a 32-bit seed is also hashed into the result.
#[inline]
pub fn hash32_with_seed<T: AsRef<[u8]>>(v: &T, seed: u32) -> u32 {
    CityHash32::hash_with_seed(v, seed)
}

/// CityHash 64-bit hash functions for a byte array.
#[inline]
pub fn hash64<T: AsRef<[u8]>>(v: &T) -> u64 {
    CityHash64::hash(v)
}

/// CityHash 64-bit hash function for a byte array.
/// For convenience, a 64-bit seed is also hashed into the result.
#[inline]
pub fn hash64_with_seed<T: AsRef<[u8]>>(v: &T, seed: u64) -> u64 {
    CityHash64::hash_with_seed(v, seed)
}

/// CityHash 64-bit hash function for a byte array.
/// For convenience, two seeds are also hashed into the result.
#[inline]
pub fn hash64_with_seeds<T: AsRef<[u8]>>(v: &T, seed0: u64, seed1: u64) -> u64 {
    CityHash64::hash_with_seeds(v, seed0, seed1)
}

/// CityHash 128-bit hash function for a byte array.
#[cfg(not(feature = "sse42"))]
#[inline]
pub fn hash128<T: AsRef<[u8]>>(v: &T) -> u128 {
    CityHash128::hash(v)
}

/// CityHash 128-bit hash function for a byte array.
/// For convenience, a 128-bit seed is also hashed into the result.
#[cfg(not(feature = "sse42"))]
#[inline]
pub fn hash128_with_seed<T: AsRef<[u8]>>(v: &T, seed: u128) -> u128 {
    CityHash128::hash_with_seed(v, seed)
}

/// CityHash 128-bit hash function for a byte array using HW CRC instruction.
/// That require SSE4.2 instructions to be available.
#[cfg(any(feature = "doc", feature = "sse42"))]
#[inline]
pub fn hash128<T: AsRef<[u8]>>(v: &T) -> u128 {
    CityHashCrc128::hash(v)
}

/// CityHash 128-bit hash function for a byte array using HW CRC instruction.
/// For convenience, a 128-bit seed is also hashed into the result.
/// That require SSE4.2 instructions to be available.
#[cfg(any(feature = "doc", feature = "sse42"))]
#[inline]
pub fn hash128_with_seed<T: AsRef<[u8]>>(v: &T, seed: u128) -> u128 {
    CityHashCrc128::hash_with_seed(v, seed)
}

#[cfg(test)]
mod tests {
    use std::hash::Hasher;

    use extprim::u128::u128;

    use hasher::{FastHash, FastHasher, HasherExt};
    use super::*;

    #[test]
    fn test_cityhash32() {
        assert_eq!(CityHash32::hash(b"hello"), 2039911270);
        assert_eq!(CityHash32::hash_with_seed(b"hello", 123), 3366460263);
        assert_eq!(CityHash32::hash(b"helloworld"), 4037657980);

        let mut h = CityHasher32::new();

        h.write(b"hello");
        assert_eq!(h.finish(), 2039911270);

        h.write(b"world");
        assert_eq!(h.finish(), 4037657980);
    }

    #[test]
    fn test_cityhash64() {
        assert_eq!(CityHash64::hash(b"hello"), 2578220239953316063);
        assert_eq!(CityHash64::hash_with_seed(b"hello", 123),
                   11802079543206271427);
        assert_eq!(CityHash64::hash_with_seeds(b"hello", 123, 456),
                   13699505624668345539);
        assert_eq!(CityHash64::hash(b"helloworld"), 16622738483577116029);

        let mut h = CityHasher64::new();

        h.write(b"hello");
        assert_eq!(h.finish(), 2578220239953316063);

        h.write(b"world");
        assert_eq!(h.finish(), 16622738483577116029);
    }

    #[test]
    fn test_cityhash128() {
        assert_eq!(CityHash128::hash(b"hello"),
                   u128::from_parts(17404193039403234796, 13523890104784088047));
        assert_eq!(CityHash128::hash_with_seed(b"hello", u128::new(123)),
                   u128::from_parts(10365139276371188890, 13112352013023211873));
        assert_eq!(CityHash128::hash(b"helloworld"),
                   u128::from_parts(7450567370945444069, 787832070172609324));

        let mut h = CityHasher128::new();

        h.write(b"hello");
        assert_eq!(h.finish_ext(),
                   u128::from_parts(17404193039403234796, 13523890104784088047));

        h.write(b"world");
        assert_eq!(h.finish_ext(),
                   u128::from_parts(7450567370945444069, 787832070172609324));
    }

    #[cfg(feature = "sse42")]
    #[test]
    fn test_cityhash128crc() {
        assert_eq!(CityHashCrc128::hash(b"hello"),
                   u128::from_parts(17404193039403234796, 13523890104784088047));
        assert_eq!(CityHashCrc128::hash_with_seed(b"hello", u128::new(123)),
                   u128::from_parts(10365139276371188890, 13112352013023211873));
        assert_eq!(CityHashCrc128::hash(b"helloworld"),
                   u128::from_parts(7450567370945444069, 787832070172609324));

        let mut h = CityHasherCrc128::new();

        h.write(b"hello");
        assert_eq!(h.finish_ext(),
                   u128::from_parts(17404193039403234796, 13523890104784088047));

        h.write(b"world");
        assert_eq!(h.finish_ext(),
                   u128::from_parts(7450567370945444069, 787832070172609324));
    }
}
