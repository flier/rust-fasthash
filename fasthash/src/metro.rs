//! `MetroHash`, Exceptionally fast and statistically robust hash functions
//!
//! by J. Andrew Rogers
//!
//! https://github.com/jandrewrogers/metrohash
//!
//! `MetroHash` is a set of state-of-the-art hash functions for non-cryptographic use cases.
//! They are notable for being algorithmically generated in addition to their exceptional
//! performance. The set of published hash functions may be expanded in the future,
//! having been selected from a very large set of hash functions that have been
//! constructed this way.
//!
//! Fastest general-purpose functions for bulk hashing.
//! Fastest general-purpose functions for small, variable length keys.
//! Robust statistical bias profile, similar to the MD5 cryptographic hash.
//! Hashes can be constructed incrementally (new)
//! 64-bit, 128-bit, and 128-bit CRC variants currently available.
//! Optimized for modern x86-64 microarchitectures.
//! Elegant, compact, readable functions.
//!
//! You can read more about the design and history
//! [here](http://www.jandrewrogers.com/2015/05/27/metrohash/).
//!
//! # Example
//!
//! ```
//! use std::hash::{Hash, Hasher};
//!
//! use fasthash::{metro, MetroHasher};
//!
//! fn hash<T: Hash>(t: &T) -> u64 {
//!     let mut s: MetroHasher = Default::default();
//!     t.hash(&mut s);
//!     s.finish()
//! }
//!
//! let h = metro::hash64(b"hello world\xff");
//!
//! assert_eq!(h, hash(&"hello world"));
//! ```
//!
#![allow(non_camel_case_types)]
use std::mem;

use extprim::u128::u128;

use ffi;

use hasher::{FastHash, FastHasher};

/// `MetroHash` 64-bit hash functions
pub struct MetroHash64_1 {}

impl FastHash for MetroHash64_1 {
    type Value = u64;
    type Seed = u32;

    #[inline]
    fn hash_with_seed<T: AsRef<[u8]>>(bytes: &T, seed: u32) -> u64 {
        let mut hash = 0_u64;

        unsafe {
            ffi::metrohash64_1(bytes.as_ref().as_ptr() as *const u8,
                               bytes.as_ref().len() as u64,
                               seed,
                               mem::transmute(&mut hash));
        }

        hash
    }
}

impl_hasher!(MetroHasher64_1, MetroHash64_1);

/// `MetroHash` 64-bit hash functions
pub struct MetroHash64_2 {}

impl FastHash for MetroHash64_2 {
    type Value = u64;
    type Seed = u32;

    #[inline]
    fn hash_with_seed<T: AsRef<[u8]>>(bytes: &T, seed: u32) -> u64 {
        let mut hash = 0_u64;

        unsafe {
            ffi::metrohash64_2(bytes.as_ref().as_ptr() as *const u8,
                               bytes.as_ref().len() as u64,
                               seed,
                               mem::transmute(&mut hash));
        }

        hash
    }
}

impl_hasher!(MetroHasher64_2, MetroHash64_2);

/// `MetroHash` 128-bit hash functions
pub struct MetroHash128_1 {}

impl FastHash for MetroHash128_1 {
    type Value = u128;
    type Seed = u32;

    #[inline]
    fn hash_with_seed<T: AsRef<[u8]>>(bytes: &T, seed: u32) -> u128 {
        let mut hash = u128::zero();

        unsafe {
            ffi::metrohash128_1(bytes.as_ref().as_ptr() as *const u8,
                                bytes.as_ref().len() as u64,
                                seed,
                                mem::transmute(&mut hash));
        }

        hash
    }
}

impl_hasher_ext!(MetroHasher128_1, MetroHash128_1);

/// `MetroHash` 128-bit hash functions
pub struct MetroHash128_2 {}

impl FastHash for MetroHash128_2 {
    type Value = u128;
    type Seed = u32;

    #[inline]
    fn hash_with_seed<T: AsRef<[u8]>>(bytes: &T, seed: u32) -> u128 {
        let mut hash = u128::zero();

        unsafe {
            ffi::metrohash128_2(bytes.as_ref().as_ptr() as *const u8,
                                bytes.as_ref().len() as u64,
                                seed,
                                mem::transmute(&mut hash));
        }

        hash
    }
}

impl_hasher_ext!(MetroHasher128_2, MetroHash128_2);

/// `MetroHash` 64-bit hash functions using HW CRC instruction.
#[cfg(feature = "sse42")]
pub struct MetroHash64Crc_1 {}

#[cfg(feature = "sse42")]
impl FastHash for MetroHash64Crc_1 {
    type Value = u64;
    type Seed = u32;

    #[inline]
    fn hash_with_seed<T: AsRef<[u8]>>(bytes: &T, seed: u32) -> u64 {
        let mut hash = 0_u64;

        unsafe {
            ffi::metrohash64crc_1(bytes.as_ref().as_ptr() as *const u8,
                                  bytes.as_ref().len() as u64,
                                  seed,
                                  mem::transmute(&mut hash));
        }

        hash
    }
}

#[cfg(feature = "sse42")]
impl_hasher!(MetroHasher64Crc_1, MetroHash64Crc_1);

/// `MetroHash` 64-bit hash functions using HW CRC instruction.
#[cfg(feature = "sse42")]
pub struct MetroHash64Crc_2 {}

#[cfg(feature = "sse42")]
impl FastHash for MetroHash64Crc_2 {
    type Value = u64;
    type Seed = u32;

    #[inline]
    fn hash_with_seed<T: AsRef<[u8]>>(bytes: &T, seed: u32) -> u64 {
        let mut hash = 0_u64;

        unsafe {
            ffi::metrohash64crc_2(bytes.as_ref().as_ptr() as *const u8,
                                  bytes.as_ref().len() as u64,
                                  seed,
                                  mem::transmute(&mut hash));
        }

        hash
    }
}

#[cfg(feature = "sse42")]
impl_hasher!(MetroHasher64Crc_2, MetroHash64Crc_2);

/// `MetroHash` 128-bit hash functions using HW CRC instruction.
#[cfg(feature = "sse42")]
pub struct MetroHash128Crc_1 {}

#[cfg(feature = "sse42")]
impl FastHash for MetroHash128Crc_1 {
    type Value = u128;
    type Seed = u32;

    #[inline]
    fn hash_with_seed<T: AsRef<[u8]>>(bytes: &T, seed: u32) -> u128 {
        let mut hash = u128::zero();

        unsafe {
            ffi::metrohash128crc_1(bytes.as_ref().as_ptr() as *const u8,
                                   bytes.as_ref().len() as u64,
                                   seed,
                                   mem::transmute(&mut hash));
        }

        hash
    }
}

#[cfg(feature = "sse42")]
impl_hasher_ext!(MetroHasher128Crc_1, MetroHash128Crc_1);

/// `MetroHash` 128-bit hash functions using HW CRC instruction.
#[cfg(feature = "sse42")]
pub struct MetroHash128Crc_2 {}

#[cfg(feature = "sse42")]
impl FastHash for MetroHash128Crc_2 {
    type Value = u128;
    type Seed = u32;

    #[inline]
    fn hash_with_seed<T: AsRef<[u8]>>(bytes: &T, seed: u32) -> u128 {
        let mut hash = u128::zero();

        unsafe {
            ffi::metrohash128crc_2(bytes.as_ref().as_ptr() as *const u8,
                                   bytes.as_ref().len() as u64,
                                   seed,
                                   mem::transmute(&mut hash));
        }

        hash
    }
}

#[cfg(feature = "sse42")]
impl_hasher_ext!(MetroHasher128Crc_2, MetroHash128Crc_2);

/// `MetroHash` 64-bit hash function for a byte array.
#[cfg(not(feature = "sse42"))]
#[inline]
pub fn hash64<T: AsRef<[u8]>>(v: &T) -> u64 {
    MetroHash64_1::hash(v)
}

/// `MetroHash` 64-bit hash function for a byte array.
/// For convenience, a 64-bit seed is also hashed into the result.
#[cfg(not(feature = "sse42"))]
#[inline]
pub fn hash64_with_seed<T: AsRef<[u8]>>(v: &T, seed: u32) -> u64 {
    MetroHash64_1::hash_with_seed(v, seed)
}

/// `MetroHash` 128-bit hash function for a byte array.
#[cfg(not(feature = "sse42"))]
#[inline]
pub fn hash128<T: AsRef<[u8]>>(v: &T) -> u128 {
    MetroHash128_1::hash(v)
}

/// `MetroHash` 128-bit hash function for a byte array.
/// For convenience, a 128-bit seed is also hashed into the result.
#[cfg(not(feature = "sse42"))]
#[inline]
pub fn hash128_with_seed<T: AsRef<[u8]>>(v: &T, seed: u32) -> u128 {
    MetroHash128_1::hash_with_seed(v, seed)
}

/// `MetroHash` 64-bit hash function for a byte array using HW CRC instruction.
#[cfg(any(feature = "doc", feature = "sse42"))]
#[inline]
pub fn hash64<T: AsRef<[u8]>>(v: &T) -> u64 {
    MetroHash64Crc_1::hash(v)
}

/// `MetroHash` 64-bit hash function for a byte array using HW CRC instruction.
/// For convenience, a 64-bit seed is also hashed into the result.
#[cfg(any(feature = "doc", feature = "sse42"))]
#[inline]
pub fn hash64_with_seed<T: AsRef<[u8]>>(v: &T, seed: u32) -> u64 {
    MetroHash64Crc_1::hash_with_seed(v, seed)
}

/// `MetroHash` 128-bit hash function for a byte array using HW CRC instruction.
#[cfg(any(feature = "doc", feature = "sse42"))]
#[inline]
pub fn hash128<T: AsRef<[u8]>>(v: &T) -> u128 {
    MetroHash128Crc_1::hash(v)
}

/// `MetroHash` 128-bit hash function for a byte array. using HW CRC instruction.
/// For convenience, a 128-bit seed is also hashed into the result.
#[cfg(any(feature = "doc", feature = "sse42"))]
#[inline]
pub fn hash128_with_seed<T: AsRef<[u8]>>(v: &T, seed: u32) -> u128 {
    MetroHash128Crc_1::hash_with_seed(v, seed)
}

#[cfg(test)]
mod tests {
    use std::hash::Hasher;

    use extprim::u128::u128;

    use hasher::{FastHash, FastHasher, HasherExt};
    use super::*;

    #[test]
    fn test_metrohash64_1() {
        assert_eq!(MetroHash64_1::hash(b"hello"), 15663805623366682943);
        assert_eq!(MetroHash64_1::hash_with_seed(b"hello", 123),
                   1128464039211059189);
        assert_eq!(MetroHash64_1::hash(b"helloworld"), 4615394705531318333);

        let mut h = MetroHasher64_1::new();

        h.write(b"hello");
        assert_eq!(h.finish(), 15663805623366682943);

        h.write(b"world");
        assert_eq!(h.finish(), 4615394705531318333);
    }

    #[test]
    fn test_metrohash64_2() {
        assert_eq!(MetroHash64_2::hash(b"hello"), 12352443828090181231);
        assert_eq!(MetroHash64_2::hash_with_seed(b"hello", 123),
                   5558499743061241201);
        assert_eq!(MetroHash64_2::hash(b"helloworld"), 13816693401637061492);

        let mut h = MetroHasher64_2::new();

        h.write(b"hello");
        assert_eq!(h.finish(), 12352443828090181231);

        h.write(b"world");
        assert_eq!(h.finish(), 13816693401637061492);
    }

    #[cfg(feature = "sse42")]
    #[test]
    fn test_metrohash64crc_1() {
        assert_eq!(MetroHash64Crc_1::hash(b"hello"), 6455825309044375053);
        assert_eq!(MetroHash64Crc_1::hash_with_seed(b"hello", 123),
                   18102990158604115936);
        assert_eq!(MetroHash64Crc_1::hash(b"helloworld"), 15512397028293617890);

        let mut h = MetroHasher64Crc_1::new();

        h.write(b"hello");
        assert_eq!(h.finish(), 6455825309044375053);

        h.write(b"world");
        assert_eq!(h.finish(), 15512397028293617890);
    }

    #[cfg(feature = "sse42")]
    #[test]
    fn test_metrohash64crc_2() {
        assert_eq!(MetroHash64Crc_2::hash(b"hello"), 6093890398749886132);
        assert_eq!(MetroHash64Crc_2::hash_with_seed(b"hello", 123),
                   14600198876970659356);
        assert_eq!(MetroHash64Crc_2::hash(b"helloworld"), 11309399771810154329);

        let mut h = MetroHasher64Crc_2::new();

        h.write(b"hello");
        assert_eq!(h.finish(), 6093890398749886132);

        h.write(b"world");
        assert_eq!(h.finish(), 11309399771810154329);
    }

    #[test]
    fn test_metrohash128_1() {
        assert_eq!(MetroHash128_1::hash(b"hello"),
                   u128::from_parts(3402816320040206173, 8267579177094204812));
        assert_eq!(MetroHash128_1::hash_with_seed(b"hello", 123),
                   u128::from_parts(12815203692632715937, 16954909965332884860));
        assert_eq!(MetroHash128_1::hash(b"helloworld"),
                   u128::from_parts(9114061290236148431, 9070923966242366617));

        let mut h = MetroHasher128_1::new();

        h.write(b"hello");
        assert_eq!(h.finish_ext(),
                   u128::from_parts(3402816320040206173, 8267579177094204812));

        h.write(b"world");
        assert_eq!(h.finish_ext(),
                   u128::from_parts(9114061290236148431, 9070923966242366617));
    }

    #[test]
    fn test_metrohash128_2() {
        assert_eq!(MetroHash128_2::hash(b"hello"),
                   u128::from_parts(8645868589955642073, 18321434607751955537));
        assert_eq!(MetroHash128_2::hash_with_seed(b"hello", 123),
                   u128::from_parts(18306880534314458917, 13865612537680895339));
        assert_eq!(MetroHash128_2::hash(b"helloworld"),
                   u128::from_parts(16062202743590172306, 17411406382482299971));

        let mut h = MetroHasher128_2::new();

        h.write(b"hello");
        assert_eq!(h.finish_ext(),
                   u128::from_parts(8645868589955642073, 18321434607751955537));

        h.write(b"world");
        assert_eq!(h.finish_ext(),
                   u128::from_parts(16062202743590172306, 17411406382482299971));
    }

    #[cfg(feature = "sse42")]
    #[test]
    fn test_metrohash128crc_1() {
        assert_eq!(MetroHash128Crc_1::hash(b"hello"),
                   u128::from_parts(16571975282436791800, 17425155230852563966));
        assert_eq!(MetroHash128Crc_1::hash_with_seed(b"hello", 123),
                   u128::from_parts(2220453880884370284, 14239476408421791779));
        assert_eq!(MetroHash128Crc_1::hash(b"helloworld"),
                   u128::from_parts(17933136491111761230, 16547792430792712607));

        let mut h = MetroHasher128Crc_1::new();

        h.write(b"hello");
        assert_eq!(h.finish_ext(),
                   u128::from_parts(16571975282436791800, 17425155230852563966));

        h.write(b"world");
        assert_eq!(h.finish_ext(),
                   u128::from_parts(17933136491111761230, 16547792430792712607));
    }

    #[cfg(feature = "sse42")]
    #[test]
    fn test_metrohash128crc_2() {
        assert_eq!(MetroHash128Crc_2::hash(b"hello"),
                   u128::from_parts(3913189466847962340, 14660650764275632263));
        assert_eq!(MetroHash128Crc_2::hash_with_seed(b"hello", 123),
                   u128::from_parts(16592714704904777620, 13014106652212044248));
        assert_eq!(MetroHash128Crc_2::hash(b"helloworld"),
                   u128::from_parts(18016644482327815926, 8337696161216335052));

        let mut h = MetroHasher128Crc_2::new();

        h.write(b"hello");
        assert_eq!(h.finish_ext(),
                   u128::from_parts(3913189466847962340, 14660650764275632263));

        h.write(b"world");
        assert_eq!(h.finish_ext(),
                   u128::from_parts(18016644482327815926, 8337696161216335052));
    }
}
