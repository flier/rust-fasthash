#![allow(non_camel_case_types)]
use std::mem;

use extprim::u128::u128;

use ffi;

use hasher::FastHash;

#[doc(hidden)]
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

#[doc(hidden)]
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

#[doc(hidden)]
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

#[doc(hidden)]
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

#[inline]
pub fn hash64(s: &[u8]) -> u64 {
    MetroHash64_1::hash(&s)
}

#[inline]
pub fn hash64_with_seed(s: &[u8], seed: u32) -> u64 {
    MetroHash64_1::hash_with_seed(&s, seed)
}

#[inline]
pub fn hash128(s: &[u8]) -> u128 {
    MetroHash128_1::hash(&s)
}

#[inline]
pub fn hash128_with_seed(s: &[u8], seed: u32) -> u128 {
    MetroHash128_1::hash_with_seed(&s, seed)
}

#[cfg(test)]
mod tests {
    use std::hash::Hasher;

    use extprim::u128::u128;

    use hasher::{FastHash, HasherExt};
    use super::*;

    #[test]
    fn test_cityhash64_1() {
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
    fn test_cityhash64_2() {
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

    #[test]
    fn test_cityhash128_1() {
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
    fn test_cityhash128_2() {
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
}
