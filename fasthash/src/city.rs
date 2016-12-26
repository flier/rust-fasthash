use std::mem;

use extprim::u128::u128;

use ffi;

use hasher::FastHash;

#[doc(hidden)]
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

#[doc(hidden)]
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

#[doc(hidden)]
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

#[cfg(feature = "sse42")]
#[doc(hidden)]
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

#[inline]
pub fn hash32<T: AsRef<[u8]>>(v: &T) -> u32 {
    CityHash32::hash(v)
}

#[inline]
pub fn hash32_with_seed<T: AsRef<[u8]>>(v: &T, seed: u32) -> u32 {
    CityHash32::hash_with_seed(v, seed)
}

#[inline]
pub fn hash64<T: AsRef<[u8]>>(v: &T) -> u64 {
    CityHash64::hash(v)
}

#[inline]
pub fn hash64_with_seed<T: AsRef<[u8]>>(v: &T, seed: u64) -> u64 {
    CityHash64::hash_with_seed(v, seed)
}

#[inline]
pub fn hash64_with_seeds<T: AsRef<[u8]>>(v: &T, seed0: u64, seed1: u64) -> u64 {
    CityHash64::hash_with_seeds(v, seed0, seed1)
}

#[inline]
pub fn hash128<T: AsRef<[u8]>>(v: &T) -> u128 {
    CityHash128::hash(v)
}

#[inline]
pub fn hash128_with_seed<T: AsRef<[u8]>>(v: &T, seed: u128) -> u128 {
    CityHash128::hash_with_seed(v, seed)
}

#[cfg(feature = "sse42")]
#[inline]
pub fn hash128crc<T: AsRef<[u8]>>(v: &T) -> u128 {
    CityHashCrc128::hash(v)
}

#[cfg(feature = "sse42")]
#[inline]
pub fn hash128crc_with_seed<T: AsRef<[u8]>>(v: &T, seed: u128) -> u128 {
    CityHashCrc128::hash_with_seed(v, seed)
}

#[cfg(test)]
mod tests {
    use std::hash::Hasher;

    use extprim::u128::u128;

    use hasher::{FastHash, HasherExt};
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
