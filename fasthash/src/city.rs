#![allow(non_camel_case_types)]

use std::mem;

use extprim::u128::u128;

use ffi;

use hasher::FastHasher;

#[doc(hidden)]
pub struct cityhash32 {}

impl FastHasher for cityhash32 {
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

fasthash!(CityHash32, cityhash32);

#[doc(hidden)]
pub struct cityhash64 {}

impl FastHasher for cityhash64 {
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

fasthash!(CityHash64, cityhash64);

#[doc(hidden)]
pub struct cityhash128 {}

impl FastHasher for cityhash128 {
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

fasthash_ext!(CityHash128, cityhash128);


#[inline]
pub fn hash32(s: &[u8]) -> u32 {
    cityhash32::hash(&s)
}

#[inline]
pub fn hash32_with_seed(s: &[u8], seed: u32) -> u32 {
    cityhash32::hash_with_seed(&s, seed)
}

#[inline]
pub fn hash64(s: &[u8]) -> u64 {
    cityhash64::hash(&s)
}

#[inline]
pub fn hash64_with_seed(s: &[u8], seed: u64) -> u64 {
    cityhash64::hash_with_seed(&s, seed)
}

#[inline]
pub fn hash128(s: &[u8]) -> u128 {
    cityhash128::hash(&s)
}

#[inline]
pub fn hash128_with_seed(s: &[u8], seed: u128) -> u128 {
    cityhash128::hash_with_seed(&s, seed)
}


#[cfg(test)]
mod tests {
    use std::hash::Hasher;

    use extprim::u128::u128;

    use hasher::{FastHasher, HasherExt};
    use super::*;

    #[test]
    fn test_cityhash32() {
        assert_eq!(cityhash32::hash(b"hello"), 2039911270);
        assert_eq!(cityhash32::hash_with_seed(b"hello", 123), 3366460263);
        assert_eq!(cityhash32::hash(b"helloworld"), 4037657980);

        let mut h = CityHash32::new();

        h.write(b"hello");
        assert_eq!(h.finish(), 2039911270);

        h.write(b"world");
        assert_eq!(h.finish(), 4037657980);
    }

    #[test]
    fn test_cityhash64() {
        assert_eq!(cityhash64::hash(b"hello"), 2578220239953316063);
        assert_eq!(cityhash64::hash_with_seed(b"hello", 123),
                   11802079543206271427);
        assert_eq!(cityhash64::hash(b"helloworld"), 16622738483577116029);

        let mut h = CityHash64::new();

        h.write(b"hello");
        assert_eq!(h.finish(), 2578220239953316063);

        h.write(b"world");
        assert_eq!(h.finish(), 16622738483577116029);
    }

    #[test]
    fn test_cityhash128() {
        assert_eq!(cityhash128::hash(b"hello"),
                   u128::from_parts(17404193039403234796, 13523890104784088047));
        assert_eq!(cityhash128::hash_with_seed(b"hello", u128::new(123)),
                   u128::from_parts(10365139276371188890, 13112352013023211873));
        assert_eq!(cityhash128::hash(b"helloworld"),
                   u128::from_parts(7450567370945444069, 787832070172609324));

        let mut h = CityHash128::new();

        h.write(b"hello");
        assert_eq!(h.finish(),
                   u128::from_parts(17404193039403234796, 13523890104784088047));

        h.write(b"world");
        assert_eq!(h.finish(),
                   u128::from_parts(7450567370945444069, 787832070172609324));
    }
}
