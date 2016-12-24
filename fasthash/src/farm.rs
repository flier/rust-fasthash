#![allow(non_camel_case_types)]

use std::mem;

use extprim::u128::u128;

use ffi;

use hasher::FastHasher;

#[doc(hidden)]
pub struct farmhash32 {}

impl FastHasher for farmhash32 {
    type Value = u32;
    type Seed = u32;

    #[inline]
    fn hash<T: AsRef<[u8]>>(bytes: &T) -> u32 {
        unsafe { ffi::farmhash32(bytes.as_ref().as_ptr() as *const i8, bytes.as_ref().len()) }
    }

    #[inline]
    fn hash_with_seed<T: AsRef<[u8]>>(bytes: &T, seed: u32) -> u32 {
        unsafe {
            ffi::farmhash32_with_seed(bytes.as_ref().as_ptr() as *const i8,
                                      bytes.as_ref().len(),
                                      seed)
        }
    }
}

fasthash!(FarmHash32, farmhash32);

pub struct farmhash64 {}

impl FastHasher for farmhash64 {
    type Value = u64;
    type Seed = u64;

    #[inline]
    fn hash<T: AsRef<[u8]>>(bytes: &T) -> u64 {
        unsafe { ffi::farmhash64(bytes.as_ref().as_ptr() as *const i8, bytes.as_ref().len()) }
    }

    #[inline]
    fn hash_with_seed<T: AsRef<[u8]>>(bytes: &T, seed: u64) -> u64 {
        unsafe {
            ffi::farmhash64_with_seed(bytes.as_ref().as_ptr() as *const i8,
                                      bytes.as_ref().len(),
                                      seed)
        }
    }
}

fasthash!(FarmHash64, farmhash64);

#[doc(hidden)]
pub struct farmhash128 {}

impl FastHasher for farmhash128 {
    type Value = u128;
    type Seed = u128;

    #[inline]
    fn hash<T: AsRef<[u8]>>(bytes: &T) -> u128 {
        unsafe {
            mem::transmute(ffi::farmhash128(bytes.as_ref().as_ptr() as *const i8,
                                            bytes.as_ref().len()))
        }
    }

    #[inline]
    fn hash_with_seed<T: AsRef<[u8]>>(bytes: &T, seed: u128) -> u128 {
        unsafe {
            mem::transmute(ffi::farmhash128_with_seed(bytes.as_ref().as_ptr() as *const i8,
                                                      bytes.as_ref().len(),
                                                      mem::transmute(seed)))
        }
    }
}

fasthash_ext!(FarmHash128, farmhash128);

#[inline]
pub fn hash32(s: &[u8]) -> u32 {
    farmhash32::hash(&s)
}

#[inline]
pub fn hash32_with_seed(s: &[u8], seed: u32) -> u32 {
    farmhash32::hash_with_seed(&s, seed)
}

#[inline]
pub fn hash64(s: &[u8]) -> u64 {
    farmhash64::hash(&s)
}

#[inline]
pub fn hash64_with_seed(s: &[u8], seed: u64) -> u64 {
    farmhash64::hash_with_seed(&s, seed)
}

#[inline]
pub fn hash128(s: &[u8]) -> u128 {
    farmhash128::hash(&s)
}

#[inline]
pub fn hash128_with_seed(s: &[u8], seed: u128) -> u128 {
    farmhash128::hash_with_seed(&s, seed)
}


#[cfg(test)]
mod tests {
    use std::hash::Hasher;

    use extprim::u128::u128;

    use hasher::{FastHasher, HasherExt};
    use super::*;

    #[test]
    fn test_farmhash32() {
        assert_eq!(farmhash32::hash(b"hello"), 3111026382);
        assert_eq!(farmhash32::hash_with_seed(b"hello", 123), 1449662659);
        assert_eq!(farmhash32::hash(b"helloworld"), 3283552592);

        let mut h = FarmHash32::new();

        h.write(b"hello");
        assert_eq!(h.finish(), 3111026382);

        h.write(b"world");
        assert_eq!(h.finish(), 3283552592);
    }

    #[test]
    fn test_farmhash64() {
        assert_eq!(farmhash64::hash(b"hello"), 14403600180753024522);
        assert_eq!(farmhash64::hash_with_seed(b"hello", 123),
                   6856739100025169098);
        assert_eq!(farmhash64::hash(b"helloworld"), 1077737941828767314);

        let mut h = FarmHash64::new();

        h.write(b"hello");
        assert_eq!(h.finish(), 14403600180753024522);

        h.write(b"world");
        assert_eq!(h.finish(), 1077737941828767314);
    }

    #[test]
    fn test_farmhash128() {
        assert_eq!(farmhash128::hash(b"hello"),
                   u128::from_parts(14545675544334878584, 15888401098353921598));
        assert_eq!(farmhash128::hash_with_seed(b"hello", u128::new(123)),
                   u128::from_parts(15212901187400903054, 13320390559359511083));
        assert_eq!(farmhash128::hash(b"helloworld"),
                   u128::from_parts(16066658700231169910, 1119455499735156801));

        let mut h = FarmHash128::new();

        h.write(b"hello");
        assert_eq!(h.finish(),
                   u128::from_parts(14545675544334878584, 15888401098353921598));

        h.write(b"world");
        assert_eq!(h.finish(),
                   u128::from_parts(16066658700231169910, 1119455499735156801));
    }
}
