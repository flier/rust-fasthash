use std::mem;

use extprim::u128::u128;

use ffi;

use hasher::FastHash;

#[doc(hidden)]
pub struct FarmHash32 {}

impl FastHash for FarmHash32 {
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

impl_hasher!(FarmHasher32, FarmHash32);

#[doc(hidden)]
pub struct FarmHash64 {}

impl FarmHash64 {
    #[inline]
    pub fn hash_with_seeds<T: AsRef<[u8]>>(bytes: &T, seed0: u64, seed1: u64) -> u64 {
        unsafe {
            ffi::farmhash64_with_seeds(bytes.as_ref().as_ptr() as *const i8,
                                       bytes.as_ref().len(),
                                       seed0,
                                       seed1)
        }
    }
}

impl FastHash for FarmHash64 {
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

impl_hasher!(FarmHasher64, FarmHash64);

#[doc(hidden)]
pub struct FarmHash128 {}

impl FastHash for FarmHash128 {
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

impl_hasher_ext!(FarmHasher128, FarmHash128);

#[inline]
pub fn hash32(s: &[u8]) -> u32 {
    FarmHash32::hash(&s)
}

#[inline]
pub fn hash32_with_seed(s: &[u8], seed: u32) -> u32 {
    FarmHash32::hash_with_seed(&s, seed)
}

#[inline]
pub fn hash64(s: &[u8]) -> u64 {
    FarmHash64::hash(&s)
}

#[inline]
pub fn hash64_with_seed(s: &[u8], seed: u64) -> u64 {
    FarmHash64::hash_with_seed(&s, seed)
}

pub fn hash64_with_seeds(s: &[u8], seed0: u64, seed1: u64) -> u64 {
    FarmHash64::hash_with_seeds(&s, seed0, seed1)
}

#[inline]
pub fn hash128(s: &[u8]) -> u128 {
    FarmHash128::hash(&s)
}

#[inline]
pub fn hash128_with_seed(s: &[u8], seed: u128) -> u128 {
    FarmHash128::hash_with_seed(&s, seed)
}


#[cfg(test)]
mod tests {
    use std::hash::Hasher;

    use extprim::u128::u128;

    use hasher::{FastHash, HasherExt};
    use super::*;

    #[test]
    fn test_farmhash32() {
        assert_eq!(FarmHash32::hash(b"hello"), 3111026382);
        assert_eq!(FarmHash32::hash_with_seed(b"hello", 123), 1449662659);
        assert_eq!(FarmHash32::hash(b"helloworld"), 3283552592);

        let mut h = FarmHasher32::new();

        h.write(b"hello");
        assert_eq!(h.finish(), 3111026382);

        h.write(b"world");
        assert_eq!(h.finish(), 3283552592);
    }

    #[test]
    fn test_farmhash64() {
        assert_eq!(FarmHash64::hash(b"hello"), 14403600180753024522);
        assert_eq!(FarmHash64::hash_with_seed(b"hello", 123),
                   6856739100025169098);
        assert_eq!(FarmHash64::hash_with_seeds(b"hello", 123, 456),
                   15077713332534145879);
        assert_eq!(FarmHash64::hash(b"helloworld"), 1077737941828767314);

        let mut h = FarmHasher64::new();

        h.write(b"hello");
        assert_eq!(h.finish(), 14403600180753024522);

        h.write(b"world");
        assert_eq!(h.finish(), 1077737941828767314);
    }

    #[test]
    fn test_farmhash128() {
        assert_eq!(FarmHash128::hash(b"hello"),
                   u128::from_parts(14545675544334878584, 15888401098353921598));
        assert_eq!(FarmHash128::hash_with_seed(b"hello", u128::new(123)),
                   u128::from_parts(15212901187400903054, 13320390559359511083));
        assert_eq!(FarmHash128::hash(b"helloworld"),
                   u128::from_parts(16066658700231169910, 1119455499735156801));

        let mut h = FarmHasher128::new();

        h.write(b"hello");
        assert_eq!(h.finish_ext(),
                   u128::from_parts(14545675544334878584, 15888401098353921598));

        h.write(b"world");
        assert_eq!(h.finish_ext(),
                   u128::from_parts(16066658700231169910, 1119455499735156801));
    }
}
