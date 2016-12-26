#![allow(non_camel_case_types)]
use std::os::raw::c_void;

use ffi;

use hasher::FastHash;

#[doc(hidden)]
pub struct Murmur2 {}

impl FastHash for Murmur2 {
    type Value = u32;
    type Seed = u32;

    #[inline]
    fn hash_with_seed<T: AsRef<[u8]>>(bytes: &T, seed: u32) -> u32 {
        unsafe {
            ffi::MurmurHash2(bytes.as_ref().as_ptr() as *const c_void,
                             bytes.as_ref().len() as i32,
                             seed)
        }
    }
}

impl_hasher!(Murmur2Hasher, Murmur2);

#[doc(hidden)]
pub struct Murmur2A {}

impl FastHash for Murmur2A {
    type Value = u32;
    type Seed = u32;

    #[inline]
    fn hash_with_seed<T: AsRef<[u8]>>(bytes: &T, seed: u32) -> u32 {
        unsafe {
            ffi::MurmurHash2A(bytes.as_ref().as_ptr() as *const c_void,
                              bytes.as_ref().len() as i32,
                              seed)
        }
    }
}

impl_hasher!(Murmur2AHasher, Murmur2A);

#[doc(hidden)]
pub struct Murmur2Neutral {}

impl FastHash for Murmur2Neutral {
    type Value = u32;
    type Seed = u32;

    #[inline]
    fn hash_with_seed<T: AsRef<[u8]>>(bytes: &T, seed: u32) -> u32 {
        unsafe {
            ffi::MurmurHashNeutral2(bytes.as_ref().as_ptr() as *const c_void,
                                    bytes.as_ref().len() as i32,
                                    seed)
        }
    }
}

impl_hasher!(Murmur2NeutralHasher, Murmur2Neutral);

#[doc(hidden)]
pub struct Murmur2Aligned {}

impl FastHash for Murmur2Aligned {
    type Value = u32;
    type Seed = u32;

    #[inline]
    fn hash_with_seed<T: AsRef<[u8]>>(bytes: &T, seed: u32) -> u32 {
        unsafe {
            ffi::MurmurHashAligned2(bytes.as_ref().as_ptr() as *const c_void,
                                    bytes.as_ref().len() as i32,
                                    seed)
        }
    }
}

impl_hasher!(Murmur2AlignedHasher, Murmur2Aligned);

#[doc(hidden)]
pub struct Murmur2_x64_64 {}

impl FastHash for Murmur2_x64_64 {
    type Value = u64;
    type Seed = u64;

    #[inline]
    fn hash_with_seed<T: AsRef<[u8]>>(bytes: &T, seed: u64) -> u64 {
        unsafe {
            ffi::MurmurHash64A(bytes.as_ref().as_ptr() as *const c_void,
                               bytes.as_ref().len() as i32,
                               seed)
        }
    }
}

impl_hasher!(Murmur2Hasher_x64_64, Murmur2_x64_64);

#[doc(hidden)]
pub struct Murmur2_x86_64 {}

impl FastHash for Murmur2_x86_64 {
    type Value = u64;
    type Seed = u64;

    #[inline]
    fn hash_with_seed<T: AsRef<[u8]>>(bytes: &T, seed: u64) -> u64 {
        unsafe {
            ffi::MurmurHash64B(bytes.as_ref().as_ptr() as *const c_void,
                               bytes.as_ref().len() as i32,
                               seed)
        }
    }
}

impl_hasher!(Murmur2Hasher_x86_64, Murmur2_x86_64);

#[inline]
pub fn hash32<T: AsRef<[u8]>>(v: &T) -> u32 {
    Murmur2::hash(v)
}

#[inline]
pub fn hash32_with_seed<T: AsRef<[u8]>>(v: &T, seed: u32) -> u32 {
    Murmur2::hash_with_seed(v, seed)
}

#[inline]
pub fn hash64<T: AsRef<[u8]>>(v: &T) -> u64 {
    Murmur2_x64_64::hash(v)
}

#[inline]
pub fn hash64_with_seed<T: AsRef<[u8]>>(v: &T, seed: u64) -> u64 {
    Murmur2_x64_64::hash_with_seed(v, seed)
}

#[cfg(test)]
mod tests {
    use std::hash::Hasher;

    use hasher::FastHash;
    use super::*;

    #[test]
    fn test_murmur2() {
        assert_eq!(Murmur2::hash(b"hello"), 3848350155);
        assert_eq!(Murmur2::hash_with_seed(b"hello", 123), 2385981934);
        assert_eq!(Murmur2::hash(b"helloworld"), 2155944146);

        let mut h = Murmur2Hasher::new();

        h.write(b"hello");
        assert_eq!(h.finish(), 3848350155);

        h.write(b"world");
        assert_eq!(h.finish(), 2155944146);
    }

    #[test]
    fn test_murmur2a() {
        assert_eq!(Murmur2A::hash(b"hello"), 259931098);
        assert_eq!(Murmur2A::hash_with_seed(b"hello", 123), 509510832);
        assert_eq!(Murmur2A::hash(b"helloworld"), 403945221);

        let mut h = Murmur2AHasher::new();

        h.write(b"hello");
        assert_eq!(h.finish(), 259931098);

        h.write(b"world");
        assert_eq!(h.finish(), 403945221);
    }

    #[test]
    fn test_murmur2_neutral() {
        assert_eq!(Murmur2Neutral::hash(b"hello"), 3848350155);
        assert_eq!(Murmur2Neutral::hash_with_seed(b"hello", 123), 2385981934);
        assert_eq!(Murmur2Neutral::hash(b"helloworld"), 2155944146);

        let mut h = Murmur2NeutralHasher::new();

        h.write(b"hello");
        assert_eq!(h.finish(), 3848350155);

        h.write(b"world");
        assert_eq!(h.finish(), 2155944146);
    }

    #[test]
    fn test_murmur2_aligned() {
        assert_eq!(Murmur2Aligned::hash(b"hello"), 3848350155);
        assert_eq!(Murmur2Aligned::hash_with_seed(b"hello", 123), 2385981934);
        assert_eq!(Murmur2Aligned::hash(b"helloworld"), 2155944146);

        let mut h = Murmur2AlignedHasher::new();

        h.write(b"hello");
        assert_eq!(h.finish(), 3848350155);

        h.write(b"world");
        assert_eq!(h.finish(), 2155944146);
    }

    #[test]
    fn test_murmur2_x64_64() {
        assert_eq!(Murmur2_x64_64::hash(b"hello"), 2191231550387646743);
        assert_eq!(Murmur2_x64_64::hash_with_seed(b"hello", 123),
                   2597646618390559622);
        assert_eq!(Murmur2_x64_64::hash(b"helloworld"), 2139823713852166039);

        let mut h = Murmur2Hasher_x64_64::new();

        h.write(b"hello");
        assert_eq!(h.finish(), 2191231550387646743);

        h.write(b"world");
        assert_eq!(h.finish(), 2139823713852166039);
    }

    #[test]
    fn test_murmur2_x86_64() {
        assert_eq!(Murmur2_x86_64::hash(b"hello"), 17658855022785723775);
        assert_eq!(Murmur2_x86_64::hash_with_seed(b"hello", 123),
                   1883382312211796549);
        assert_eq!(Murmur2_x86_64::hash(b"helloworld"), 14017254558097603378);

        let mut h = Murmur2Hasher_x86_64::new();

        h.write(b"hello");
        assert_eq!(h.finish(), 17658855022785723775);

        h.write(b"world");
        assert_eq!(h.finish(), 14017254558097603378);
    }
}
