#![allow(non_camel_case_types)]
use std::os::raw::c_void;

use ffi;

use hasher::FastHasher;

#[doc(hidden)]
pub struct murmur2 {}

impl FastHasher for murmur2 {
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

fasthash!(Murmur2, murmur2);

#[doc(hidden)]
pub struct murmur2a {}

impl FastHasher for murmur2a {
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

fasthash!(Murmur2A, murmur2a);

#[doc(hidden)]
pub struct murmur2_neutral {}

impl FastHasher for murmur2_neutral {
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

fasthash!(Murmur2Neutral, murmur2_neutral);

#[doc(hidden)]
pub struct murmur2_aligned {}

impl FastHasher for murmur2_aligned {
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

fasthash!(Murmur2Aligned, murmur2_aligned);

#[doc(hidden)]
pub struct murmur2_x64_64 {}

impl FastHasher for murmur2_x64_64 {
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

fasthash!(Murmur2_x64_64, murmur2_x64_64);

#[doc(hidden)]
pub struct murmur2_x86_64 {}

impl FastHasher for murmur2_x86_64 {
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

fasthash!(Murmur2_x86_64, murmur2_x86_64);

#[inline]
pub fn hash32(s: &[u8]) -> u32 {
    murmur2::hash(&s)
}

#[inline]
pub fn hash32_with_seed(s: &[u8], seed: u32) -> u32 {
    murmur2::hash_with_seed(&s, seed)
}

#[inline]
pub fn hash64(s: &[u8]) -> u64 {
    murmur2_x64_64::hash(&s)
}

#[inline]
pub fn hash64_with_seed(s: &[u8], seed: u64) -> u64 {
    murmur2_x64_64::hash_with_seed(&s, seed)
}

#[cfg(test)]
mod tests {
    use std::hash::Hasher;

    use hasher::FastHasher;
    use super::*;

    #[test]
    fn test_murmur2() {
        assert_eq!(murmur2::hash(b"hello"), 3848350155);
        assert_eq!(murmur2::hash_with_seed(b"hello", 123), 2385981934);
        assert_eq!(murmur2::hash(b"helloworld"), 2155944146);

        let mut h = Murmur2::new();

        h.write(b"hello");
        assert_eq!(h.finish(), 3848350155);

        h.write(b"world");
        assert_eq!(h.finish(), 2155944146);
    }

    #[test]
    fn test_murmur2a() {
        assert_eq!(murmur2a::hash(b"hello"), 259931098);
        assert_eq!(murmur2a::hash_with_seed(b"hello", 123), 509510832);
        assert_eq!(murmur2a::hash(b"helloworld"), 403945221);

        let mut h = Murmur2A::new();

        h.write(b"hello");
        assert_eq!(h.finish(), 259931098);

        h.write(b"world");
        assert_eq!(h.finish(), 403945221);
    }

    #[test]
    fn test_murmur2_neutral() {
        assert_eq!(murmur2_neutral::hash(b"hello"), 3848350155);
        assert_eq!(murmur2_neutral::hash_with_seed(b"hello", 123), 2385981934);
        assert_eq!(murmur2_neutral::hash(b"helloworld"), 2155944146);

        let mut h = Murmur2Neutral::new();

        h.write(b"hello");
        assert_eq!(h.finish(), 3848350155);

        h.write(b"world");
        assert_eq!(h.finish(), 2155944146);
    }

    #[test]
    fn test_murmur2_aligned() {
        assert_eq!(murmur2_aligned::hash(b"hello"), 3848350155);
        assert_eq!(murmur2_aligned::hash_with_seed(b"hello", 123), 2385981934);
        assert_eq!(murmur2_aligned::hash(b"helloworld"), 2155944146);

        let mut h = Murmur2Aligned::new();

        h.write(b"hello");
        assert_eq!(h.finish(), 3848350155);

        h.write(b"world");
        assert_eq!(h.finish(), 2155944146);
    }

    #[test]
    fn test_murmur2_x64_64() {
        assert_eq!(murmur2_x64_64::hash(b"hello"), 2191231550387646743);
        assert_eq!(murmur2_x64_64::hash_with_seed(b"hello", 123),
                   2597646618390559622);
        assert_eq!(murmur2_x64_64::hash(b"helloworld"), 2139823713852166039);

        let mut h = Murmur2_x64_64::new();

        h.write(b"hello");
        assert_eq!(h.finish(), 2191231550387646743);

        h.write(b"world");
        assert_eq!(h.finish(), 2139823713852166039);
    }

    #[test]
    fn test_murmur2_x86_64() {
        assert_eq!(murmur2_x86_64::hash(b"hello"), 17658855022785723775);
        assert_eq!(murmur2_x86_64::hash_with_seed(b"hello", 123),
                   1883382312211796549);
        assert_eq!(murmur2_x86_64::hash(b"helloworld"), 14017254558097603378);

        let mut h = Murmur2_x86_64::new();

        h.write(b"hello");
        assert_eq!(h.finish(), 17658855022785723775);

        h.write(b"world");
        assert_eq!(h.finish(), 14017254558097603378);
    }
}
