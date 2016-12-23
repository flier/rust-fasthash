#![allow(non_camel_case_types)]

use std::os::raw::c_void;

use ffi;

use hasher::FastHasher;

pub struct murmur {}

impl FastHasher for murmur {
    type Value = u32;
    type Seed = u32;

    #[inline]
    fn hash_with_seed<T: AsRef<[u8]>>(bytes: &T, seed: u32) -> u32 {
        unsafe {
            ffi::MurmurHash1(bytes.as_ref().as_ptr() as *const c_void,
                             bytes.as_ref().len() as i32,
                             seed)
        }
    }
}

fasthash!(Murmur, murmur);

pub struct murmurAligned {}

impl FastHasher for murmurAligned {
    type Value = u32;
    type Seed = u32;

    #[inline]
    fn hash_with_seed<T: AsRef<[u8]>>(bytes: &T, seed: u32) -> u32 {
        unsafe {
            ffi::MurmurHash1Aligned(bytes.as_ref().as_ptr() as *const c_void,
                                    bytes.as_ref().len() as i32,
                                    seed)
        }
    }
}

fasthash!(MurmurAligned, murmurAligned);

#[inline]
pub fn hash32(s: &[u8]) -> u32 {
    murmur::hash(&s)
}

#[inline]
pub fn hash32_with_seed(s: &[u8], seed: u32) -> u32 {
    murmur::hash_with_seed(&s, seed)
}

#[inline]
pub fn hash32_aligned(s: &[u8]) -> u32 {
    murmurAligned::hash(&s)
}

#[inline]
pub fn hash32_aligned_with_seed(s: &[u8], seed: u32) -> u32 {
    murmurAligned::hash_with_seed(&s, seed)
}

#[cfg(test)]
mod tests {
    use std::hash::Hasher;

    use super::*;

    #[test]
    fn test_murmur() {
        assert_eq!(hash32(b"hello"), 1773990585);
        assert_eq!(hash32_with_seed(b"hello", 123), 2155802495);
        assert_eq!(hash32(b"helloworld"), 567127608);

        let mut h = Murmur::new();

        h.write(b"hello");
        assert_eq!(h.finish(), 1773990585);

        h.write(b"world");
        assert_eq!(h.finish(), 567127608);
    }

    #[test]
    fn test_murmur_aligned() {
        assert_eq!(hash32_aligned(b"hello"), 1773990585);
        assert_eq!(hash32_aligned_with_seed(b"hello", 123), 2155802495);
        assert_eq!(hash32_aligned(b"helloworld"), 567127608);

        let mut h = MurmurAligned::new();

        h.write(b"hello");
        assert_eq!(h.finish(), 1773990585);

        h.write(b"world");
        assert_eq!(h.finish(), 567127608);
    }
}
