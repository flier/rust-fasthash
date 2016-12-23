#![allow(non_camel_case_types)]

use std::os::raw::c_void;

use ffi;

use hasher::FastHasher;

#[doc(hidden)]
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

#[doc(hidden)]
pub struct murmur_aligned {}

impl FastHasher for murmur_aligned {
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

fasthash!(MurmurAligned, murmur_aligned);

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
    murmur_aligned::hash(&s)
}

#[inline]
pub fn hash32_aligned_with_seed(s: &[u8], seed: u32) -> u32 {
    murmur_aligned::hash_with_seed(&s, seed)
}

#[cfg(test)]
mod tests {
    use std::hash::Hasher;

    use hasher::FastHasher;
    use super::*;

    #[test]
    fn test_murmur() {
        assert_eq!(murmur::hash(b"hello"), 1773990585);
        assert_eq!(murmur::hash_with_seed(b"hello", 123), 2155802495);
        assert_eq!(murmur::hash(b"helloworld"), 567127608);

        let mut h = Murmur::new();

        h.write(b"hello");
        assert_eq!(h.finish(), 1773990585);

        h.write(b"world");
        assert_eq!(h.finish(), 567127608);
    }

    #[test]
    fn test_murmur_aligned() {
        assert_eq!(murmur_aligned::hash(b"hello"), 1773990585);
        assert_eq!(murmur_aligned::hash_with_seed(b"hello", 123), 2155802495);
        assert_eq!(murmur_aligned::hash(b"helloworld"), 567127608);

        let mut h = MurmurAligned::new();

        h.write(b"hello");
        assert_eq!(h.finish(), 1773990585);

        h.write(b"world");
        assert_eq!(h.finish(), 567127608);
    }
}
