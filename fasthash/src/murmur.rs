use std::os::raw::c_void;

use ffi;

use hasher::Hasher;

pub struct Murmur {}

impl Hasher for Murmur {
    type Value = u32;
    type Seed = u32;

    #[inline]
    fn hash_with_seed<T: AsRef<[u8]>>(bytes: &T, seed: u32) -> u32 {
        unsafe {
            let buf = bytes.as_ref();

            ffi::MurmurHash1(buf.as_ptr() as *const c_void, buf.len() as i32, seed)
        }
    }
}

fasthash!(MurmurHasher, Murmur);

pub struct MurmurAligned {}

impl Hasher for MurmurAligned {
    type Value = u32;
    type Seed = u32;

    #[inline]
    fn hash_with_seed<T: AsRef<[u8]>>(bytes: &T, seed: u32) -> u32 {
        unsafe {
            let buf = bytes.as_ref();

            ffi::MurmurHash1Aligned(buf.as_ptr() as *const c_void, buf.len() as i32, seed)
        }
    }
}

fasthash!(MurmurAlignedHasher, MurmurAligned);

#[inline]
pub fn hash32(s: &[u8]) -> u32 {
    Murmur::hash(&s)
}

#[inline]
pub fn hash32_with_seed(s: &[u8], seed: u32) -> u32 {
    Murmur::hash_with_seed(&s, seed)
}

#[inline]
pub fn hash32_aligned(s: &[u8]) -> u32 {
    MurmurAligned::hash(&s)
}

#[inline]
pub fn hash32_aligned_with_seed(s: &[u8], seed: u32) -> u32 {
    MurmurAligned::hash_with_seed(&s, seed)
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

        let mut h = MurmurHasher::new();

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

        let mut h = MurmurAlignedHasher::new();

        h.write(b"hello");
        assert_eq!(h.finish(), 1773990585);

        h.write(b"world");
        assert_eq!(h.finish(), 567127608);
    }
}
