use std::os::raw::c_void;

use ffi;

use hasher::FastHash;

#[doc(hidden)]
pub struct Murmur {}

impl FastHash for Murmur {
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

impl_hasher!(MurmurHasher, Murmur);

#[doc(hidden)]
pub struct MurmurAligned {}

impl FastHash for MurmurAligned {
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

impl_hasher!(MurmurAlignedHasher, MurmurAligned);

#[inline]
pub fn hash32<T: AsRef<[u8]>>(v: &T) -> u32 {
    Murmur::hash(v)
}

#[inline]
pub fn hash32_with_seed<T: AsRef<[u8]>>(v: &T, seed: u32) -> u32 {
    Murmur::hash_with_seed(v, seed)
}

#[inline]
pub fn hash32_aligned<T: AsRef<[u8]>>(v: &T) -> u32 {
    MurmurAligned::hash(v)
}

#[inline]
pub fn hash32_aligned_with_seed<T: AsRef<[u8]>>(v: &T, seed: u32) -> u32 {
    MurmurAligned::hash_with_seed(v, seed)
}

#[cfg(test)]
mod tests {
    use std::hash::Hasher;

    use hasher::FastHash;
    use super::*;

    #[test]
    fn test_murmur() {
        assert_eq!(Murmur::hash(b"hello"), 1773990585);
        assert_eq!(Murmur::hash_with_seed(b"hello", 123), 2155802495);
        assert_eq!(Murmur::hash(b"helloworld"), 567127608);

        let mut h = MurmurHasher::new();

        h.write(b"hello");
        assert_eq!(h.finish(), 1773990585);

        h.write(b"world");
        assert_eq!(h.finish(), 567127608);
    }

    #[test]
    fn test_murmur_aligned() {
        assert_eq!(MurmurAligned::hash(b"hello"), 1773990585);
        assert_eq!(MurmurAligned::hash_with_seed(b"hello", 123), 2155802495);
        assert_eq!(MurmurAligned::hash(b"helloworld"), 567127608);

        let mut h = MurmurAlignedHasher::new();

        h.write(b"hello");
        assert_eq!(h.finish(), 1773990585);

        h.write(b"world");
        assert_eq!(h.finish(), 567127608);
    }
}
