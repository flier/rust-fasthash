#![allow(non_camel_case_types)]
use std::os::raw::c_void;

use ffi;

use hasher::FastHash;

#[doc(hidden)]
pub struct MumHash {}

impl FastHash for MumHash {
    type Value = u64;
    type Seed = u64;

    #[inline]
    fn hash_with_seed<T: AsRef<[u8]>>(bytes: &T, seed: u64) -> u64 {
        unsafe {
            ffi::mum_hash_(bytes.as_ref().as_ptr() as *const c_void,
                           bytes.as_ref().len(),
                           seed)
        }
    }
}

impl_hasher!(MumHasher, MumHash);

#[inline]
pub fn hash64(s: &[u8]) -> u64 {
    MumHash::hash(&s)
}

#[inline]
pub fn hash64_with_seed(s: &[u8], seed: u64) -> u64 {
    MumHash::hash_with_seed(&s, seed)
}

#[cfg(test)]
mod tests {
    use std::hash::Hasher;

    use hasher::FastHash;
    use super::*;

    #[test]
    fn test_mum64() {
        assert_eq!(MumHash::hash(b"hello"), 9723359729180093834);
        assert_eq!(MumHash::hash_with_seed(b"hello", 123), 12693953100868515521);
        assert_eq!(MumHash::hash(b"helloworld"), 9122204010978352975);

        let mut h = MumHasher::new();

        h.write(b"hello");
        assert_eq!(h.finish(), 9723359729180093834);

        h.write(b"world");
        assert_eq!(h.finish(), 9122204010978352975);
    }
}
