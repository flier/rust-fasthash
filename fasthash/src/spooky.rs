#![allow(non_camel_case_types)]

use std::os::raw::c_void;

use extprim::u128::u128;

use ffi;

use hasher::{FastHasher, HasherExt};

#[doc(hidden)]
pub struct spooky32 {}

impl FastHasher for spooky32 {
    type Value = u32;
    type Seed = u32;

    #[inline]
    fn hash_with_seed<T: AsRef<[u8]>>(bytes: &T, seed: u32) -> u32 {
        let mut hash1 = seed as u64;
        let mut hash2 = seed as u64;

        unsafe {
            ffi::SpookyHasherHash(bytes.as_ref().as_ptr() as *const c_void,
                                  bytes.as_ref().len(),
                                  &mut hash1,
                                  &mut hash2);
        }

        hash1 as u32
    }
}

#[doc(hidden)]
pub struct spooky64 {}

impl FastHasher for spooky64 {
    type Value = u64;
    type Seed = u64;

    #[inline]
    fn hash_with_seed<T: AsRef<[u8]>>(bytes: &T, seed: u64) -> u64 {
        let mut hash1 = seed;
        let mut hash2 = seed;

        unsafe {
            ffi::SpookyHasherHash(bytes.as_ref().as_ptr() as *const c_void,
                                  bytes.as_ref().len(),
                                  &mut hash1,
                                  &mut hash2);
        }

        hash1
    }
}

#[doc(hidden)]
pub struct spooky128 {}

impl FastHasher for spooky128 {
    type Value = u128;
    type Seed = u128;

    #[inline]
    fn hash_with_seed<T: AsRef<[u8]>>(bytes: &T, seed: u128) -> u128 {
        let mut hash1 = seed.high64();
        let mut hash2 = seed.low64();

        unsafe {
            ffi::SpookyHasherHash(bytes.as_ref().as_ptr() as *const c_void,
                                  bytes.as_ref().len(),
                                  &mut hash1,
                                  &mut hash2);
        }

        u128::from_parts(hash1, hash2)
    }
}

pub struct SpookyHasher(*mut c_void);

impl SpookyHasher {
    #[inline]
    pub fn new() -> SpookyHasher {
        Self::with_seed(u128::new(0))
    }

    #[inline]
    pub fn with_seed(seed: u128) -> SpookyHasher {
        let h = unsafe { ffi::SpookyHasherNew() };

        unsafe {
            ffi::SpookyHasherInit(h, seed.high64(), seed.low64());
        }

        SpookyHasher(h)
    }
}

impl Drop for SpookyHasher {
    fn drop(&mut self) {
        unsafe { ffi::SpookyHasherFree(self.0) }
    }
}

impl HasherExt for SpookyHasher {
    #[inline]
    fn finish(&self) -> u128 {
        let mut hash1 = 0_u64;
        let mut hash2 = 0_u64;

        unsafe {
            ffi::SpookyHasherFinal(self.0, &mut hash1, &mut hash2);
        }

        u128::from_parts(hash1, hash2)
    }

    #[inline]
    fn write(&mut self, bytes: &[u8]) {
        unsafe {
            ffi::SpookyHasherUpdate(self.0,
                                    bytes.as_ref().as_ptr() as *const c_void,
                                    bytes.as_ref().len())
        }
    }
}

#[inline]
pub fn hash32(s: &[u8]) -> u32 {
    spooky32::hash(&s)
}

#[inline]
pub fn hash32_with_seed(s: &[u8], seed: u32) -> u32 {
    spooky32::hash_with_seed(&s, seed)
}

#[inline]
pub fn hash64(s: &[u8]) -> u64 {
    spooky64::hash(&s)
}

#[inline]
pub fn hash64_with_seed(s: &[u8], seed: u64) -> u64 {
    spooky64::hash_with_seed(&s, seed)
}

#[inline]
pub fn hash128(s: &[u8]) -> u128 {
    spooky128::hash(&s)
}

#[inline]
pub fn hash128_with_seed(s: &[u8], seed: u128) -> u128 {
    spooky128::hash_with_seed(&s, seed)
}


#[cfg(test)]
mod tests {
    use std::hash::Hasher;

    use extprim::u128::u128;

    use hasher::{FastHasher, HasherExt};
    use super::*;

    #[test]
    fn test_spooky32() {
        assert_eq!(spooky32::hash(b"hello"), 3907268544);
        assert_eq!(spooky32::hash_with_seed(b"hello", 123), 2211835972);
        assert_eq!(spooky32::hash(b"helloworld"), 3874077464);
    }

    #[test]
    fn test_spooky64() {
        assert_eq!(spooky64::hash(b"hello"), 6105954949053820864);
        assert_eq!(spooky64::hash_with_seed(b"hello", 123), 8819086853393477700);
        assert_eq!(spooky64::hash(b"helloworld"), 18412934266828208920);
    }

    #[test]
    fn test_spooky128() {
        assert_eq!(spooky128::hash(b"hello"),
                   u128::from_parts(6105954949053820864, 16417113279381893933));
        assert_eq!(spooky128::hash_with_seed(b"hello", u128::new(123)),
                   u128::from_parts(7262466432451564128, 15030932129358977799));
        assert_eq!(spooky128::hash(b"helloworld"),
                   u128::from_parts(18412934266828208920, 13883738476858207693));
    }

    #[test]
    fn test_spooky_hasher() {
        let mut h = SpookyHasher::new();

        h.write(b"hello");
        assert_eq!(h.finish(),
                   u128::from_parts(6105954949053820864, 16417113279381893933));

        h.write(b"world");
        assert_eq!(h.finish(),
                   u128::from_parts(18412934266828208920, 13883738476858207693));
    }
}
