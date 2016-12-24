use std::hash::Hasher;
use std::os::raw::c_void;

use ffi;

use hasher::FastHash;

#[doc(hidden)]
pub struct XXHash32 {}

impl FastHash for XXHash32 {
    type Value = u32;
    type Seed = u32;

    #[inline]
    fn hash_with_seed<T: AsRef<[u8]>>(bytes: &T, seed: u32) -> u32 {
        unsafe {
            ffi::XXH32(bytes.as_ref().as_ptr() as *const c_void,
                       bytes.as_ref().len(),
                       seed)
        }
    }
}

#[doc(hidden)]
pub struct XXHash64 {}

impl FastHash for XXHash64 {
    type Value = u64;
    type Seed = u64;

    #[inline]
    fn hash_with_seed<T: AsRef<[u8]>>(bytes: &T, seed: u64) -> u64 {
        unsafe {
            ffi::XXH64(bytes.as_ref().as_ptr() as *const c_void,
                       bytes.as_ref().len(),
                       seed)
        }
    }
}

#[inline]
pub fn hash32(s: &[u8]) -> u32 {
    XXHash32::hash(&s)
}

#[inline]
pub fn hash32_with_seed(s: &[u8], seed: u32) -> u32 {
    XXHash32::hash_with_seed(&s, seed)
}

#[inline]
pub fn hash64(s: &[u8]) -> u64 {
    XXHash64::hash(&s)
}

#[inline]
pub fn hash64_with_seed(s: &[u8], seed: u64) -> u64 {
    XXHash64::hash_with_seed(&s, seed)
}

pub struct XXHasher32(*mut ffi::XXH32_state_t);

impl XXHasher32 {
    #[inline]
    pub fn new() -> Self {
        Self::with_seed(0)
    }

    #[inline]
    pub fn with_seed(seed: u32) -> Self {
        let h = unsafe { ffi::XXH32_createState() };

        unsafe {
            ffi::XXH32_reset(h, seed);
        }

        XXHasher32(h)
    }
}

impl Drop for XXHasher32 {
    #[inline]
    fn drop(&mut self) {
        unsafe {
            ffi::XXH32_freeState(self.0);
        }
    }
}

impl Hasher for XXHasher32 {
    #[inline]
    fn finish(&self) -> u64 {
        unsafe { ffi::XXH32_digest(self.0) as u64 }
    }

    #[inline]
    fn write(&mut self, bytes: &[u8]) {
        unsafe {
            ffi::XXH32_update(self.0,
                              bytes.as_ref().as_ptr() as *const c_void,
                              bytes.as_ref().len());
        }
    }
}

pub struct XXHasher64(*mut ffi::XXH64_state_t);

impl XXHasher64 {
    #[inline]
    pub fn new() -> Self {
        Self::with_seed(0)
    }

    #[inline]
    pub fn with_seed(seed: u64) -> Self {
        let h = unsafe { ffi::XXH64_createState() };

        unsafe {
            ffi::XXH64_reset(h, seed);
        }

        XXHasher64(h)
    }
}

impl Drop for XXHasher64 {
    fn drop(&mut self) {
        unsafe {
            ffi::XXH64_freeState(self.0);
        }
    }
}

impl Hasher for XXHasher64 {
    #[inline]
    fn finish(&self) -> u64 {
        unsafe { ffi::XXH64_digest(self.0) }
    }

    #[inline]
    fn write(&mut self, bytes: &[u8]) {
        unsafe {
            ffi::XXH64_update(self.0,
                              bytes.as_ref().as_ptr() as *const c_void,
                              bytes.as_ref().len());
        }
    }
}

#[cfg(test)]
mod tests {
    use std::hash::Hasher;

    use hasher::FastHash;
    use super::*;

    #[test]
    fn test_xxh32() {
        assert_eq!(XXHash32::hash(b"hello"), 4211111929);
        assert_eq!(XXHash32::hash_with_seed(b"hello", 123), 2147069998);
        assert_eq!(XXHash32::hash(b"helloworld"), 593682946);

        let mut h = XXHasher32::new();

        h.write(b"hello");
        assert_eq!(h.finish(), 4211111929);

        h.write(b"world");
        assert_eq!(h.finish(), 593682946);
    }

    #[test]
    fn test_xxh64() {
        assert_eq!(XXHash64::hash(b"hello"), 2794345569481354659);
        assert_eq!(XXHash64::hash_with_seed(b"hello", 123), 2900467397628653179);
        assert_eq!(XXHash64::hash(b"helloworld"), 9228181307863624271);

        let mut h = XXHasher64::new();

        h.write(b"hello");
        assert_eq!(h.finish(), 2794345569481354659);

        h.write(b"world");
        assert_eq!(h.finish(), 9228181307863624271);
    }
}
