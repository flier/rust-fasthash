use std::os::raw::c_void;

use ffi;

use hasher::FastHash;

#[doc(hidden)]
pub struct T1ha64Le {}

impl FastHash for T1ha64Le {
    type Value = u64;
    type Seed = u64;

    #[inline]
    fn hash_with_seed<T: AsRef<[u8]>>(bytes: &T, seed: u64) -> u64 {
        unsafe {
            ffi::t1ha(bytes.as_ref().as_ptr() as *const c_void,
                      bytes.as_ref().len(),
                      seed)
        }
    }
}

impl_hasher!(T1ha64LeHasher, T1ha64Le);

#[doc(hidden)]
pub struct T1ha64Be {}

impl FastHash for T1ha64Be {
    type Value = u64;
    type Seed = u64;

    #[inline]
    fn hash_with_seed<T: AsRef<[u8]>>(bytes: &T, seed: u64) -> u64 {
        unsafe {
            ffi::t1ha_64be(bytes.as_ref().as_ptr() as *const c_void,
                           bytes.as_ref().len(),
                           seed)
        }
    }
}

impl_hasher!(T1ha64BeHasher, T1ha64Be);

#[doc(hidden)]
pub struct T1ha32Le {}

impl FastHash for T1ha32Le {
    type Value = u64;
    type Seed = u64;

    #[inline]
    fn hash_with_seed<T: AsRef<[u8]>>(bytes: &T, seed: u64) -> u64 {
        unsafe {
            ffi::t1ha_32le(bytes.as_ref().as_ptr() as *const c_void,
                           bytes.as_ref().len(),
                           seed)
        }
    }
}

impl_hasher!(T1ha32LeHasher, T1ha32Le);

#[doc(hidden)]
pub struct T1ha32Be {}

impl FastHash for T1ha32Be {
    type Value = u64;
    type Seed = u64;

    #[inline]
    fn hash_with_seed<T: AsRef<[u8]>>(bytes: &T, seed: u64) -> u64 {
        unsafe {
            ffi::t1ha_32be(bytes.as_ref().as_ptr() as *const c_void,
                           bytes.as_ref().len(),
                           seed)
        }
    }
}

impl_hasher!(T1ha32BeHasher, T1ha32Be);

#[cfg(feature = "sse42")]
#[doc(hidden)]
pub struct T1ha64Crc {}

#[cfg(feature = "sse42")]
impl FastHash for T1ha64Crc {
    type Value = u64;
    type Seed = u64;

    #[inline]
    fn hash_with_seed<T: AsRef<[u8]>>(bytes: &T, seed: u64) -> u64 {
        unsafe {
            ffi::t1ha_ia32crc(bytes.as_ref().as_ptr() as *const c_void,
                              bytes.as_ref().len(),
                              seed)
        }
    }
}

#[cfg(feature = "sse42")]
impl_hasher!(T1ha64CrcHasher, T1ha64Crc);

#[inline]
pub fn hash32<T: AsRef<[u8]>>(v: &T) -> u64 {
    T1ha32Le::hash(v)
}

#[inline]
pub fn hash32_with_seed<T: AsRef<[u8]>>(v: &T, seed: u64) -> u64 {
    T1ha32Le::hash_with_seed(v, seed)
}

#[inline]
pub fn hash64<T: AsRef<[u8]>>(v: &T) -> u64 {
    T1ha64Le::hash(v)
}

#[inline]
pub fn hash64_with_seed<T: AsRef<[u8]>>(v: &T, seed: u64) -> u64 {
    T1ha64Le::hash_with_seed(v, seed)
}

#[cfg(feature = "sse42")]
#[inline]
pub fn hash64crc<T: AsRef<[u8]>>(v: &T) -> u64 {
    T1ha64Crc::hash(v)
}

#[cfg(feature = "sse42")]
#[inline]
pub fn hash64crc_with_seed<T: AsRef<[u8]>>(v: &T, seed: u64) -> u64 {
    T1ha64Crc::hash_with_seed(v, seed)
}

#[cfg(test)]
mod tests {
    use std::hash::Hasher;

    use hasher::FastHash;
    use super::*;

    #[test]
    fn test_t1ha_32_le() {
        assert_eq!(T1ha32Le::hash(b"hello"), 1026677640742993727);
        assert_eq!(T1ha32Le::hash_with_seed(b"hello", 123), 9601366527779802491);
        assert_eq!(T1ha32Le::hash(b"helloworld"), 15938092988918204794);

        let mut h = T1ha32LeHasher::new();

        h.write(b"hello");
        assert_eq!(h.finish(), 1026677640742993727);

        h.write(b"world");
        assert_eq!(h.finish(), 15938092988918204794);
    }

    #[test]
    fn test_t1ha_32_be() {
        assert_eq!(T1ha32Be::hash(b"hello"), 14968514543474807977);
        assert_eq!(T1ha32Be::hash_with_seed(b"hello", 123),
                   18258318775703579484);
        assert_eq!(T1ha32Be::hash(b"helloworld"), 6104456647282750739);

        let mut h = T1ha32BeHasher::new();

        h.write(b"hello");
        assert_eq!(h.finish(), 14968514543474807977);

        h.write(b"world");
        assert_eq!(h.finish(), 6104456647282750739);
    }

    #[test]
    fn test_t1ha_64_le() {
        assert_eq!(T1ha64Le::hash(b"hello"), 12810198970222070563);
        assert_eq!(T1ha64Le::hash_with_seed(b"hello", 123), 7105133355958514544);
        assert_eq!(T1ha64Le::hash(b"helloworld"), 16997942636322422782);

        let mut h = T1ha64LeHasher::new();

        h.write(b"hello");
        assert_eq!(h.finish(), 12810198970222070563);

        h.write(b"world");
        assert_eq!(h.finish(), 16997942636322422782);
    }

    #[test]
    fn test_t1ha_64_be() {
        assert_eq!(T1ha64Be::hash(b"hello"), 14880640220959195744);
        assert_eq!(T1ha64Be::hash_with_seed(b"hello", 123), 1421069625385545216);
        assert_eq!(T1ha64Be::hash(b"helloworld"), 15825971635414726702);

        let mut h = T1ha64BeHasher::new();

        h.write(b"hello");
        assert_eq!(h.finish(), 14880640220959195744);

        h.write(b"world");
        assert_eq!(h.finish(), 15825971635414726702);
    }
}
