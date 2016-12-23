#![allow(non_camel_case_types)]

use std::mem;
use std::os::raw::c_void;

use extprim::u128::u128;

use ffi;

use hasher::FastHasher;

#[doc(hidden)]
pub struct murmur3_x86_32 {}

impl FastHasher for murmur3_x86_32 {
    type Value = u32;
    type Seed = u32;

    #[inline]
    fn hash_with_seed<T: AsRef<[u8]>>(bytes: &T, seed: u32) -> u32 {
        unsafe {
            let mut hash = 0_u32;

            ffi::MurmurHash3_x86_32(bytes.as_ref().as_ptr() as *const c_void,
                                    bytes.as_ref().len() as i32,
                                    seed,
                                    mem::transmute(&mut hash));

            hash
        }
    }
}

fasthash!(Murmur3_x86_32, murmur3_x86_32);

#[doc(hidden)]
pub struct murmur3_x86_128 {}

impl FastHasher for murmur3_x86_128 {
    type Value = u128;
    type Seed = u32;

    #[inline]
    fn hash_with_seed<T: AsRef<[u8]>>(bytes: &T, seed: u32) -> u128 {
        unsafe {
            let mut hash = u128::zero();

            ffi::MurmurHash3_x86_128(bytes.as_ref().as_ptr() as *const c_void,
                                     bytes.as_ref().len() as i32,
                                     seed,
                                     mem::transmute(&mut hash));

            hash
        }
    }
}

fasthash_ext!(Murmur3_x86_128, murmur3_x86_128);

#[doc(hidden)]
pub struct murmur3_x64_128 {}

impl FastHasher for murmur3_x64_128 {
    type Value = u128;
    type Seed = u32;

    #[inline]
    fn hash_with_seed<T: AsRef<[u8]>>(bytes: &T, seed: u32) -> u128 {
        unsafe {
            let mut hash = u128::zero();

            ffi::MurmurHash3_x64_128(bytes.as_ref().as_ptr() as *const c_void,
                                     bytes.as_ref().len() as i32,
                                     seed,
                                     mem::transmute(&mut hash));

            hash
        }
    }
}

fasthash_ext!(Murmur3_x64_128, murmur3_x64_128);

#[inline]
pub fn hash32(s: &[u8]) -> u32 {
    murmur3_x86_32::hash(&s)
}

#[inline]
pub fn hash32_with_seed(s: &[u8], seed: u32) -> u32 {
    murmur3_x86_32::hash_with_seed(&s, seed)
}

#[inline]
pub fn hash128(s: &[u8]) -> u128 {
    murmur3_x64_128::hash(&s)
}

#[inline]
pub fn hash128_with_seed(s: &[u8], seed: u32) -> u128 {
    murmur3_x64_128::hash_with_seed(&s, seed)
}


#[cfg(test)]
mod tests {
    use std::hash::Hasher;

    use extprim::u128::u128;

    use hasher::{FastHasher, HasherExt};
    use super::*;

    #[test]
    fn test_murmur3_x86_32() {
        assert_eq!(murmur3_x86_32::hash(b"hello"), 613153351);
        assert_eq!(murmur3_x86_32::hash_with_seed(b"hello", 123), 1573043710);
        assert_eq!(murmur3_x86_32::hash(b"helloworld"), 2687965642);

        let mut h = Murmur3_x86_32::new();

        h.write(b"hello");
        assert_eq!(h.finish(), 613153351);

        h.write(b"world");
        assert_eq!(h.finish(), 2687965642);
    }

    #[test]
    fn test_murmur3_x86_128() {
        assert_eq!(murmur3_x86_128::hash(b"hello"),
                   u128::from_parts(11158567162092401078, 15821672119091348640));
        assert_eq!(murmur3_x86_128::hash_with_seed(b"hello", 123),
                   u128::from_parts(2149221405153268091, 10130600740778964073));
        assert_eq!(murmur3_x86_128::hash(b"helloworld"),
                   u128::from_parts(4510970894511742178, 13166749202678098166));

        let mut h = Murmur3_x86_128::new();

        h.write(b"hello");
        assert_eq!(h.finish(),
                   u128::from_parts(11158567162092401078, 15821672119091348640));

        h.write(b"world");
        assert_eq!(h.finish(),
                   u128::from_parts(4510970894511742178, 13166749202678098166));
    }

    #[test]
    fn test_murmur3_x64_128() {
        assert_eq!(murmur3_x64_128::hash(b"hello"),
                   u128::from_parts(6565844092913065241, 14688674573012802306));
        assert_eq!(murmur3_x64_128::hash_with_seed(b"hello", 123),
                   u128::from_parts(1043184066639555970, 3016954156110693643));
        assert_eq!(murmur3_x64_128::hash(b"helloworld"),
                   u128::from_parts(11724578221562109303, 10256632503372987514));

        let mut h = Murmur3_x64_128::new();

        h.write(b"hello");
        assert_eq!(h.finish(),
                   u128::from_parts(6565844092913065241, 14688674573012802306));

        h.write(b"world");
        assert_eq!(h.finish(),
                   u128::from_parts(11724578221562109303, 10256632503372987514));
    }
}
