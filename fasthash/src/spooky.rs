//! `SpookyHash`: a 128-bit noncryptographic hash function
//!
//! by Bob Jenkins
//!
//! http://www.burtleburtle.net/bob/hash/spooky.html
//!
//!  - Oct 31 2010: alpha, framework + `SpookyHash`::Mix appears right
//!  - Oct 31 2011: alpha again, Mix only good to 2^^69 but rest appears right
//!  - Dec 31 2011: beta, improved Mix, tested it for 2-bit deltas
//!  - Feb  2 2012: production, same bits as beta
//!  - Feb  5 2012: adjusted definitions of uint* to be more portable
//!
//! Up to 4 bytes/cycle for long messages.  Reasonably fast for short messages.
//! All 1 or 2 bit deltas achieve avalanche within 1% bias per output bit.
//!
//! This was developed for and tested on 64-bit x86-compatible processors.
//! It assumes the processor is little-endian.  There is a macro
//! controlling whether unaligned reads are allowed (by default they are).
//! This should be an equally good hash on big-endian machines, but it will
//! compute different results on them than on little-endian machines.
//!
//! Google's `CityHash` has similar specs to `SpookyHash`, and `CityHash` is faster
//! on some platforms.  MD4 and MD5 also have similar specs, but they are orders
//! of magnitude slower.  CRCs are two or more times slower, but unlike
//! `SpookyHash`, they have nice math for combining the CRCs of pieces to form
//! the CRCs of wholes.  There are also cryptographic hashes, but those are even
//! slower than MD5.
//!
//! # Examples
//!
//! ```
//! use std::hash::{Hash, Hasher};
//!
//! use fasthash::{spooky, SpookyHasher};
//!
//! fn hash<T: Hash>(t: &T) -> u64 {
//!     let mut s: SpookyHasher = Default::default();
//!     t.hash(&mut s);
//!     s.finish()
//! }
//!
//! let h = spooky::hash128(b"hello world\xff");
//!
//! assert_eq!(h.low64(), hash(&"hello world"));
//! ```
//!
use std::hash::Hasher;
use std::os::raw::c_void;

use extprim::u128::u128;

use ffi;

use hasher::{FastHash, FastHasher, HasherExt, StreamHasher};

/// `SpookyHash` 32-bit hash functions
pub struct SpookyHash32 {}

impl FastHash for SpookyHash32 {
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

impl_fasthash!(SpookyHasher128, SpookyHash32);

/// `SpookyHash` 64-bit hash functions
pub struct SpookyHash64 {}

impl FastHash for SpookyHash64 {
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

impl_fasthash!(SpookyHasher128, SpookyHash64);

/// `SpookyHash` 128-bit hash functions
pub struct SpookyHash128 {}

impl FastHash for SpookyHash128 {
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

/// An implementation of `std::hash::Hasher` and `fasthash::HasherExt`.
pub struct SpookyHasher128(*mut c_void);

impl Default for SpookyHasher128 {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for SpookyHasher128 {
    #[inline]
    fn drop(&mut self) {
        unsafe { ffi::SpookyHasherFree(self.0) }
    }
}

impl Hasher for SpookyHasher128 {
    #[inline]
    fn finish(&self) -> u64 {
        self.finish_ext().low64()
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

impl HasherExt for SpookyHasher128 {
    #[inline]
    fn finish_ext(&self) -> u128 {
        let mut hash1 = 0_u64;
        let mut hash2 = 0_u64;

        unsafe {
            ffi::SpookyHasherFinal(self.0, &mut hash1, &mut hash2);
        }

        u128::from_parts(hash1, hash2)
    }
}

impl FastHasher for SpookyHasher128 {
    type Seed = (u64, u64);

    #[inline]
    fn with_seed(seed: Self::Seed) -> SpookyHasher128 {
        let h = unsafe { ffi::SpookyHasherNew() };

        unsafe {
            ffi::SpookyHasherInit(h, seed.0, seed.1);
        }

        SpookyHasher128(h)
    }
}

impl StreamHasher for SpookyHasher128 {}

impl_fasthash!(SpookyHasher128, SpookyHash128);

/// `SpookyHash` 32-bit hash functions for a byte array.
#[inline]
pub fn hash32<T: AsRef<[u8]>>(v: &T) -> u32 {
    SpookyHash32::hash(v)
}

/// `SpookyHash` 32-bit hash functions for a byte array.
/// For convenience, a 32-bit seed is also hashed into the result.
#[inline]
pub fn hash32_with_seed<T: AsRef<[u8]>>(v: &T, seed: u32) -> u32 {
    SpookyHash32::hash_with_seed(v, seed)
}

/// `SpookyHash` 64-bit hash functions for a byte array.
/// For convenience, a 64-bit seed is also hashed into the result.
#[inline]
pub fn hash64<T: AsRef<[u8]>>(v: &T) -> u64 {
    SpookyHash64::hash(v)
}

/// `SpookyHash` 64-bit hash functions for a byte array.
#[inline]
pub fn hash64_with_seed<T: AsRef<[u8]>>(v: &T, seed: u64) -> u64 {
    SpookyHash64::hash_with_seed(v, seed)
}

/// `SpookyHash` 128-bit hash functions for a byte array.
/// For convenience, a 128-bit seed is also hashed into the result.
#[inline]
pub fn hash128<T: AsRef<[u8]>>(v: &T) -> u128 {
    SpookyHash128::hash(v)
}

/// `SpookyHash` 128-bit hash functions for a byte array.
#[inline]
pub fn hash128_with_seed<T: AsRef<[u8]>>(v: &T, seed: u128) -> u128 {
    SpookyHash128::hash_with_seed(v, seed)
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;
    use std::hash::Hasher;

    use extprim::u128::u128;

    use hasher::{FastHash, FastHasher, HasherExt, StreamHasher};
    use super::*;

    #[test]
    fn test_spooky32() {
        assert_eq!(SpookyHash32::hash(b"hello"), 3907268544);
        assert_eq!(SpookyHash32::hash_with_seed(b"hello", 123), 2211835972);
        assert_eq!(SpookyHash32::hash(b"helloworld"), 3874077464);
    }

    #[test]
    fn test_spooky64() {
        assert_eq!(SpookyHash64::hash(b"hello"), 6105954949053820864);
        assert_eq!(SpookyHash64::hash_with_seed(b"hello", 123),
                   8819086853393477700);
        assert_eq!(SpookyHash64::hash(b"helloworld"), 18412934266828208920);
    }

    #[test]
    fn test_spooky128() {
        assert_eq!(SpookyHash128::hash(b"hello"),
                   u128::from_parts(6105954949053820864, 16417113279381893933));
        assert_eq!(SpookyHash128::hash_with_seed(b"hello", u128::new(123)),
                   u128::from_parts(7262466432451564128, 15030932129358977799));
        assert_eq!(SpookyHash128::hash(b"helloworld"),
                   u128::from_parts(18412934266828208920, 13883738476858207693));

        let mut h = SpookyHasher128::new();

        h.write(b"hello");
        assert_eq!(h.finish_ext(),
                   u128::from_parts(6105954949053820864, 16417113279381893933));

        h.write(b"world");
        assert_eq!(h.finish_ext(),
                   u128::from_parts(18412934266828208920, 13883738476858207693));

        h.write_stream(&mut Cursor::new(&[0_u8; 4567][..])).unwrap();
        assert_eq!(h.finish(), 2977683714085165920);
    }
}
