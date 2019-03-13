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
//! let h = spooky::hash64(b"hello world\xff");
//!
//! assert_eq!(h as u64, hash(&"hello world"));
//! ```
//!
use std::hash::Hasher;
use std::os::raw::c_void;

use ffi;

use hasher::{FastHash, FastHasher, HasherExt, StreamHasher};

/// `SpookyHash` 32-bit hash functions
///
/// # Example
///
/// ```
/// use fasthash::{spooky::Hash32, FastHash};
///
/// assert_eq!(Hash32::hash(b"hello"), 3907268544);
/// assert_eq!(Hash32::hash_with_seed(b"hello", 123), 2211835972);
/// assert_eq!(Hash32::hash(b"helloworld"), 3874077464);
/// ```
pub struct Hash32;

impl FastHash for Hash32 {
    type Hash = u32;
    type Seed = u32;

    #[inline]
    fn hash_with_seed<T: AsRef<[u8]>>(bytes: T, seed: u32) -> u32 {
        let mut hash1 = u64::from(seed);
        let mut hash2 = u64::from(seed);

        unsafe {
            ffi::SpookyHasherHash(
                bytes.as_ref().as_ptr() as *const c_void,
                bytes.as_ref().len(),
                &mut hash1,
                &mut hash2,
            );
        }

        hash1 as u32
    }
}

impl_hasher!(
    #[doc = r#"
# Example

```
use std::hash::Hasher;

use fasthash::{spooky::Hasher32, FastHasher};

let mut h = Hasher32::new();

h.write(b"hello");
assert_eq!(h.finish(), 3907268544);

h.write(b"world");
assert_eq!(h.finish(), 3874077464);
```
"#]
    Hasher32,
    Hash32
);

/// `SpookyHash` 64-bit hash functions
///
/// # Example
///
/// ```
/// use fasthash::{spooky::Hash64, FastHash};
///
/// assert_eq!(Hash64::hash(b"hello"), 6105954949053820864);
/// assert_eq!(Hash64::hash_with_seed(b"hello", 123), 8819086853393477700);
/// assert_eq!(Hash64::hash(b"helloworld"), 18412934266828208920);
/// ```
pub struct Hash64;

impl FastHash for Hash64 {
    type Hash = u64;
    type Seed = u64;

    #[inline]
    fn hash_with_seed<T: AsRef<[u8]>>(bytes: T, seed: u64) -> u64 {
        let mut hash1 = seed;
        let mut hash2 = seed;

        unsafe {
            ffi::SpookyHasherHash(
                bytes.as_ref().as_ptr() as *const c_void,
                bytes.as_ref().len(),
                &mut hash1,
                &mut hash2,
            );
        }

        hash1
    }
}

impl_hasher!(
    #[doc = r#"
# Example

```
use std::hash::Hasher;

use fasthash::{spooky::Hasher64, FastHasher};

let mut h = Hasher64::new();

h.write(b"hello");
assert_eq!(h.finish(), 6105954949053820864);

h.write(b"world");
assert_eq!(h.finish(), 18412934266828208920);
```
"#]
    Hasher64,
    Hash64
);

/// `SpookyHash` 128-bit hash functions
///
/// # Example
///
/// ```
/// use fasthash::{spooky::Hash128, FastHash};
///
/// assert_eq!(
///     Hash128::hash(b"hello"),
///     112634988270796077198737188616407610157
/// );
/// assert_eq!(
///     Hash128::hash_with_seed(b"hello", 123),
///     133968859623340440246086107642109008647
/// );
/// assert_eq!(
///     Hash128::hash(b"helloworld"),
///     339658686066216790682429200470429822413
/// );
/// ```
pub struct Hash128;

impl FastHash for Hash128 {
    type Hash = u128;
    type Seed = u128;

    #[inline]
    fn hash_with_seed<T: AsRef<[u8]>>(bytes: T, seed: u128) -> u128 {
        let mut hi = (seed >> 64) as u64;
        let mut lo = seed as u64;

        unsafe {
            ffi::SpookyHasherHash(
                bytes.as_ref().as_ptr() as *const c_void,
                bytes.as_ref().len(),
                &mut hi,
                &mut lo,
            );
        }

        u128::from(hi).wrapping_shl(64) + u128::from(lo)
    }
}

/// An implementation of `std::hash::Hasher` and `fasthash::HasherExt`.
///
/// # Example
///
/// ```
/// use std::hash::Hasher;
///
/// use fasthash::{spooky::Hasher128, FastHasher, HasherExt};
///
/// let mut h = Hasher128::new();
///
/// h.write(b"hello");
/// assert_eq!(h.finish_ext(), 112634988270796077198737188616407610157);
///
/// h.write(b"world");
/// assert_eq!(h.finish_ext(), 339658686066216790682429200470429822413);
/// ```
pub struct Hasher128(*mut c_void);

impl Default for Hasher128 {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for Hasher128 {
    #[inline]
    fn drop(&mut self) {
        unsafe { ffi::SpookyHasherFree(self.0) }
    }
}

impl Hasher for Hasher128 {
    #[inline]
    fn finish(&self) -> u64 {
        self.finish_ext() as u64
    }

    #[inline]
    fn write(&mut self, bytes: &[u8]) {
        unsafe { ffi::SpookyHasherUpdate(self.0, bytes.as_ptr() as *const c_void, bytes.len()) }
    }
}

impl HasherExt for Hasher128 {
    #[inline]
    fn finish_ext(&self) -> u128 {
        let mut hi = 0_u64;
        let mut lo = 0_u64;

        unsafe {
            ffi::SpookyHasherFinal(self.0, &mut hi, &mut lo);
        }

        u128::from(hi).wrapping_shl(64) + u128::from(lo)
    }
}

impl FastHasher for Hasher128 {
    type Seed = (u64, u64);

    #[inline]
    fn with_seed(seed: Self::Seed) -> Hasher128 {
        let h = unsafe { ffi::SpookyHasherNew() };

        unsafe {
            ffi::SpookyHasherInit(h, seed.0, seed.1);
        }

        Hasher128(h)
    }
}

impl StreamHasher for Hasher128 {}

impl_fasthash!(Hasher128, Hash128);

/// `SpookyHash` 32-bit hash functions for a byte array.
#[inline]
pub fn hash32<T: AsRef<[u8]>>(v: &T) -> u32 {
    Hash32::hash(v)
}

/// `SpookyHash` 32-bit hash functions for a byte array.
/// For convenience, a 32-bit seed is also hashed into the result.
#[inline]
pub fn hash32_with_seed<T: AsRef<[u8]>>(v: &T, seed: u32) -> u32 {
    Hash32::hash_with_seed(v, seed)
}

/// `SpookyHash` 64-bit hash functions for a byte array.
/// For convenience, a 64-bit seed is also hashed into the result.
#[inline]
pub fn hash64<T: AsRef<[u8]>>(v: &T) -> u64 {
    Hash64::hash(v)
}

/// `SpookyHash` 64-bit hash functions for a byte array.
#[inline]
pub fn hash64_with_seed<T: AsRef<[u8]>>(v: &T, seed: u64) -> u64 {
    Hash64::hash_with_seed(v, seed)
}

/// `SpookyHash` 128-bit hash functions for a byte array.
/// For convenience, a 128-bit seed is also hashed into the result.
#[inline]
pub fn hash128<T: AsRef<[u8]>>(v: &T) -> u128 {
    Hash128::hash(v)
}

/// `SpookyHash` 128-bit hash functions for a byte array.
#[inline]
pub fn hash128_with_seed<T: AsRef<[u8]>>(v: &T, seed: u128) -> u128 {
    Hash128::hash_with_seed(v, seed)
}
