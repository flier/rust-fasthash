//! ## HighwayHash
//!
//! We have devised a new way of mixing inputs with SIMD multiply and permute
//! instructions. The multiplications are 32x32 -> 64 bits and therefore infeasible
//! to reverse. Permuting equalizes the distribution of the resulting bytes.
//!
//! The internal state is quite large (1024 bits) but fits within SIMD registers.
//! Due to limitations of the AVX2 instruction set, the registers are partitioned
//! into two 512-bit halves that remain independent until the reduce phase. The
//! algorithm outputs 64 bit digests or up to 256 bits at no extra cost.
//!
//! In addition to high throughput, the algorithm is designed for low finalization
//! cost. The result is more than twice as fast as SipTreeHash.
//!
//! We also provide an SSE4.1 version (80% as fast for large inputs and 95% as fast
//! for short inputs), an implementation for VSX on POWER and a portable version
//! (10% as fast). A third-party ARM implementation is referenced below.
//!
//! Statistical analyses and preliminary cryptanalysis are given in
//! https://arxiv.org/abs/1612.06257.
use crate::FastHash;

/// 256-bit secret key that should remain unknown to attackers.
/// We recommend initializing it to a random value.
pub type Seed = ffi::HHKey;

/// `HighwayHash` 64-bit hash functions for a byte array.
///
/// # Example
///
/// ```
/// use std::hash::Hasher;
/// use std::io::Cursor;
///
/// use fasthash::{highway, FastHash};
///
/// assert_eq!(highway::hash64("hello world"), 10265319535608467649);
/// ```
#[inline(always)]
pub fn hash64<T: AsRef<[u8]>>(v: T) -> u64 {
    Hash64::hash(v)
}

/// `HighwayHash` 64-bit hash function for a byte array.
///
/// For convenience, a 256-bit seed is also hashed into the result.
///
/// # Example
///
/// ```
/// use std::hash::Hasher;
/// use std::io::Cursor;
///
/// use fasthash::{highway, FastHash};
///
/// assert_eq!(highway::hash64_with_seed("hello world", [1, 2, 3, 4]), 6273970844710122614);
/// ```
#[inline(always)]
pub fn hash64_with_seed<T: AsRef<[u8]>>(v: T, seed: Seed) -> u64 {
    Hash64::hash_with_seed(v, seed)
}

/// `HighwayHash` 128-bit hash functions for a byte array.
///
/// # Example
///
/// ```
/// use std::hash::Hasher;
/// use std::io::Cursor;
///
/// use fasthash::{highway, FastHash};
///
/// assert_eq!(highway::hash128("hello world"), 184704813598772831779357069533224393217);
/// ```
#[inline(always)]
pub fn hash128<T: AsRef<[u8]>>(v: T) -> u128 {
    Hash128::hash(v)
}

/// `HighwayHash` 128-bit hash function for a byte array.
///
/// For convenience, a 256-bit seed is also hashed into the result.
///
/// # Example
///
/// ```
/// use std::hash::Hasher;
/// use std::io::Cursor;
///
/// use fasthash::{highway, FastHash};
///
/// assert_eq!(highway::hash128_with_seed("hello world", [1, 2, 3, 4]), 70726204502586093039340094508598794871);
/// ```
#[inline(always)]
pub fn hash128_with_seed<T: AsRef<[u8]>>(v: T, seed: Seed) -> u128 {
    Hash128::hash_with_seed(v, seed)
}

/// An implementation of `std::hash::Hasher`.
///
/// # Example
///
/// ```
/// use std::hash::Hasher;
/// use std::io::Cursor;
///
/// use fasthash::{highway, FastHash};
///
/// assert_eq!(highway::Hash64::hash_with_seed("hello world", [1, 2, 3, 4]), 6273970844710122614);
/// ```
#[derive(Clone)]
pub struct Hash64;

impl FastHash for Hash64 {
    type Hash = u64;
    type Seed = Seed;

    #[inline(always)]
    fn hash_with_seed<T: AsRef<[u8]>>(bytes: T, seed: Self::Seed) -> Self::Hash {
        let bytes = bytes.as_ref();

        unsafe {
            ffi::HighwayHash64(
                seed.as_ptr() as *mut _,
                bytes.as_ptr() as *const _,
                bytes.len() as u64,
            )
        }
    }
}

impl_hasher!(
    #[doc = r#"
# Example

```
use std::hash::Hasher;

use fasthash::{highway::Hasher64, FastHasher};

let mut h = Hasher64::new();

h.write(b"hello");
assert_eq!(h.finish(), 16088634173958985784);

h.write(b"world");
assert_eq!(h.finish(), 14621305948273251148);
```
"#]
    Hasher64,
    Hash64
);

/// An implementation of `std::hash::Hasher`.
///
/// # Example
///
/// ```
/// use std::hash::Hasher;
/// use std::io::Cursor;
///
/// use fasthash::{highway, FastHash};
///
/// assert_eq!(highway::Hash128::hash_with_seed("hello world", [1, 2, 3, 4]), 70726204502586093039340094508598794871);
/// ```
#[derive(Clone)]
pub struct Hash128;

impl FastHash for Hash128 {
    type Hash = u128;
    type Seed = Seed;

    #[inline(always)]
    fn hash_with_seed<T: AsRef<[u8]>>(bytes: T, seed: Self::Seed) -> Self::Hash {
        let bytes = bytes.as_ref();
        let mut hash: ffi::HHResult128 = [0; 2];

        unsafe {
            ffi::HighwayHash128(
                seed.as_ptr() as *mut _,
                bytes.as_ptr() as *const _,
                bytes.len() as u64,
                &mut hash,
            )
        }

        u128::from(hash[0]) + (u128::from(hash[1]) << 64)
    }
}

impl_hasher_ext!(
    #[doc = r#"
# Example

```
use std::hash::Hasher;

use fasthash::{highway::Hasher128, FastHasher, HasherExt};

let mut h = Hasher128::new();

h.write(b"hello");
assert_eq!(h.finish_ext(), 25004695140143629173192629076022730068);

h.write(b"world");
assert_eq!(h.finish_ext(), 11585459712122041444150834631428357454);
```
"#]
    Hasher128,
    Hash128
);
