//! PRVHASH - Pseudo-Random-Value Hash
//!
//! PRVHASH is a hash function that generates a uniform pseudo-random number sequence derived from the message.
//! PRVHASH is conceptually similar (in the sense of using a pseudo-random number sequence as a hash) to keccak
//! and RadioGatun schemes, but is a completely different implementation of such concept.
//! PRVHASH is both a "randomness extractor" and an "extendable-output function" (XOF).
//!
//! PRVHASH can generate 64- to unlimited-bit hashes, yielding hashes of approximately equal quality
//! independent of the chosen hash length. PRVHASH is based on 64-bit math.
//! The use of the function beyond 1024-bit hashes is easily possible, but has to be statistically tested.
//! For example, any 32-bit element extracted from 2048-, or 4096-bit resulting hash is as collision resistant
//! as just a 32-bit hash. It is a fixed execution time hash function that depends only on message's length.
//! A streamed hashing implementation is available.
//!
//! PRVHASH is solely based on the butterfly effect, inspired by LCG pseudo-random number generators.
//! The generated hashes have good avalanche properties.
//! For best security, a random seed should be supplied to the hash function, but this is not a requirement.
//! In practice, the InitVec (instead of UseSeed), and initial hash, can both be randomly seeded
//! (see the suggestions in prvhash64.h), adding useful initial entropy (InitVec plus Hash total bits of entropy).
use std::hash;
use std::mem;
use std::ptr;

use crate::hasher::{FastHash, FastHasher, HasherExt, StreamHasher};

/// `prvhash` 64-bit hash functions
///
/// # Example
///
/// ```
/// use fasthash::{prv::Hash64, FastHash};
///
/// assert_eq!(Hash64::hash(b"hello"), 10463018639652235399);
/// assert_eq!(Hash64::hash_with_seed(b"hello", 123), 3244297802064062444);
/// assert_eq!(Hash64::hash(b"helloworld"), 5802738683617665747);
/// ```
#[derive(Clone, Default)]
pub struct Hash64;

impl FastHash for Hash64 {
    type Hash = u64;
    type Seed = u64;

    #[inline(always)]
    fn hash_with_seed<T: AsRef<[u8]>>(bytes: T, seed: u64) -> u64 {
        unsafe {
            ffi::prvhash64_64m_(
                bytes.as_ref().as_ptr() as *const _,
                bytes.as_ref().len(),
                seed,
            )
        }
    }
}

impl_build_hasher!(Hasher64, Hash64);
impl_digest!(Hasher64, u64);

/// `prvhash` 64-bit hash functions for a byte array.
///
/// # Example
///
/// ```
/// use fasthash::prv;
///
/// assert_eq!(prv::hash64(b"hello"), 10463018639652235399);
/// ```
#[inline(always)]
pub fn hash64<T: AsRef<[u8]>>(v: T) -> u64 {
    Hash64::hash(v)
}

/// `prvhash` 64-bit hash function for a byte array.
/// For convenience, a 64-bit seed is also hashed into the result.
///
/// # Example
///
/// ```
/// use fasthash::prv;
///
/// assert_eq!(prv::hash64_with_seed(b"hello", 123), 3244297802064062444);
/// ```
#[inline(always)]
pub fn hash64_with_seed<T: AsRef<[u8]>>(v: T, seed: u64) -> u64 {
    Hash64::hash_with_seed(v, seed)
}

/// An `prvhash` implementation of `std::hash::Hasher`.
///
/// # Example
///
/// ```
/// use std::hash::Hasher;
///
/// use fasthash::{prv::Hasher64, FastHasher};
///
/// let mut h = Hasher64::new();
///
/// h.write(b"hello");
/// assert_eq!(h.finish(), 10745757879812790000);
/// ```
pub type Hasher64 = Hasher<u64>;

/// An `prvhash` implementation of `std::hash::Hasher`.
///
/// # Example
///
/// ```
/// use std::hash::Hasher;
///
/// use fasthash::{prv::Hasher128, FastHasher, HasherExt};
///
/// let mut h = Hasher128::new();
///
/// h.write(b"hello");
/// assert_eq!(h.finish(), 582374857702463471);
///
/// h.write(b"world");
/// assert_eq!(h.finish_ext(), 253104439810385140536055825314052921327);
/// ```
pub type Hasher128 = Hasher<u128>;

/// An `prvhash` implementation of `std::hash::Hasher`.
///
/// # Example
///
/// ```
/// use std::hash::Hasher as _;
///
/// use fasthash::{prv::Hasher, FastHasher};
///
/// let mut h = Hasher::<u64>::new();
///
/// h.write(b"hello");
/// assert_eq!(h.finish(), 10745757879812790000);
/// ```
#[derive(Clone)]
pub struct Hasher<T> {
    ctx: ptr::NonNull<ffi::PRVHASH64S_CTX>,
    hash: ptr::NonNull<T>,
}

impl<T> Drop for Hasher<T> {
    fn drop(&mut self) {
        unsafe {
            mem::drop(Box::from_raw(self.ctx.as_ptr()));
            mem::drop(Box::from_raw(self.hash.as_ptr()));
        }
    }
}

macro_rules! impl_hasher {
    ($ty:ty) => {
        impl Default for Hasher<$ty> {
            fn default() -> Self {
                Self::new()
            }
        }

        impl hash::Hasher for Hasher<$ty> {
            #[inline(always)]
            fn write(&mut self, bytes: &[u8]) {
                unsafe {
                    ffi::prvhash64s_update_(
                        self.ctx.as_ptr(),
                        bytes.as_ptr() as *const _,
                        bytes.len(),
                    );
                }
            }

            #[inline(always)]
            fn finish(&self) -> u64 {
                unsafe {
                    ffi::prvhash64s_final_(self.ctx.as_ptr());
                    *(self.hash.as_ptr() as *const u64)
                }
            }
        }

        impl FastHasher for Hasher<$ty> {
            type Seed = [u64; 4];
            type Output = u64;

            #[inline(always)]
            fn with_seed(seed: [u64; 4]) -> Self {
                unsafe {
                    let ctx: ptr::NonNull<ffi::PRVHASH64S_CTX> =
                        ptr::NonNull::new_unchecked(Box::into_raw(Box::new(mem::zeroed())));
                    let hash: ptr::NonNull<$ty> =
                        ptr::NonNull::new_unchecked(Box::into_raw(Box::new(mem::zeroed())));

                    ffi::prvhash64s_init_(
                        ctx.as_ptr(),
                        hash.as_ptr() as *mut _,
                        mem::size_of::<$ty>(),
                        &seed[0],
                        ptr::null_mut(),
                    );

                    Hasher { ctx, hash }
                }
            }
        }

        impl StreamHasher for Hasher<$ty> {}
    };
}

impl_hasher!(u64);
impl_hasher!(u128);

impl HasherExt for Hasher128 {
    fn finish_ext(&self) -> u128 {
        unsafe {
            ffi::prvhash64s_final_(self.ctx.as_ptr());

            *self.hash.as_ref()
        }
    }
}
