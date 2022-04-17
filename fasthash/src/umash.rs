//! UMASH: a non-cryptographic hash function with collision bounds
//!
//! <https://github.com/backtrace-labs/umash>
//!
//! SPDX-License-Identifier: MIT
//! Copyright 2020-2022 Backtrace I/O, Inc.
//! Copyright 2022 Paul Khuong
//!
//! UMASH is a fast (9-22 ns latency for inputs of 1-64 bytes and 22
//! GB/s peak throughput, on a 2.5 GHz Intel 8175M) 64-bit hash
//! function with mathematically proven collision bounds: it is
//! [ceil(s / 4096)//! 2^{-55}]-almost-universal for inputs of s or
//! fewer bytes.
//!
//! When that's not enough, UMASH can also generate a pair of 64-bit
//! hashes in a single traversal.  The resulting fingerprint reduces
//! the collision probability to less than [ceil(s / 2^{26})^2//! 2^{-83}];
//! the probability that two distinct inputs receive the same
//! fingerprint is less 2^{-83} for inputs up to 64 MB, and less than
//! 2^{-70} as long as the inputs are shorter than 5 GB each.  This
//! expectation is taken over the randomly generated `umash_params`.
//! If an attacker can infer the contents of these parameters, the
//! bounds do not apply.
use std::hash::Hasher;
use std::mem::MaybeUninit;
use std::ptr;

use crate::{ffi, FastHash, FastHasher, HasherExt, StreamHasher};

lazy_static::lazy_static! {
    static ref UMASH_PARAMS: ffi::umash_params = {
        let mut params = MaybeUninit::zeroed();

        unsafe {
            ffi::umash_params_derive(params.as_mut_ptr(), 0, ptr::null());

            params.assume_init()
        }
    };
}

/// `umash` 64-bit hash functions
///
/// # Example
///
/// ```
/// use fasthash::{umash::Hash64, FastHash};
///
/// assert_eq!(Hash64::hash(b"hello"), 5438208324359413139);
/// assert_eq!(Hash64::hash_with_seed(b"hello", 123), 1759100371871183206);
/// assert_eq!(Hash64::hash(b"helloworld"), 14943953233150700587);
/// ```
#[derive(Clone, Default)]
pub struct Hash64;

impl FastHash for Hash64 {
    type Hash = u64;
    type Seed = u64;

    #[inline(always)]
    fn hash_with_seed<T: AsRef<[u8]>>(bytes: T, seed: u64) -> u64 {
        unsafe {
            ffi::umash_full(
                &*UMASH_PARAMS,
                seed,
                0,
                bytes.as_ref().as_ptr() as *const _,
                bytes.as_ref().len(),
            )
        }
    }
}

/// An implementation of `std::hash::Hasher`.
///
/// # Example
///
/// ```
/// use std::hash::Hasher;
///
/// use fasthash::{umash::Hasher64, FastHasher};
///
/// let mut h = Hasher64::new();
///
/// h.write(b"hello");
/// assert_eq!(h.finish(), 5438208324359413139);
///
/// h.write(b"world");
/// assert_eq!(h.finish(), 14943953233150700587);
/// ```
#[derive(Clone)]
pub struct Hasher64(ffi::umash_state);

impl Default for Hasher64 {
    fn default() -> Self {
        Self::new()
    }
}

impl Hasher for Hasher64 {
    #[inline(always)]
    fn finish(&self) -> u64 {
        unsafe { ffi::umash_digest(&self.0) }
    }

    #[inline(always)]
    fn write(&mut self, bytes: &[u8]) {
        unsafe {
            ffi::umash_sink_update(
                &mut self.0.sink as *mut _,
                bytes.as_ptr() as *const _,
                bytes.len(),
            )
        }
    }
}

impl FastHasher for Hasher64 {
    type Seed = u64;
    type Output = u64;

    #[inline(always)]
    fn with_seed(seed: Self::Seed) -> Hasher64 {
        let mut state = MaybeUninit::zeroed();

        unsafe {
            ffi::umash_init(state.as_mut_ptr(), &*UMASH_PARAMS, seed, 0);

            Hasher64(state.assume_init())
        }
    }
}

impl StreamHasher for Hasher64 {}

impl_build_hasher!(Hasher64, Hash64);
impl_digest!(Hash64, u64);

/// `umash` 128-bit hash functions
///
/// # Example
///
/// ```
/// use fasthash::{umash::Hash128, FastHash};
///
/// assert_eq!(
///     Hash128::hash(b"hello"),
///     100317237178974955349420447318060928321
/// );
/// assert_eq!(
///     Hash128::hash_with_seed(b"hello", 123),
///     32449674359875017241133207903625339377
/// );
/// assert_eq!(
///     Hash128::hash(b"helloworld"),
///     275667280741415379346614556661868569684
/// );
/// ```
#[derive(Clone, Default)]
pub struct Hash128;

impl FastHash for Hash128 {
    type Hash = u128;
    type Seed = u64;

    #[inline(always)]
    fn hash_with_seed<T: AsRef<[u8]>>(bytes: T, seed: u64) -> u128 {
        let fp = unsafe {
            ffi::umash_fprint(
                &*UMASH_PARAMS,
                seed,
                bytes.as_ref().as_ptr() as *const _,
                bytes.as_ref().len(),
            )
        };

        u128::from(fp.hash[0]).wrapping_shl(64) + u128::from(fp.hash[1])
    }
}

/// An implementation of `std::hash::Hasher` and `fasthash::HasherExt`.
///
/// # Example
///
/// ```
/// use std::hash::Hasher;
///
/// use fasthash::{umash::Hasher128, FastHasher, HasherExt};
///
/// let mut h = Hasher128::new();
///
/// h.write(b"hello");
/// assert_eq!(h.finish_ext(), 100317237178974955349420447318060928321);
///
/// h.write(b"world");
/// assert_eq!(h.finish_ext(), 275667280741415379346614556661868569684);
/// ```
#[derive(Clone)]
pub struct Hasher128(ffi::umash_fp_state);

impl Default for Hasher128 {
    fn default() -> Self {
        Self::new()
    }
}

impl Hasher for Hasher128 {
    #[inline(always)]
    fn finish(&self) -> u64 {
        self.finish_ext() as _
    }

    #[inline(always)]
    fn write(&mut self, bytes: &[u8]) {
        unsafe {
            ffi::umash_sink_update(
                &mut self.0.sink as *mut _,
                bytes.as_ptr() as *const _,
                bytes.len(),
            )
        }
    }
}

impl HasherExt for Hasher128 {
    #[inline(always)]
    fn finish_ext(&self) -> u128 {
        let fp = unsafe { ffi::umash_fp_digest(&self.0 as *const _) };

        u128::from(fp.hash[0]).wrapping_shl(64) + u128::from(fp.hash[1])
    }
}

impl FastHasher for Hasher128 {
    type Seed = u64;
    type Output = u128;

    #[inline(always)]
    fn with_seed(seed: Self::Seed) -> Hasher128 {
        let mut state = MaybeUninit::zeroed();

        unsafe {
            ffi::umash_fp_init(state.as_mut_ptr(), &*UMASH_PARAMS, seed);

            Hasher128(state.assume_init())
        }
    }
}

impl StreamHasher for Hasher128 {}

impl_build_hasher!(Hasher128, Hash128);
impl_digest!(Hash128, u128);

/// `umash` 64-bit hash functions for a byte array.
///
/// # Example
///
/// ```
/// use fasthash::umash;
///
/// assert_eq!(umash::hash64(b"hello"), 5438208324359413139);
/// ```
#[inline(always)]
pub fn hash64<T: AsRef<[u8]>>(v: T) -> u64 {
    Hash64::hash(v)
}

/// `umash` 64-bit hash functions for a byte array.
///
/// # Example
///
/// ```
/// use fasthash::umash;
///
/// assert_eq!(umash::hash64_with_seed(b"hello", 123), 1759100371871183206);
/// ```
#[inline(always)]
pub fn hash64_with_seed<T: AsRef<[u8]>>(v: T, seed: u64) -> u64 {
    Hash64::hash_with_seed(v, seed)
}

/// `umash` 128-bit hash functions for a byte array.
///
/// # Example
///
/// ```
/// use fasthash::umash;
///
/// assert_eq!(umash::hash128(b"hello"), 100317237178974955349420447318060928321);
/// ```
#[inline(always)]
pub fn hash128<T: AsRef<[u8]>>(v: T) -> u128 {
    Hash128::hash(v)
}

/// `umash` 128-bit hash functions for a byte array.
///
/// # Example
///
/// ```
/// use fasthash::umash;
///
/// assert_eq!(umash::hash128_with_seed(b"hello", 123), 32449674359875017241133207903625339377);
/// ```
#[inline(always)]
pub fn hash128_with_seed<T: AsRef<[u8]>>(v: T, seed: u64) -> u128 {
    Hash128::hash_with_seed(v, seed)
}
