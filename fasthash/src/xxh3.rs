//! XXH3 is a new hash algorithm, featuring vastly improved speed performance for both small and large inputs.
use std::hash::Hasher;
use std::mem;
use std::ptr::NonNull;

use crate::{FastHash, FastHasher, HasherExt, StreamHasher};

/// 64-bit hash functions for a byte array.
///
/// # Example
///
/// ```
/// use fasthash::xxh3;
///
/// assert_eq!(xxh3::hash64("hello world"), 16570915807259818516);
/// ```
#[inline(always)]
pub fn hash64<T: AsRef<[u8]>>(v: T) -> u64 {
    Hash64::hash(v)
}

/// 64-bit hash function for a byte array.
/// For convenience, a 64-bit seed is also hashed into the result.
///
/// # Example
///
/// ```
/// use fasthash::xxh3;
///
/// assert_eq!(xxh3::hash64_with_seed("hello world", 123456789), 4348189770904135642);
/// ```
#[inline(always)]
pub fn hash64_with_seed<T: AsRef<[u8]>>(v: T, seed: u64) -> u64 {
    Hash64::hash_with_seed(v, seed)
}

/// 128-bit hash function for a byte array.
///
/// # Example
///
/// ```
/// use fasthash::xxh3;
///
/// assert_eq!(
///     xxh3::hash128("hello world"),
///     128288990609274964305848329913092419595,
/// );
/// ```
#[inline(always)]
pub fn hash128<T: AsRef<[u8]>>(v: T) -> u128 {
    Hash128::hash(v)
}

/// 128-bit hash function for a byte array.
///
/// For convenience, a 128-bit seed is also hashed into the result.
///
/// # Example
///
/// ```
/// use fasthash::xxh3;
///
/// assert_eq!(
///     xxh3::hash128_with_seed("hello world", 123456789),
///     112158579375068369090976928977908020817,
/// );
/// ```
#[inline(always)]
pub fn hash128_with_seed<T: AsRef<[u8]>>(v: T, seed: u64) -> u128 {
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
/// use fasthash::{xxh3::Hasher64, FastHasher, StreamHasher};
///
/// let mut h = Hasher64::new();
///
/// h.write(b"hello");
/// assert_eq!(h.finish(), 11582064415867295669);
///
/// h.write(b"world");
/// assert_eq!(h.finish(), 5799861518677282342);
/// ```
#[derive(Clone)]
pub struct Hash64;

impl FastHash for Hash64 {
    type Hash = u64;
    type Seed = u64;

    #[inline(always)]
    fn hash<T: AsRef<[u8]>>(bytes: T) -> Self::Hash {
        let bytes = bytes.as_ref();

        unsafe { ffi::XXH3_64bits(bytes.as_ptr() as *const _, bytes.len()) }
    }

    #[inline(always)]
    fn hash_with_seed<T: AsRef<[u8]>>(bytes: T, seed: Self::Seed) -> Self::Hash {
        let bytes = bytes.as_ref();

        unsafe { ffi::XXH3_64bits_withSeed(bytes.as_ptr() as *const _, bytes.len(), seed) }
    }
}

/// An implementation of `std::hash::Hasher`.
///
/// # Example
///
/// ```
/// use std::hash::Hasher;
///
/// use fasthash::{xxh3::Hasher64, FastHasher};
///
/// let mut h = Hasher64::new();
///
/// h.write(b"hello");
/// assert_eq!(h.finish(), 11582064415867295669);
///
/// h.write(b"world");
/// assert_eq!(h.finish(), 5799861518677282342);
/// ```
pub struct Hasher64(NonNull<ffi::XXH3_state_t>);

impl Default for Hasher64 {
    fn default() -> Self {
        Hasher64(unsafe { NonNull::new_unchecked(ffi::XXH3_createState()) })
    }
}

impl Clone for Hasher64 {
    fn clone(&self) -> Self {
        unsafe {
            let state = ffi::XXH3_createState();

            ffi::XXH3_copyState(state, self.0.as_ptr());

            Hasher64(NonNull::new_unchecked(state))
        }
    }
}

impl Drop for Hasher64 {
    fn drop(&mut self) {
        unsafe {
            ffi::XXH3_freeState(self.0.as_ptr());
        }
    }
}

impl Hasher for Hasher64 {
    #[inline(always)]
    fn finish(&self) -> u64 {
        unsafe { ffi::XXH3_64bits_digest(self.0.as_ptr()) }
    }

    #[inline(always)]
    fn write(&mut self, bytes: &[u8]) {
        unsafe {
            ffi::XXH3_64bits_update(self.0.as_ptr(), bytes.as_ptr() as *const _, bytes.len());
        }
    }
}

impl FastHasher for Hasher64 {
    type Seed = u64;
    type Output = u64;

    #[inline(always)]
    fn with_seed(seed: u64) -> Self {
        unsafe {
            let state = ffi::XXH3_createState();

            ffi::XXH3_64bits_reset_withSeed(state, seed);

            Hasher64(NonNull::new_unchecked(state))
        }
    }
}

impl StreamHasher for Hasher64 {}

impl_build_hasher!(Hasher64, Hash64);

/// An implementation of `std::hash::Hasher`.
///
/// # Example
///
/// ```
/// use std::hash::Hasher;
/// use std::io::Cursor;
///
/// use fasthash::{xxh3::Hasher128, FastHasher, HasherExt, StreamHasher};
///
/// let mut h = Hasher128::new();
///
/// h.write(b"hello");
/// assert_eq!(h.finish_ext(), 313673640157813024953689973667877246901);
///
/// h.write(b"world");
/// assert_eq!(h.finish_ext(), 235571704612606125258077068431826739245);
/// ```
#[derive(Clone)]
pub struct Hash128;

impl FastHash for Hash128 {
    type Hash = u128;
    type Seed = u64;

    #[inline(always)]
    fn hash<T: AsRef<[u8]>>(bytes: T) -> Self::Hash {
        let bytes = bytes.as_ref();

        unsafe { mem::transmute(ffi::XXH3_128bits(bytes.as_ptr() as *const _, bytes.len())) }
    }

    #[inline(always)]
    fn hash_with_seed<T: AsRef<[u8]>>(bytes: T, seed: Self::Seed) -> Self::Hash {
        let bytes = bytes.as_ref();

        unsafe {
            mem::transmute(ffi::XXH3_128bits_withSeed(
                bytes.as_ptr() as *const _,
                bytes.len(),
                seed,
            ))
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
/// use fasthash::{xxh3::Hasher128, FastHasher, HasherExt};
///
/// let mut h = Hasher128::new();
///
/// h.write(b"hello");
/// assert_eq!(h.finish_ext(), 313673640157813024953689973667877246901);
///
/// h.write(b"world");
/// assert_eq!(h.finish_ext(), 235571704612606125258077068431826739245);
/// ```
pub struct Hasher128(NonNull<ffi::XXH3_state_t>);

impl Default for Hasher128 {
    fn default() -> Self {
        Hasher128(unsafe { NonNull::new_unchecked(ffi::XXH3_createState()) })
    }
}

impl Clone for Hasher128 {
    fn clone(&self) -> Self {
        unsafe {
            let state = ffi::XXH3_createState();

            ffi::XXH3_copyState(state, self.0.as_ptr());

            Hasher128(NonNull::new_unchecked(state))
        }
    }
}

impl Drop for Hasher128 {
    fn drop(&mut self) {
        unsafe {
            ffi::XXH3_freeState(self.0.as_ptr());
        }
    }
}

impl Hasher for Hasher128 {
    #[inline(always)]
    fn finish(&self) -> u64 {
        unsafe { ffi::XXH3_128bits_digest(self.0.as_ptr()).low64 }
    }

    #[inline(always)]
    fn write(&mut self, bytes: &[u8]) {
        unsafe {
            ffi::XXH3_128bits_update(self.0.as_ptr(), bytes.as_ptr() as *const _, bytes.len());
        }
    }
}

impl HasherExt for Hasher128 {
    #[inline(always)]
    fn finish_ext(&self) -> u128 {
        let h = unsafe { ffi::XXH3_128bits_digest(self.0.as_ptr()) };

        u128::from(h.low64) + (u128::from(h.high64) << 64)
    }
}

impl FastHasher for Hasher128 {
    type Seed = u64;
    type Output = u128;

    #[inline(always)]
    fn with_seed(seed: u64) -> Self {
        unsafe {
            let state = ffi::XXH3_createState();

            ffi::XXH3_128bits_reset_withSeed(state, seed);

            Hasher128(NonNull::new_unchecked(state))
        }
    }
}

impl StreamHasher for Hasher128 {}

impl_build_hasher!(Hasher128, Hash128);
