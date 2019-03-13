//! `Murmur3`, a suite of non-cryptographic hash functions that was used for hash-based lookups.
//!
//! by Austin Appleby (aappleby (AT) gmail)
//!
//! https://sites.google.com/site/murmurhash/
//!
//! # Note
//!
//! The x86 and x64 versions do _not_ produce the same results, as the
//! algorithms are optimized for their respective platforms. You can still
//! compile and run any of them on any platform, but your performance with the
//! non-native version will be less than optimal.
//!
//! # Example
//!
//! ```
//! use std::hash::{Hash, Hasher};
//!
//! use fasthash::{murmur3, Murmur3HasherExt};
//!
//! fn hash<T: Hash>(t: &T) -> u64 {
//!     let mut s: Murmur3HasherExt = Default::default();
//!     t.hash(&mut s);
//!     s.finish()
//! }
//!
//! let h = murmur3::hash128(b"hello world\xff");
//!
//! assert_eq!(h as u64, hash(&"hello world"));
//! ```
//!
#![allow(non_camel_case_types)]
use std::os::raw::c_void;

use ffi;

use hasher::FastHash;

/// `MurmurHash3` 32-bit hash functions
///
/// # Example
///
/// ```
/// use fasthash::{murmur3::Hash32, FastHash};
///
/// assert_eq!(Hash32::hash(b"hello"), 613153351);
/// assert_eq!(Hash32::hash_with_seed(b"hello", 123), 1573043710);
/// assert_eq!(Hash32::hash(b"helloworld"), 2687965642);
/// ```
pub struct Hash32;

impl FastHash for Hash32 {
    type Hash = u32;
    type Seed = u32;

    #[inline(always)]
    fn hash_with_seed<T: AsRef<[u8]>>(bytes: T, seed: u32) -> u32 {
        unsafe {
            let mut hash = 0_u32;

            ffi::MurmurHash3_x86_32(
                bytes.as_ref().as_ptr() as *const c_void,
                bytes.as_ref().len() as i32,
                seed,
                &mut hash as *mut u32 as *mut c_void,
            );

            hash
        }
    }
}

impl_hasher!(
    #[doc = r#"
# Example

```
use std::hash::Hasher;

use fasthash::{murmur3::Hasher32, FastHasher};

let mut h = Hasher32::new();

h.write(b"hello");
assert_eq!(h.finish(), 613153351);

h.write(b"world");
assert_eq!(h.finish(), 2687965642);
```
"#]
    Hasher32,
    Hash32
);

/// `MurmurHash3` 128-bit hash functions for 32-bit processors
///
/// # Example
///
/// ```
/// use fasthash::{murmur3::Hash128_x86, FastHash};
///
/// assert_eq!(
///     Hash128_x86::hash(b"hello"),
///     205839232668418009241864179939306390688
/// );
/// assert_eq!(
///     Hash128_x86::hash_with_seed(b"hello", 123),
///     39646137218600763345533167485429249129
/// );
/// assert_eq!(
///     Hash128_x86::hash(b"helloworld"),
///     83212725615010754952022132390053357814
/// );
/// ```
pub struct Hash128_x86;

impl FastHash for Hash128_x86 {
    type Hash = u128;
    type Seed = u32;

    #[inline(always)]
    fn hash_with_seed<T: AsRef<[u8]>>(bytes: T, seed: u32) -> u128 {
        unsafe {
            let mut hash = 0;

            ffi::MurmurHash3_x86_128(
                bytes.as_ref().as_ptr() as *const c_void,
                bytes.as_ref().len() as i32,
                seed,
                &mut hash as *mut u128 as *mut c_void,
            );

            hash
        }
    }
}

impl_hasher_ext!(
    #[doc = r#"
# Example

```
use std::hash::Hasher;

use fasthash::{murmur3::Hasher128_x86, FastHasher, HasherExt};

let mut h = Hasher128_x86::new();

h.write(b"hello");
assert_eq!(h.finish_ext(), 205839232668418009241864179939306390688);

h.write(b"world");
assert_eq!(h.finish_ext(), 83212725615010754952022132390053357814);
```
"#]
    Hasher128_x86,
    Hash128_x86
);

/// `MurmurHash3` 128-bit hash functions for 64-bit processors
///
/// # Example
///
/// ```
/// use fasthash::{murmur3::Hash128_x64, FastHash};
///
/// assert_eq!(
///     Hash128_x64::hash(b"hello"),
///     121118445609844952839898260755277781762
/// );
/// assert_eq!(
///     Hash128_x64::hash_with_seed(b"hello", 123),
///     19243349499071459060235768594146641163
/// );
/// assert_eq!(
///     Hash128_x64::hash(b"helloworld"),
///     216280293825344914020777844322685271162
/// );
/// ```
pub struct Hash128_x64;

impl FastHash for Hash128_x64 {
    type Hash = u128;
    type Seed = u32;

    #[inline(always)]
    fn hash_with_seed<T: AsRef<[u8]>>(bytes: T, seed: u32) -> u128 {
        unsafe {
            let mut hash = 0;

            ffi::MurmurHash3_x64_128(
                bytes.as_ref().as_ptr() as *const c_void,
                bytes.as_ref().len() as i32,
                seed,
                &mut hash as *mut u128 as *mut c_void,
            );

            hash
        }
    }
}

impl_hasher_ext!(
    #[doc = r#"
# Example

```
use std::hash::Hasher;

use fasthash::{murmur3::Hasher128_x64, FastHasher, HasherExt};

let mut h = Hasher128_x64::new();

h.write(b"hello");
assert_eq!(h.finish_ext(), 121118445609844952839898260755277781762);

h.write(b"world");
assert_eq!(h.finish_ext(), 216280293825344914020777844322685271162);
```
"#]
    Hasher128_x64,
    Hash128_x64
);

/// `MurmurHash3` 32-bit hash functions for a byte array.
#[inline(always)]
pub fn hash32<T: AsRef<[u8]>>(v: T) -> u32 {
    Hash32::hash(v)
}

/// `MurmurHash3` 32-bit hash functions for a byte array.
/// For convenience, a 32-bit seed is also hashed into the result.
#[inline(always)]
pub fn hash32_with_seed<T: AsRef<[u8]>>(v: T, seed: u32) -> u32 {
    Hash32::hash_with_seed(v, seed)
}

/// `MurmurHash3` 128-bit hash functions for a byte array.
#[inline(always)]
pub fn hash128<T: AsRef<[u8]>>(v: T) -> u128 {
    if cfg!(target_pointer_width = "64") {
        Hash128_x64::hash(v)
    } else {
        Hash128_x86::hash(v)
    }
}

/// `MurmurHash3` 128-bit hash functions for a byte array.
/// For convenience, a 32-bit seed is also hashed into the result.
#[inline(always)]
pub fn hash128_with_seed<T: AsRef<[u8]>>(v: T, seed: u32) -> u128 {
    if cfg!(target_pointer_width = "64") {
        Hash128_x64::hash_with_seed(v, seed)
    } else {
        Hash128_x86::hash_with_seed(v, seed)
    }
}
