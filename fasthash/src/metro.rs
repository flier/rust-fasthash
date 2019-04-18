//! `MetroHash`, Exceptionally fast and statistically robust hash functions
//!
//! by J. Andrew Rogers
//!
//! https://github.com/jandrewrogers/metrohash
//!
//! `MetroHash` is a set of state-of-the-art hash functions for non-cryptographic use cases.
//! They are notable for being algorithmically generated in addition to their exceptional
//! performance. The set of published hash functions may be expanded in the future,
//! having been selected from a very large set of hash functions that have been
//! constructed this way.
//!
//! Fastest general-purpose functions for bulk hashing.
//! Fastest general-purpose functions for small, variable length keys.
//! Robust statistical bias profile, similar to the MD5 cryptographic hash.
//! Hashes can be constructed incrementally (new)
//! 64-bit, 128-bit, and 128-bit CRC variants currently available.
//! Optimized for modern x86-64 microarchitectures.
//! Elegant, compact, readable functions.
//!
//! You can read more about the design and history
//! [here](http://www.jandrewrogers.com/2015/05/27/metrohash/).
//!
//! # Example
//!
//! ```
//! use std::hash::{Hash, Hasher};
//!
//! use fasthash::{metro, MetroHasher};
//!
//! fn hash<T: Hash>(t: &T) -> u64 {
//!     let mut s: MetroHasher = Default::default();
//!     t.hash(&mut s);
//!     s.finish()
//! }
//!
//! let h = metro::hash64(b"hello world\xff");
//!
//! assert_eq!(h, hash(&"hello world"));
//! ```
//!
#![allow(non_camel_case_types)]

use crate::ffi;

use crate::hasher::FastHash;

/// `MetroHash` 64-bit hash functions
///
/// # Example
///
/// ```
/// use fasthash::{metro::Hash64_1, FastHash};
///
/// assert_eq!(Hash64_1::hash(b"hello"), 15663805623366682943);
/// assert_eq!(Hash64_1::hash_with_seed(b"hello", 123), 1128464039211059189);
/// assert_eq!(Hash64_1::hash(b"helloworld"), 4615394705531318333);
/// ```
#[derive(Clone)]
pub struct Hash64_1;

impl FastHash for Hash64_1 {
    type Hash = u64;
    type Seed = u32;

    #[inline(always)]
    fn hash_with_seed<T: AsRef<[u8]>>(bytes: T, seed: u32) -> u64 {
        let mut hash = 0_u64;

        unsafe {
            ffi::metrohash64_1(
                bytes.as_ref().as_ptr() as *const u8,
                bytes.as_ref().len() as u64,
                seed,
                &mut hash as *mut u64 as *mut u8,
            );
        }

        hash
    }
}

impl_hasher!(
    #[doc = r#"
# Example

```
use std::hash::Hasher;

use fasthash::{metro::Hasher64_1, FastHasher};

let mut h = Hasher64_1::new();

h.write(b"hello");
assert_eq!(h.finish(), 15663805623366682943);

h.write(b"world");
assert_eq!(h.finish(), 4615394705531318333);
```
"#]
    Hasher64_1,
    Hash64_1
);

/// `MetroHash` 64-bit hash functions
///
/// # Example
///
/// ```
/// use fasthash::{metro::Hash64_2, FastHash};
///
/// assert_eq!(Hash64_2::hash(b"hello"), 12352443828090181231);
/// assert_eq!(Hash64_2::hash_with_seed(b"hello", 123), 5558499743061241201);
/// assert_eq!(Hash64_2::hash(b"helloworld"), 13816693401637061492);
/// ```
#[derive(Clone)]
pub struct Hash64_2;

impl FastHash for Hash64_2 {
    type Hash = u64;
    type Seed = u32;

    #[inline(always)]
    fn hash_with_seed<T: AsRef<[u8]>>(bytes: T, seed: u32) -> u64 {
        let mut hash = 0_u64;

        unsafe {
            ffi::metrohash64_2(
                bytes.as_ref().as_ptr() as *const u8,
                bytes.as_ref().len() as u64,
                seed,
                &mut hash as *mut u64 as *mut u8,
            );
        }

        hash
    }
}

impl_hasher!(
    #[doc = r#"
# Example

```
use std::hash::Hasher;

use fasthash::{metro::Hasher64_2, FastHasher};

let mut h = Hasher64_2::new();

h.write(b"hello");
assert_eq!(h.finish(), 12352443828090181231);

h.write(b"world");
assert_eq!(h.finish(), 13816693401637061492);
```
"#]
    Hasher64_2,
    Hash64_2
);

/// `MetroHash` 128-bit hash functions
///
/// # Example
///
/// ```
/// use fasthash::{metro::Hash128_1, FastHash};
///
/// assert_eq!(
///     Hash128_1::hash(b"hello"),
///     62770881785623818170589043281119530380
/// );
/// assert_eq!(
///     Hash128_1::hash_with_seed(b"hello", 123),
///     236398782770453314983179012253900189052
/// );
/// assert_eq!(
///     Hash128_1::hash(b"helloworld"),
///     168124756093089300765778527570074281113
/// );
/// ```
#[derive(Clone)]
pub struct Hash128_1;

impl FastHash for Hash128_1 {
    type Hash = u128;
    type Seed = u32;

    #[inline(always)]
    fn hash_with_seed<T: AsRef<[u8]>>(bytes: T, seed: u32) -> u128 {
        let mut hash = 0;

        unsafe {
            ffi::metrohash128_1(
                bytes.as_ref().as_ptr() as *const u8,
                bytes.as_ref().len() as u64,
                seed,
                &mut hash as *mut u128 as *mut u8,
            );
        }

        hash
    }
}

impl_hasher_ext!(
    #[doc = r#"
# Example

```
use std::hash::Hasher;

use fasthash::{metro::Hasher128_1, FastHasher, HasherExt};

let mut h = Hasher128_1::new();

h.write(b"hello");
assert_eq!(h.finish_ext(), 62770881785623818170589043281119530380);

h.write(b"world");
assert_eq!(h.finish_ext(), 168124756093089300765778527570074281113);
```
"#]
    Hasher128_1,
    Hash128_1
);

/// `MetroHash` 128-bit hash functions
///
/// # Example
///
/// ```
/// use fasthash::{metro::Hash128_2, FastHash};
///
/// assert_eq!(
///     Hash128_2::hash(b"hello"),
///     159488125173835797791070285137966695505
/// );
/// assert_eq!(
///     Hash128_2::hash_with_seed(b"hello", 123),
///     337702340004473994826279129255403855211
/// );
/// assert_eq!(
///     Hash128_2::hash(b"helloworld"),
///     296295343271043311657399689121923046467
/// );
/// ```
#[derive(Clone)]
pub struct Hash128_2;

impl FastHash for Hash128_2 {
    type Hash = u128;
    type Seed = u32;

    #[inline(always)]
    fn hash_with_seed<T: AsRef<[u8]>>(bytes: T, seed: u32) -> u128 {
        let mut hash = 0;

        unsafe {
            ffi::metrohash128_2(
                bytes.as_ref().as_ptr() as *const u8,
                bytes.as_ref().len() as u64,
                seed,
                &mut hash as *mut u128 as *mut u8,
            );
        }

        hash
    }
}

impl_hasher_ext!(
    #[doc = r#"
# Example

```
use std::hash::Hasher;

use fasthash::{metro::Hasher128_2, FastHasher, HasherExt};

let mut h = Hasher128_2::new();

h.write(b"hello");
assert_eq!(h.finish_ext(), 159488125173835797791070285137966695505);

h.write(b"world");
assert_eq!(h.finish_ext(), 296295343271043311657399689121923046467);
```
"#]
    Hasher128_2,
    Hash128_2
);

/// hash functions using HW CRC instruction.
#[cfg(any(feature = "sse42", target_feature = "sse4.2"))]
pub mod crc {
    use crate::FastHash;

    /// `MetroHash` 64-bit hash functions using HW CRC instruction.
    ///
    /// # Example
    ///
    /// ```
    /// use fasthash::{metro::crc::Hash64_1, FastHash};
    ///
    /// assert_eq!(Hash64_1::hash(b"hello"), 6455825309044375053);
    /// assert_eq!(
    ///     Hash64_1::hash_with_seed(b"hello", 123),
    ///     18102990158604115936
    /// );
    /// assert_eq!(Hash64_1::hash(b"helloworld"), 15512397028293617890);
    /// ```
    #[derive(Clone)]
    pub struct Hash64_1;

    impl FastHash for Hash64_1 {
        type Hash = u64;
        type Seed = u32;

        #[inline(always)]
        fn hash_with_seed<T: AsRef<[u8]>>(bytes: T, seed: u32) -> u64 {
            let mut hash = 0_u64;

            unsafe {
                ffi::metrohash64crc_1(
                    bytes.as_ref().as_ptr() as *const u8,
                    bytes.as_ref().len() as u64,
                    seed,
                    &mut hash as *mut u64 as *mut u8,
                );
            }

            hash
        }
    }

    impl_hasher!(
        #[doc = r#"
# Example

```
use std::hash::Hasher;

use fasthash::{metro::crc::Hasher64_1, FastHasher};

let mut h = Hasher64_1::new();

h.write(b"hello");
assert_eq!(h.finish(), 6455825309044375053);

h.write(b"world");
assert_eq!(h.finish(), 15512397028293617890);
```
"#]
        Hasher64_1,
        Hash64_1
    );

    /// `MetroHash` 64-bit hash functions using HW CRC instruction.
    ///
    /// # Example
    ///
    /// ```
    /// use fasthash::{metro::crc::Hash64_2, FastHash};
    ///
    /// assert_eq!(Hash64_2::hash(b"hello"), 6093890398749886132);
    /// assert_eq!(
    ///     Hash64_2::hash_with_seed(b"hello", 123),
    ///     14600198876970659356
    /// );
    /// assert_eq!(Hash64_2::hash(b"helloworld"), 11309399771810154329);
    /// ```
    #[derive(Clone)]
    pub struct Hash64_2;

    impl FastHash for Hash64_2 {
        type Hash = u64;
        type Seed = u32;

        #[inline(always)]
        fn hash_with_seed<T: AsRef<[u8]>>(bytes: T, seed: u32) -> u64 {
            let mut hash = 0_u64;

            unsafe {
                ffi::metrohash64crc_2(
                    bytes.as_ref().as_ptr() as *const u8,
                    bytes.as_ref().len() as u64,
                    seed,
                    &mut hash as *mut u64 as *mut u8,
                );
            }

            hash
        }
    }

    impl_hasher!(
        #[doc = r#"
# Example

```
use std::hash::Hasher;

use fasthash::{metro::crc::Hasher64_2, FastHasher};

let mut h = Hasher64_2::new();

h.write(b"hello");
assert_eq!(h.finish(), 6093890398749886132);

h.write(b"world");
assert_eq!(h.finish(), 11309399771810154329);
```
"#]
        Hasher64_2,
        Hash64_2
    );

    /// `MetroHash` 128-bit hash functions using HW CRC instruction.
    ///
    /// # Example
    ///
    /// ```
    /// use fasthash::{metro::crc::Hash128_1, FastHash};
    ///
    /// assert_eq!(
    ///     Hash128_1::hash(b"hello"),
    ///     305698986830952061993175238670398112766
    /// );
    /// assert_eq!(
    ///     Hash128_1::hash_with_seed(b"hello", 123),
    ///     40960144468149132188388779584576370723
    /// );
    /// assert_eq!(
    ///     Hash128_1::hash(b"helloworld"),
    ///     330807979290440384643858402038145360287
    /// );
    /// ```
    #[derive(Clone)]
    pub struct Hash128_1;

    impl FastHash for Hash128_1 {
        type Hash = u128;
        type Seed = u32;

        #[inline(always)]
        fn hash_with_seed<T: AsRef<[u8]>>(bytes: T, seed: u32) -> u128 {
            let mut hash = 0;

            unsafe {
                ffi::metrohash128crc_1(
                    bytes.as_ref().as_ptr() as *const u8,
                    bytes.as_ref().len() as u64,
                    seed,
                    &mut hash as *mut u128 as *mut u8,
                );
            }

            hash
        }
    }

    impl_hasher_ext!(
        #[doc = r#"
# Example

```
use std::hash::Hasher;

use fasthash::{metro::crc::Hasher128_1, FastHasher, HasherExt};

let mut h = Hasher128_1::new();

h.write(b"hello");
assert_eq!(h.finish_ext(), 305698986830952061993175238670398112766);

h.write(b"world");
assert_eq!(h.finish_ext(), 330807979290440384643858402038145360287);
```
"#]
        Hasher128_1,
        Hash128_1
    );

    /// `MetroHash` 128-bit hash functions using HW CRC instruction.
    ///
    /// # Example
    ///
    /// ```
    /// use fasthash::{metro::crc::Hash128_2, FastHash};
    ///
    /// assert_eq!(
    ///     Hash128_2::hash(b"hello"),
    ///     72185604606880289212099011688929773703
    /// );
    /// assert_eq!(
    ///     Hash128_2::hash_with_seed(b"hello", 123),
    ///     306081561649455538136824300998603678168
    /// );
    /// assert_eq!(
    ///     Hash128_2::hash(b"helloworld"),
    ///     332348429832512530891646387991260171468
    /// );
    /// ```
    #[derive(Clone)]
    pub struct Hash128_2;

    impl FastHash for Hash128_2 {
        type Hash = u128;
        type Seed = u32;

        #[inline(always)]
        fn hash_with_seed<T: AsRef<[u8]>>(bytes: T, seed: u32) -> u128 {
            let mut hash = 0;

            unsafe {
                ffi::metrohash128crc_2(
                    bytes.as_ref().as_ptr() as *const u8,
                    bytes.as_ref().len() as u64,
                    seed,
                    &mut hash as *mut u128 as *mut u8,
                );
            }

            hash
        }
    }

    impl_hasher_ext!(
        #[doc = r#"
# Example

```
use std::hash::Hasher;

use fasthash::{metro::crc::Hasher128_2, FastHasher, HasherExt};

let mut h = Hasher128_2::new();

h.write(b"hello");
assert_eq!(h.finish_ext(), 72185604606880289212099011688929773703);

h.write(b"world");
assert_eq!(h.finish_ext(), 332348429832512530891646387991260171468);
```
"#]
        Hasher128_2,
        Hash128_2
    );
}

cfg_if! {
    if #[cfg(any(feature = "sse42", target_feature = "sse4.2"))] {
        /// `MetroHash` 64-bit hash function for a byte array using HW CRC instruction.
        #[inline(always)]
        pub fn hash64<T: AsRef<[u8]>>(v: T) -> u64 {
            crc::Hash64_1::hash(v)
        }

        /// `MetroHash` 64-bit hash function for a byte array using HW CRC instruction.
        /// For convenience, a 64-bit seed is also hashed into the result.
        #[inline(always)]
        pub fn hash64_with_seed<T: AsRef<[u8]>>(v: T, seed: u32) -> u64 {
            crc::Hash64_1::hash_with_seed(v, seed)
        }

        /// `MetroHash` 128-bit hash function for a byte array using HW CRC instruction.
        #[inline(always)]
        pub fn hash128<T: AsRef<[u8]>>(v: T) -> u128 {
            crc::Hash128_1::hash(v)
        }

        /// `MetroHash` 128-bit hash function for a byte array. using HW CRC instruction.
        /// For convenience, a 128-bit seed is also hashed into the result.
        #[inline(always)]
        pub fn hash128_with_seed<T: AsRef<[u8]>>(v: T, seed: u32) -> u128 {
            crc::Hash128_1::hash_with_seed(v, seed)
        }
    } else {
        /// `MetroHash` 64-bit hash function for a byte array.
        #[inline(always)]
        pub fn hash64<T: AsRef<[u8]>>(v: T) -> u64 {
            Hash64_1::hash(v)
        }

        /// `MetroHash` 64-bit hash function for a byte array.
        /// For convenience, a 64-bit seed is also hashed into the result.
        #[inline(always)]
        pub fn hash64_with_seed<T: AsRef<[u8]>>(v: T, seed: u32) -> u64 {
            Hash64_1::hash_with_seed(v, seed)
        }

        /// `MetroHash` 128-bit hash function for a byte array.
        #[inline(always)]
        pub fn hash128<T: AsRef<[u8]>>(v: T) -> u128 {
            Hash128_1::hash(v)
        }

        /// `MetroHash` 128-bit hash function for a byte array.
        /// For convenience, a 128-bit seed is also hashed into the result.
        #[inline(always)]
        pub fn hash128_with_seed<T: AsRef<[u8]>>(v: T, seed: u32) -> u128 {
            Hash128_1::hash_with_seed(v, seed)
        }
    }
}
