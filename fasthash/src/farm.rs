//! `FarmHash`, a family of hash functions.
//!
//! by Geoff Pike
//!
//! https://github.com/google/farmhash
//!
//! Introduction
//! ============
//!
//! `FarmHash` provides hash functions for strings and other data.  The functions
//! mix the input bits thoroughly but are not suitable for cryptography.  See
//! "Hash Quality," below, for details on how `FarmHash` was tested and so on.
//!
//! We provide reference implementations in C++, with a friendly MIT license.
//!
//! All members of the `FarmHash` family were designed with heavy reliance on
//! previous work by Jyrki Alakuijala, Austin Appleby, Bob Jenkins, and others.
//!
//!
//! Recommended Usage
//! =================
//!
//! Our belief is that the typical hash function is mostly used for in-memory hash
//! tables and similar.  That use case allows hash functions that differ on
//! different platforms, and that change from time to time.  For this, I recommend
//! using wrapper functions in a .h file with comments such as, "may change from
//! time to time, may differ on different platforms, and may change depending on
//! NDEBUG."
//!
//! Some projects may also require a forever-fixed, portable hash function.  Again
//! we recommend using wrapper functions in a .h, but in this case the comments on
//! them would be very different.
//!
//! We have provided a sample of these wrapper functions in src/farmhash.h.  Our
//! hope is that most people will need nothing more than src/farmhash.h and
//! src/farmhash.cc.  Those two files are a usable and relatively portable library.
//! (One portability snag: if your compiler doesn't have `__builtin_expect` then
//! you may need to define `FARMHASH_NO_BUILTIN_EXPECT`.)  For those that prefer
//! using a configure script (perhaps because they want to "make install" later),
//! `FarmHash` has one, but for many people it's best to ignore it.
//!
//! Note that the wrapper functions such as Hash() in src/farmhash.h can select
//! one of several hash functions.  The selection is done at compile time, based
//! on your machine architecture (e.g., `sizeof(size_t)`) and the availability of
//! vector instructions (e.g., SSE4.1).
//!
//! To get the best performance from `FarmHash`, one will need to think a bit about
//! when to use compiler flags that allow vector instructions and such: -maes,
//! -msse4.2, -mavx, etc., or their equivalents for other compilers.  Those are
//! the g++ flags that make g++ emit more types of machine instructions than it
//! otherwise would.  For example, if you are confident that you will only be
//! using `FarmHash` on systems with SSE4.2 and/or AES, you may communicate that to
//! the compiler as explained in src/farmhash.cc.  If not, use -maes, -mavx, etc.,
//! when you can, and the appropriate choices will be made by via conditional
//! compilation in src/farmhash.cc.
//!
//! It may be beneficial to try -O3 or other compiler flags as well.  I also have
//! found feedback-directed optimization (FDO) to improve the speed of `FarmHash`.
//!
//! Further Details
//! ===============
//!
//! The above instructions will produce a single source-level library that
//! includes multiple hash functions.  It will use conditional compilation, and
//! perhaps GCC's multiversioning, to select among the functions.  In addition,
//! "make all check" will create an object file using your chosen compiler, and
//! test it.  The object file won't necessarily contain all the code that would be
//! used if you were to compile the code on other platforms.  The downside of this
//! is obvious: the paths not tested may not actually work if and when you try
//! them.  The `FarmHash` developers try hard to prevent such problems; please let
//! us know if you find bugs.
//!
//! To aid your cross-platform testing, for each relevant platform you may
//! compile your program that uses farmhash.cc with the preprocessor flag
//! FARMHASHSELFTEST equal to 1.  This causes a `FarmHash` self test to run
//! at program startup; the self test writes output to stdout and then
//! calls `std::exit()`.  You can see this in action by running "make check":
//! see src/farm-test.cc for details.
//!
//! There's also a trivial workaround to force particular functions to be used:
//! modify the wrapper functions in hash.h.  You can prevent choices being made via
//! conditional compilation or multiversioning by choosing `FarmHash` variants with
//! names like `farmhashaa::Hash32`, `farmhashab::Hash64`, etc.: those compute the same
//! hash function regardless of conditional compilation, multiversioning, or
//! endianness.  Consult their comments and ifdefs to learn their requirements: for
//! example, they are not all guaranteed to work on all platforms.
//!
//! Known Issues
//! ============
//!
//! 1) `FarmHash` was developed with little-endian architectures in mind.  It should
//! work on big-endian too, but less work has gone into optimizing for those
//! platforms.  To make `FarmHash` work properly on big-endian platforms you may
//! need to modify the wrapper .h file and/or your compiler flags to arrange for
//! `FARMHASH_BIG_ENDIAN` to be defined, though there is logic that tries to figure
//! it out automatically.
//!
//! 2) `FarmHash`'s implementation is fairly complex.
//!
//! 3) The techniques described in dev/INSTRUCTIONS to let hash function
//! developers regenerate src/*.cc from dev/* are hacky and not so portable.
//!
//! # Example
//!
//! ```
//! use std::hash::{Hash, Hasher};
//!
//! use fasthash::{farm, FarmHasher};
//!
//! fn hash<T: Hash>(t: &T) -> u64 {
//!     let mut s: FarmHasher = Default::default();
//!     t.hash(&mut s);
//!     s.finish()
//! }
//!
//! let h = farm::hash64(b"hello world\xff");
//!
//! assert_eq!(h, hash(&"hello world"));
//! ```
//!
use std::mem;

use ffi;

use hasher::{FastHash, Fingerprint};

/// `FarmHash` 32-bit hash functions
///
/// # Example
///
/// ```
/// use fasthash::{farm::Hash32, FastHash};
///
/// assert_eq!(Hash32::hash(b"hello"), 2535641019);
/// assert_eq!(Hash32::hash_with_seed(b"world", 123), 60914537);
/// assert_eq!(Hash32::hash(b"helloworld"), 2214725017);
/// ```
#[derive(Clone)]
pub struct Hash32;

impl FastHash for Hash32 {
    type Hash = u32;
    type Seed = u32;

    #[inline(always)]
    fn hash<T: AsRef<[u8]>>(bytes: T) -> u32 {
        unsafe { ffi::farmhash32(bytes.as_ref().as_ptr() as *const i8, bytes.as_ref().len()) }
    }

    #[inline(always)]
    fn hash_with_seed<T: AsRef<[u8]>>(bytes: T, seed: u32) -> u32 {
        unsafe {
            ffi::farmhash32_with_seed(
                bytes.as_ref().as_ptr() as *const i8,
                bytes.as_ref().len(),
                seed,
            )
        }
    }
}

impl_hasher!(
    #[doc = r#"
# Example

```
use std::hash::Hasher;

use fasthash::{farm::Hasher32, FastHasher};

let mut h = Hasher32::new();

h.write(b"hello");
assert_eq!(h.finish(), 2535641019);

h.write(b"world");
assert_eq!(h.finish(), 2214725017);
```
"#]
    Hasher32,
    Hash32
);

/// `FarmHash` 64-bit hash functions
///
/// # Example
///
/// ```
/// use fasthash::{farm::Hash64, FastHash};
///
/// assert_eq!(Hash64::hash(b"hello"), 14403600180753024522);
/// assert_eq!(
///     Hash64::hash_with_seed(b"hello", 123),
///     6856739100025169098
/// );
/// assert_eq!(
///     Hash64::hash_with_seeds(b"hello", 123, 456),
///     15077713332534145879
/// );
/// assert_eq!(Hash64::hash(b"helloworld"), 1077737941828767314);
/// ```
#[derive(Clone)]
pub struct Hash64;

impl Hash64 {
    /// Hash functions for a byte array.
    /// For convenience, seeds are also hashed into the result.
    #[inline(always)]
    pub fn hash_with_seeds<T: AsRef<[u8]>>(bytes: T, seed0: u64, seed1: u64) -> u64 {
        unsafe {
            ffi::farmhash64_with_seeds(
                bytes.as_ref().as_ptr() as *const i8,
                bytes.as_ref().len(),
                seed0,
                seed1,
            )
        }
    }
}

impl FastHash for Hash64 {
    type Hash = u64;
    type Seed = u64;

    #[inline(always)]
    fn hash<T: AsRef<[u8]>>(bytes: T) -> u64 {
        unsafe { ffi::farmhash64(bytes.as_ref().as_ptr() as *const i8, bytes.as_ref().len()) }
    }

    #[inline(always)]
    fn hash_with_seed<T: AsRef<[u8]>>(bytes: T, seed: u64) -> u64 {
        unsafe {
            ffi::farmhash64_with_seed(
                bytes.as_ref().as_ptr() as *const i8,
                bytes.as_ref().len(),
                seed,
            )
        }
    }
}

impl_hasher!(
    #[doc = r#"
# Example

```
use std::hash::Hasher;

use fasthash::{farm::Hasher64, FastHasher};

let mut h = Hasher64::new();

h.write(b"hello");
assert_eq!(h.finish(), 14403600180753024522);

h.write(b"world");
assert_eq!(h.finish(), 1077737941828767314);
```
"#]
    Hasher64,
    Hash64
);

/// `FarmHash` 128-bit hash functions
///
/// # Example
///
/// ```
/// use fasthash::{farm::Hash128, FastHash};
///
/// assert_eq!(
///     Hash128::hash(b"hello"),
///     268320354145561377850759526474794913342
/// );
/// assert_eq!(
///     Hash128::hash_with_seed(b"hello", 123),
///     280628494822616609321111119103184546347
/// );
/// assert_eq!(
///     Hash128::hash(b"helloworld"),
///     296377541162803340912737385112946231361
/// );
/// ```
#[derive(Clone)]
pub struct Hash128;

impl FastHash for Hash128 {
    type Hash = u128;
    type Seed = u128;

    #[inline(always)]
    fn hash<T: AsRef<[u8]>>(bytes: T) -> u128 {
        unsafe {
            mem::transmute(ffi::farmhash128(
                bytes.as_ref().as_ptr() as *const i8,
                bytes.as_ref().len(),
            ))
        }
    }

    #[inline(always)]
    fn hash_with_seed<T: AsRef<[u8]>>(bytes: T, seed: u128) -> u128 {
        unsafe {
            mem::transmute(ffi::farmhash128_with_seed(
                bytes.as_ref().as_ptr() as *const i8,
                bytes.as_ref().len(),
                mem::transmute(seed),
            ))
        }
    }
}

impl_hasher_ext!(
    #[doc = r#"
# Example

```
use std::hash::Hasher;

use fasthash::{farm::Hasher128, FastHasher, HasherExt};

let mut h = Hasher128::new();

h.write(b"hello");
assert_eq!(h.finish_ext(), 268320354145561377850759526474794913342);

h.write(b"world");
assert_eq!(h.finish_ext(), 296377541162803340912737385112946231361);
```
"#]
    Hasher128,
    Hash128
);

/// `FarmHash` 32-bit hash function for a byte array.
///
/// May change from time to time, may differ on different platforms, may differ depending on NDEBUG.
///
#[inline(always)]
pub fn hash32<T: AsRef<[u8]>>(v: T) -> u32 {
    Hash32::hash(v)
}

/// `FarmHash` 32-bit hash function for a byte array.
/// For convenience, a 32-bit seed is also hashed into the result.
///
/// May change from time to time, may differ on different platforms, may differ depending on NDEBUG.
///
#[inline(always)]
pub fn hash32_with_seed<T: AsRef<[u8]>>(v: T, seed: u32) -> u32 {
    Hash32::hash_with_seed(v, seed)
}

/// `FarmHash` 64-bit hash function for a byte array.
///
/// May change from time to time, may differ on different platforms, may differ depending on NDEBUG.
#[inline(always)]
pub fn hash64<T: AsRef<[u8]>>(v: T) -> u64 {
    Hash64::hash(v)
}

/// `FarmHash` 64-bit hash function for a byte array.
/// For convenience, a 64-bit seed is also hashed into the result.
///
/// May change from time to time, may differ on different platforms, may differ depending on NDEBUG.
///
#[inline(always)]
pub fn hash64_with_seed<T: AsRef<[u8]>>(v: T, seed: u64) -> u64 {
    Hash64::hash_with_seed(v, seed)
}

/// `FarmHash` 64-bit hash function for a byte array.
/// For convenience, two seeds are also hashed into the result.
///
/// May change from time to time, may differ on different platforms, may differ depending on NDEBUG.
///
pub fn hash64_with_seeds<T: AsRef<[u8]>>(v: T, seed0: u64, seed1: u64) -> u64 {
    Hash64::hash_with_seeds(v, seed0, seed1)
}

/// `FarmHash` 128-bit hash function for a byte array.
///
/// May change from time to time, may differ on different platforms, may differ depending on NDEBUG.
///
#[inline(always)]
pub fn hash128<T: AsRef<[u8]>>(v: T) -> u128 {
    Hash128::hash(v)
}

/// `FarmHash` 128-bit hash function for a byte array.
/// For convenience, a 128-bit seed is also hashed into the result.
///
/// May change from time to time, may differ on different platforms, may differ depending on NDEBUG.
///
#[inline(always)]
pub fn hash128_with_seed<T: AsRef<[u8]>>(v: T, seed: u128) -> u128 {
    Hash128::hash_with_seed(v, seed)
}

/// `FarmHash` 32-bit fingerprint function for a byte array.
///
/// # Example
///
/// ```
/// use fasthash::farm::fingerprint32;
///
/// assert_eq!(fingerprint32(b"hello word"), 4146030890);
/// ```
#[inline(always)]
pub fn fingerprint32<T: AsRef<[u8]>>(v: T) -> u32 {
    unsafe { ffi::farmhash_fingerprint32(v.as_ref().as_ptr() as *const i8, v.as_ref().len()) }
}

/// `FarmHash` 64-bit fingerprint function for a byte array.
///
/// # Example
///
/// ```
/// use fasthash::farm::fingerprint64;
///
/// assert_eq!(fingerprint64(b"hello word"), 2862784602449412590_u64);
/// ```
#[inline(always)]
pub fn fingerprint64<T: AsRef<[u8]>>(v: T) -> u64 {
    unsafe { ffi::farmhash_fingerprint64(v.as_ref().as_ptr() as *const i8, v.as_ref().len()) }
}

/// `FarmHash` 128-bit fingerprint function for a byte array.
///
/// # Example
///
/// ```
/// use fasthash::farm::fingerprint128;
///
/// assert_eq!(fingerprint128(b"hello word"), 73675844590621301084713386800078304440);
/// ```
#[inline(always)]
pub fn fingerprint128<T: AsRef<[u8]>>(v: T) -> u128 {
    unsafe {
        mem::transmute(ffi::farmhash_fingerprint128(
            v.as_ref().as_ptr() as *const i8,
            v.as_ref().len(),
        ))
    }
}

impl Fingerprint<u64> for u64 {
    #[inline(always)]
    fn fingerprint(&self) -> u64 {
        unsafe { ffi::farmhash_fingerprint_uint64(*self) }
    }
}

impl Fingerprint<u64> for u128 {
    #[inline(always)]
    fn fingerprint(&self) -> u64 {
        unsafe { ffi::farmhash_fingerprint_uint128(mem::transmute(*self)) }
    }
}

#[cfg(test)]
mod tests {
    use hasher::Fingerprint;

    #[test]
    fn test_fingerprint() {
        assert_eq!(123u64.fingerprint(), 4781265650859502840);
        assert_eq!(123u128.fingerprint(), 4011577241381678309);
    }
}
