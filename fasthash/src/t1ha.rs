//! Fast Positive Hash, aka "Позитивный Хэш"
//!
//! by Positive Technologies.
//!
//! <https://github.com/leo-yuriev/t1ha>
//!
//! Briefly, it is a 64-bit Hash Function:
//!
//! Created for 64-bit little-endian platforms, in predominantly for `x86_64`,
//! but without penalties could runs on any 64-bit CPU.
//! In most cases up to 15% faster than City64, xxHash, mum-hash,
//! metro-hash and all others which are not use specific hardware tricks.
//! Not suitable for cryptography.
//! Please see t1ha.c for implementation details.
//!
//! Acknowledgement:
//!
//! The t1ha was originally developed by Leonid Yuriev (Леонид Юрьев)
//! for The 1Hippeus project - zerocopy messaging in the spirit of Sparta!
//!
//! Requirements and Portability:
//!
//! t1ha designed for modern 64-bit architectures. But on the other hand,
//! t1ha doesn't uses any one tricks nor instructions specific to any particular architecture:
//! therefore t1ha could be used on any CPU for which GCC provides support 64-bit arithmetics.
//! but unfortunately t1ha could be dramatically slowly on architectures
//! without native 64-bit operations.
//! This implementation of t1ha requires modern GNU C compatible compiler,
//! includes Clang/LLVM; or MSVC++ 14.0 (Visual Studio 2015).
//!
//! # Example
//!
//! ```
//! use std::hash::{Hash, Hasher};
//!
//! use fasthash::{t1ha, T1haHasher};
//!
//! let h = t1ha::hash64(b"hello world");
//!
//! assert_eq!(h, 17676503408873599861);
//!
//! let mut s: T1haHasher = Default::default();
//! b"hello world".hash(&mut s);
//! let h = s.finish();
//!
//! assert_eq!(h, 14267663792334695945);
//! ```
//!
use crate::hasher::FastHash;

///
/// t1ha2 = 64 and 128-bit, SLIGHTLY MORE ATTENTION FOR QUALITY AND STRENGTH.
///
///    - The recommended version of "Fast Positive Hash" with good quality
///      for checksum, hash tables and fingerprinting.
///    - Portable and extremely efficiency on modern 64-bit CPUs.
///      Designed for 64-bit little-endian platforms,
///      in other cases will runs slowly.
///    - Great quality of hashing and still faster than other non-t1ha hashes.
///      Provides streaming mode and 128-bit result.
///
pub mod t1ha2 {
    use std::hash::Hasher;
    use std::mem;
    use std::ptr;

    use crate::hasher::{FastHash, FastHasher, HasherExt, StreamHasher};

    /// The at-once variant with 64-bit result
    ///
    /// # Example
    ///
    /// ```
    /// use fasthash::{FastHash, t1ha2::Hash64AtOnce};
    ///
    /// assert_eq!(
    ///     Hash64AtOnce::hash(b"hello"),
    ///     3053206065578472372
    /// );
    /// assert_eq!(
    ///     Hash64AtOnce::hash_with_seed(b"hello", 123),
    ///     14202271713409552392
    /// );
    /// assert_eq!(
    ///     Hash64AtOnce::hash(b"helloworld"),
    ///     15302361616348747620
    /// );
    /// ```
    #[derive(Clone, Default)]
    pub struct Hash64AtOnce;

    impl FastHash for Hash64AtOnce {
        type Hash = u64;
        type Seed = u64;

        #[inline(always)]
        fn hash_with_seed<T: AsRef<[u8]>>(bytes: T, seed: u64) -> u64 {
            unsafe {
                ffi::t1ha2_atonce(
                    bytes.as_ref().as_ptr() as *const _,
                    bytes.as_ref().len(),
                    seed,
                )
            }
        }
    }

    /// The at-once variant with 64-bit result
    ///
    /// # Example
    ///
    /// ```
    /// use fasthash::{FastHash, t1ha2::Hash128AtOnce};
    ///
    /// assert_eq!(
    ///     Hash128AtOnce::hash(b"hello"),
    ///     181522150951767732353014146495581994137
    /// );
    /// assert_eq!(
    ///     Hash128AtOnce::hash_with_seed(b"hello", 123),
    ///     116090820602478335969970261629923046941
    /// );
    /// assert_eq!(
    ///     Hash128AtOnce::hash(b"helloworld"),
    ///     315212713565720527393405448145758944961
    /// );
    /// ```
    #[derive(Clone, Default)]
    pub struct Hash128AtOnce;

    impl FastHash for Hash128AtOnce {
        type Hash = u128;
        type Seed = u64;

        #[inline(always)]
        fn hash_with_seed<T: AsRef<[u8]>>(bytes: T, seed: u64) -> u128 {
            let mut hi = 0;

            let lo = unsafe {
                ffi::t1ha2_atonce128(
                    &mut hi,
                    bytes.as_ref().as_ptr() as *const _,
                    bytes.as_ref().len(),
                    seed,
                )
            };

            u128::from(hi).wrapping_shl(64) + u128::from(lo)
        }
    }

    /// An `t1ha2` implementation of `std::hash::Hasher`.
    ///
    /// # Note
    ///
    /// Due performance reason 64- and 128-bit results are completely different each other,
    /// i.e. 64-bit result is NOT any part of 128-bit. */
    ///
    /// # Example
    ///
    /// ```
    /// use std::hash::Hasher;
    ///
    /// use fasthash::{t1ha2::Hasher128, FastHasher, HasherExt};
    ///
    /// let mut h = Hasher128::new();
    ///
    /// h.write(b"hello");
    /// assert_eq!(h.finish(), 11611394885310216856);
    ///
    /// h.write(b"world");
    /// assert_eq!(h.finish_ext(), 189154943715293976030023582550666960629);
    /// ```
    #[derive(Clone)]
    pub struct Hasher128(ptr::NonNull<ffi::t1ha_context_t>);

    impl Default for Hasher128 {
        fn default() -> Self {
            Self::new()
        }
    }

    impl Drop for Hasher128 {
        fn drop(&mut self) {
            unsafe { mem::drop(Box::from_raw(self.0.as_ptr())) }
        }
    }

    impl Hasher for Hasher128 {
        #[inline(always)]
        fn write(&mut self, bytes: &[u8]) {
            unsafe {
                ffi::t1ha2_update(self.0.as_ptr(), bytes.as_ptr() as *const _, bytes.len());
            }
        }

        #[inline(always)]
        fn finish(&self) -> u64 {
            unsafe { ffi::t1ha2_final(self.0.as_ptr(), ptr::null_mut()) }
        }
    }

    impl HasherExt for Hasher128 {
        fn finish_ext(&self) -> u128 {
            let mut hi = 0;
            let lo = unsafe { ffi::t1ha2_final(self.0.as_ptr(), &mut hi) };

            (u128::from(hi) << 64) + u128::from(lo)
        }
    }

    impl FastHasher for Hasher128 {
        type Seed = (u64, u64);
        type Output = u128;

        #[inline(always)]
        fn with_seed(seed: (u64, u64)) -> Self {
            unsafe {
                let ctx: ptr::NonNull<ffi::t1ha_context_t> =
                    ptr::NonNull::new_unchecked(Box::into_raw(Box::new(mem::zeroed())));

                ffi::t1ha2_init(ctx.as_ptr(), seed.0, seed.1);

                Hasher128(ctx)
            }
        }
    }

    impl StreamHasher for Hasher128 {}

    impl_build_hasher!(Hasher128, Hash64AtOnce);
    impl_build_hasher!(Hasher128, Hash128AtOnce);
}

///
/// t1ha1 = 64-bit, BASELINE FAST PORTABLE HASH:
///
///    - Runs faster on 64-bit platforms in other cases may runs slowly.
///    - Portable and stable, returns same 64-bit result
///      on all architectures and CPUs.
///    - Unfortunately it fails the "strict avalanche criteria",
///      see test results at <https://github.com/demerphq/smhasher>.
///
///      This flaw is insignificant for the t1ha1() purposes and imperceptible
///      from a practical point of view.
///      However, nowadays this issue has resolved in the next t1ha2(),
///      that was initially planned to providing a bit more quality.
///
pub mod t1ha1 {
    use crate::hasher::FastHash;

    cfg_if! {
        if #[cfg(target_endian = "little")] {
            pub use self::{Hasher64Le as Hasher64, Hash64Le as Hash64};
        } else {
            pub use self::{Hasher64Be as Hasher64, Hash64Be as Hash64};
        }
    }

    /// `T1Hash` 64-bit hash functions for 64-bit little-endian platforms.
    ///
    /// # Example
    ///
    /// ```
    /// use fasthash::{FastHash, t1ha1::Hash64Le};
    ///
    /// assert_eq!(Hash64Le::hash(b"hello"), 12810198970222070563);
    /// assert_eq!(
    ///     Hash64Le::hash_with_seed(b"hello", 123),
    ///     7105133355958514544
    /// );
    /// assert_eq!(Hash64Le::hash(b"helloworld"), 16997942636322422782);
    /// ```
    #[derive(Clone, Default)]
    pub struct Hash64Le;

    impl FastHash for Hash64Le {
        type Hash = u64;
        type Seed = u64;

        #[inline(always)]
        fn hash_with_seed<T: AsRef<[u8]>>(bytes: T, seed: u64) -> u64 {
            unsafe {
                ffi::t1ha1_le(
                    bytes.as_ref().as_ptr() as *const _,
                    bytes.as_ref().len(),
                    seed,
                )
            }
        }
    }

    trivial_hasher! {
        /// # Example
        ///
        /// ```
        /// use std::hash::Hasher;
        ///
        /// use fasthash::{t1ha1::Hasher64Le, FastHasher};
        ///
        /// let mut h = Hasher64Le::new();
        ///
        /// h.write(b"hello");
        /// assert_eq!(h.finish(), 12810198970222070563);
        ///
        /// h.write(b"world");
        /// assert_eq!(h.finish(), 16997942636322422782);
        /// ```
        Hasher64Le(Hash64Le) -> u64
    }

    /// `T1Hash` 64-bit hash functions for 64-bit big-endian platforms.
    ///
    /// # Example
    ///
    /// ```
    /// use fasthash::{FastHash, t1ha1::Hash64Be};
    ///
    /// assert_eq!(Hash64Be::hash(b"hello"), 14880640220959195744);
    /// assert_eq!(
    ///     Hash64Be::hash_with_seed(b"hello", 123),
    ///     1421069625385545216
    /// );
    /// assert_eq!(Hash64Be::hash(b"helloworld"), 15825971635414726702);
    /// ```
    #[derive(Clone, Default)]
    pub struct Hash64Be;

    impl FastHash for Hash64Be {
        type Hash = u64;
        type Seed = u64;

        #[inline(always)]
        fn hash_with_seed<T: AsRef<[u8]>>(bytes: T, seed: u64) -> u64 {
            unsafe {
                ffi::t1ha1_be(
                    bytes.as_ref().as_ptr() as *const _,
                    bytes.as_ref().len(),
                    seed,
                )
            }
        }
    }

    trivial_hasher! {
        /// # Example
        ///
        /// ```
        /// use std::hash::Hasher;
        ///
        /// use fasthash::{t1ha1::Hasher64Be, FastHasher};
        ///
        /// let mut h = Hasher64Be::new();
        ///
        /// h.write(b"hello");
        /// assert_eq!(h.finish(), 14880640220959195744);
        ///
        /// h.write(b"world");
        /// assert_eq!(h.finish(), 15825971635414726702);
        /// ```
        Hasher64Be(Hash64Be) -> u64
    }
}

///
/// t1ha0 = 64-bit, JUST ONLY FASTER:
///
///    - Provides fast-as-possible hashing for current CPU, including
///      32-bit systems and engaging the available hardware acceleration.
///    - It is a facade that selects most quick-and-dirty hash
///      for the current processor. For instance, on IA32 (x86) actual function
///      will be selected in runtime, depending on current CPU capabilities
///
pub mod t1ha0 {
    use crate::hasher::FastHash;

    lazy_static::lazy_static! {
        static ref T1HA0: ffi::t1ha0_function_t = unsafe { ffi::t1ha0_resolve() };
    }

    /// `T1Hash` 64-bit hash functions.
    ///
    /// # Example
    ///
    /// ```
    /// use fasthash::{FastHash, t1ha0::Hash64};
    ///
    /// assert_eq!(Hash64::hash(b"hello"), 3053206065578472372);
    /// assert_eq!(
    ///     Hash64::hash_with_seed(b"hello", 123),
    ///     14202271713409552392
    /// );
    /// assert_eq!(Hash64::hash(b"helloworld"), 15302361616348747620);
    /// ```
    #[derive(Clone, Default)]
    pub struct Hash64;

    impl FastHash for Hash64 {
        type Hash = u64;
        type Seed = u64;

        #[inline(always)]
        fn hash_with_seed<T: AsRef<[u8]>>(bytes: T, seed: u64) -> u64 {
            unsafe {
                T1HA0.unwrap_or(ffi::t1ha0_64)(
                    bytes.as_ref().as_ptr() as *const _,
                    bytes.as_ref().len(),
                    seed,
                )
            }
        }
    }

    trivial_hasher! {
        /// # Example
        ///
        /// ```
        /// use std::hash::Hasher;
        ///
        /// use fasthash::{t1ha0::Hasher64, FastHasher};
        ///
        /// let mut h = Hasher64::new();
        ///
        /// h.write(b"hello");
        /// assert_eq!(h.finish(), 3053206065578472372);
        ///
        /// h.write(b"world");
        /// assert_eq!(h.finish(), 15302361616348747620);
        /// ```
        Hasher64(Hash64) -> u64
    }
}

/// `T1Hash` 64-bit hash functions for a byte array.
#[inline(always)]
pub fn hash64<T: AsRef<[u8]>>(v: T) -> u64 {
    t1ha2::Hash64AtOnce::hash(v)
}

/// `T1Hash` 64-bit hash function for a byte array.
/// For convenience, a 64-bit seed is also hashed into the result.
#[inline(always)]
pub fn hash64_with_seed<T: AsRef<[u8]>>(v: T, seed: u64) -> u64 {
    t1ha2::Hash64AtOnce::hash_with_seed(v, seed)
}
