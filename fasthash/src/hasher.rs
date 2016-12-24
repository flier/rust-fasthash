use std::mem;

use std::hash::Hasher;

use extprim::i128::i128;
use extprim::u128::u128;

#[doc(hidden)]
pub trait FastHash {
    type Value;
    type Seed: Default;

    fn hash_with_seed<T: AsRef<[u8]>>(bytes: &T, seed: Self::Seed) -> Self::Value;

    fn hash<T: AsRef<[u8]>>(bytes: &T) -> Self::Value {
        Self::hash_with_seed(bytes, Default::default())
    }
}

/// A trait which represents the ability to hash an arbitrary stream of bytes.
pub trait HasherExt: Hasher {
    /// Completes a round of hashing, producing the output hash generated.
    fn finish_ext(&self) -> u128;

    /// Writes a single `u128` into this hasher.
    #[inline]
    fn write_u128(&mut self, i: u128) {
        self.write(&unsafe { mem::transmute::<_, [u8; 16]>(i) })
    }

    /// Writes a single `i128` into this hasher.
    #[inline]
    fn write_i128(&mut self, i: i128) {
        self.write_u128(i.as_u128())
    }
}

#[doc(hidden)]
#[macro_export]
macro_rules! impl_hasher {
    ($hasher:ident, $hash:ident) => (
        #[derive(Default, Clone)]
        pub struct $hasher {
            seed: Option<<$hash as $crate::hasher::FastHash>::Seed>,
            bytes: Vec<u8>,
        }

        impl $hasher {
            #[inline]
            pub fn new() -> Self {
                $hasher {
                    seed: None,
                    bytes: Vec::with_capacity(16),
                }
            }

            #[inline]
            pub fn with_seed(seed: <$hash as $crate::hasher::FastHash>::Seed) -> Self {
                $hasher {
                    seed: Some(seed),
                    bytes: Vec::with_capacity(16),
                }
            }
        }

        impl ::std::hash::Hasher for $hasher {
            #[inline]
            fn finish(&self) -> u64 {
                self.seed.map_or_else(
                    || $hash::hash(&self.bytes),
                    |seed| $hash::hash_with_seed(&self.bytes, seed)).into()
            }
            #[inline]
            fn write(&mut self, bytes: &[u8]) {
                self.bytes.extend_from_slice(bytes)
            }
        }
    )
}

#[doc(hidden)]
#[macro_export]
macro_rules! impl_hasher_ext {
    ($hasher:ident, $hash:ident) => (
        #[derive(Default, Clone)]
        pub struct $hasher {
            seed: Option<<$hash as $crate::hasher::FastHash>::Seed>,
            bytes: Vec<u8>,
        }

        impl $hasher {
            #[inline]
            pub fn new() -> Self {
                $hasher {
                    seed: None,
                    bytes: Vec::with_capacity(16),
                }
            }

            #[inline]
            pub fn with_seed(seed: <$hash as $crate::hasher::FastHash>::Seed) -> Self {
                $hasher {
                    seed: Some(seed),
                    bytes: Vec::with_capacity(16),
                }
            }

            #[inline]
            fn _final(&self) -> u128 {
                self.seed.map_or_else(
                    || $hash::hash(&self.bytes),
                    |seed| $hash::hash_with_seed(&self.bytes, seed))
            }
        }

        impl ::std::hash::Hasher for $hasher {
            #[inline]
            fn finish(&self) -> u64 {
                self._final().low64()
            }
            #[inline]
            fn write(&mut self, bytes: &[u8]) {
                self.bytes.extend_from_slice(bytes)
            }
        }

        impl $crate::hasher::HasherExt for $hasher {
            #[inline]
            fn finish_ext(&self) -> u128 {
                self._final()
            }
        }
    )
}
