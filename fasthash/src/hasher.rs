use std::mem;

use extprim::i128::i128;
use extprim::u128::u128;

pub trait FastHasher {
    type Value;
    type Seed: Default;

    fn hash_with_seed<T: AsRef<[u8]>>(bytes: &T, seed: Self::Seed) -> Self::Value;

    fn hash<T: AsRef<[u8]>>(bytes: &T) -> Self::Value {
        Self::hash_with_seed(bytes, Default::default())
    }
}

/// A trait which represents the ability to hash an arbitrary stream of bytes.
pub trait HasherExt {
    /// Completes a round of hashing, producing the output hash generated.
    fn finish(&self) -> u128;

    /// Writes some data into this `Hasher`.
    fn write(&mut self, bytes: &[u8]);

    /// Write a single `u8` into this hasher.
    #[inline]
    fn write_u8(&mut self, i: u8) {
        self.write(&[i])
    }
    /// Writes a single `u16` into this hasher.
    #[inline]
    fn write_u16(&mut self, i: u16) {
        self.write(&unsafe { mem::transmute::<_, [u8; 2]>(i) })
    }
    /// Writes a single `u32` into this hasher.
    #[inline]
    fn write_u32(&mut self, i: u32) {
        self.write(&unsafe { mem::transmute::<_, [u8; 4]>(i) })
    }
    /// Writes a single `u64` into this hasher.
    #[inline]
    fn write_u64(&mut self, i: u64) {
        self.write(&unsafe { mem::transmute::<_, [u8; 8]>(i) })
    }
    /// Writes a single `u128` into this hasher.
    #[inline]
    fn write_u128(&mut self, i: u128) {
        self.write(&unsafe { mem::transmute::<_, [u8; 16]>(i) })
    }
    /// Writes a single `usize` into this hasher.
    #[inline]
    fn write_usize(&mut self, i: usize) {
        let bytes = unsafe {
            ::std::slice::from_raw_parts(&i as *const usize as *const u8, mem::size_of::<usize>())
        };
        self.write(bytes);
    }

    /// Writes a single `i8` into this hasher.
    #[inline]
    fn write_i8(&mut self, i: i8) {
        self.write_u8(i as u8)
    }
    /// Writes a single `i16` into this hasher.
    #[inline]
    fn write_i16(&mut self, i: i16) {
        self.write_u16(i as u16)
    }
    /// Writes a single `i32` into this hasher.
    #[inline]
    fn write_i32(&mut self, i: i32) {
        self.write_u32(i as u32)
    }
    /// Writes a single `i64` into this hasher.
    #[inline]
    fn write_i64(&mut self, i: i64) {
        self.write_u64(i as u64)
    }
    /// Writes a single `i128` into this hasher.
    #[inline]
    fn write_i128(&mut self, i: i128) {
        self.write_u128(i.as_u128())
    }
    /// Writes a single `isize` into this hasher.
    #[inline]
    fn write_isize(&mut self, i: isize) {
        self.write_usize(i as usize)
    }
}

#[macro_export]
macro_rules! fasthash {
    ($hasher:ident, $hash:ident) => (
        #[derive(Default, Clone)]
        pub struct $hasher {
            seed: <$hash as $crate::hasher::FastHasher>::Seed,
            bytes: Vec<u8>,
        }

        impl $hasher {
            #[inline]
            pub fn new() -> Self {
                $hasher {
                    seed: Default::default(),
                    bytes: Vec::with_capacity(16),
                }
            }

            #[inline]
            pub fn with_seed(seed: <$hash as $crate::hasher::FastHasher>::Seed) -> Self {
                $hasher {
                    seed: seed,
                    bytes: Vec::with_capacity(16),
                }
            }
        }

        impl ::std::hash::Hasher for $hasher {
            fn finish(&self) -> u64 {
                $hash::hash_with_seed(&self.bytes, self.seed).into()
            }
            fn write(&mut self, bytes: &[u8]) {
                self.bytes.extend_from_slice(bytes)
            }
        }
    )
}

#[macro_export]
macro_rules! fasthash_ext {
    ($hasher:ident, $hash:ident) => (
        #[derive(Default, Clone)]
        pub struct $hasher {
            seed: <$hash as $crate::hasher::FastHasher>::Seed,
            bytes: Vec<u8>,
        }

        impl $hasher {
            #[inline]
            pub fn new() -> Self {
                $hasher {
                    seed: Default::default(),
                    bytes: Vec::with_capacity(16),
                }
            }

            #[inline]
            pub fn with_seed(seed: <$hash as $crate::hasher::FastHasher>::Seed) -> Self {
                $hasher {
                    seed: seed,
                    bytes: Vec::with_capacity(16),
                }
            }
        }

        impl $crate::hasher::HasherExt for $hasher {
            fn finish(&self) -> u128 {
                $hash::hash_with_seed(&self.bytes, self.seed)
            }
            fn write(&mut self, bytes: &[u8]) {
                self.bytes.extend_from_slice(bytes)
            }
        }
    )
}
