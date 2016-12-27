use std::mem;
use std::io;
use std::cell::Cell;
use std::marker::PhantomData;
use std::hash::{Hasher, BuildHasher};

use rand::{Rng, OsRng};

use extprim::i128::i128;
use extprim::u128::u128;

/// Generate a good, portable, forever-fixed hash value
pub trait Fingerprint<T> {
    /// This is intended to be a good fingerprinting primitive.
    fn fingerprint(&self) -> T;
}

pub trait BuildHasherExt: BuildHasher {
    type FastHasher: FastHasher;

    fn build_hasher_with_seed(seed: &Seed) -> Self::Hasher;
}

/// Fast non-cryptographic hash functions
pub trait FastHash {
    type Value;
    type Seed: Default + Copy;

    /// Hash functions for a byte array.
    /// For convenience, a seed is also hashed into the result.
    fn hash_with_seed<T: AsRef<[u8]>>(bytes: &T, seed: Self::Seed) -> Self::Value;

    /// Hash functions for a byte array.
    fn hash<T: AsRef<[u8]>>(bytes: &T) -> Self::Value {
        Self::hash_with_seed(bytes, Default::default())
    }
}

pub trait FastHasher: Hasher
    where Self: Sized
{
    type Seed: Default + Copy;

    fn new() -> Self {
        Self::with_seed(Default::default())
    }

    fn with_seed(seed: Self::Seed) -> Self;
}

/// Hasher in the buffer mode for short key
pub trait BufHasher: Hasher + AsRef<[u8]> {
    /// Returns the number of bytes in the buffer.
    #[inline]
    fn len(&self) -> usize {
        self.as_ref().len()
    }

    /// Extracts a slice containing the entire buffer.
    #[inline]
    fn as_slice(&self) -> &[u8] {
        self.as_ref()
    }
}

/// Hasher in the streaming mode without buffer
pub trait StreamHasher: Hasher + Sized {
    /// Writes the stream into this hasher.
    fn write_stream<R: io::Read>(&mut self, r: &mut R) -> io::Result<usize> {
        let mut buf = [0_u8; 4096];
        let mut len = 0;
        let mut pos = 0;
        let ret;

        loop {
            if pos == buf.len() {
                self.write(&buf[..]);
                pos = 0;
            }

            match r.read(&mut buf[pos..]) {
                Ok(0) => {
                    ret = Ok(len);
                    break;
                }
                Ok(n) => {
                    len += n;
                    pos += n;
                }
                Err(ref e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => {
                    ret = Err(e);
                    break;
                }
            }
        }

        if pos > 0 {
            self.write(&buf[..pos])
        }

        ret
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

#[derive(Clone, Copy, Debug)]
pub struct Seed(u64, u64);

impl Seed {
    pub fn new() -> Seed {
        let mut r = OsRng::new().expect("failed to create an OS RNG");

        Seed(r.gen(), r.gen())
    }
    pub fn next(self) -> Seed {
        Seed(self.0.wrapping_add(1), self.1.wrapping_sub(1))
    }

    pub fn gen() -> Seed {
        thread_local!(static SEEDS: Cell<Seed> = Cell::new(Seed::new()));

        SEEDS.with(|seeds| {
            let seed = seeds.get();
            seeds.set(seed.next());
            seed
        })
    }
}

impl From<Seed> for u32 {
    fn from(seed: Seed) -> u32 {
        seed.0 as u32
    }
}

impl From<Seed> for u64 {
    fn from(seed: Seed) -> u64 {
        seed.0
    }
}

impl From<Seed> for u128 {
    fn from(seed: Seed) -> u128 {
        u128::from_parts(seed.1, seed.0)
    }
}

pub struct RandomState<T: FastHash + BuildHasherExt> {
    seed: Seed,
    phantom: PhantomData<T>,
}

impl<T: FastHash + BuildHasherExt> RandomState<T> {
    pub fn new() -> Self {
        RandomState {
            seed: Seed::gen(),
            phantom: PhantomData,
        }
    }
}

impl<T: FastHash + BuildHasherExt> BuildHasher for RandomState<T> {
    type Hasher = T::Hasher;

    #[inline]
    fn build_hasher(&self) -> Self::Hasher {
        <T as BuildHasherExt>::build_hasher_with_seed(&self.seed)
    }
}

impl<T: FastHash + BuildHasherExt> Default for RandomState<T> {
    fn default() -> Self {
        RandomState::new()
    }
}

#[doc(hidden)]
#[macro_export]
macro_rules! impl_hasher {
    ($(#[$attr:meta])*  $hasher:ident, $hash:ident) => (
        /// An implementation of `std::hash::Hasher`.
        #[derive(Clone)]
        pub struct $hasher {
            seed: Option<<$hash as $crate::hasher::FastHash>::Seed>,
            bytes: Vec<u8>,
        }

        impl $hasher {
        }

        impl Default for $hasher {
            fn default() -> Self {
                $hasher::new()
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

        impl $crate::hasher::FastHasher for $hasher {
            type Seed = <$hash as $crate::hasher::FastHash>::Seed;

            #[inline]
            fn new() -> Self {
                $hasher {
                    seed: None,
                    bytes: Vec::with_capacity(64),
                }
            }

            #[inline]
            fn with_seed(seed: Self::Seed) -> Self {
                $hasher {
                    seed: Some(seed),
                    bytes: Vec::with_capacity(64),
                }
            }
        }

        impl ::std::convert::AsRef<[u8]> for $hasher {
            #[inline]
            fn as_ref(&self) -> &[u8] {
                &self.bytes
            }
        }

        impl $crate::hasher::BufHasher for $hasher {}

        impl ::std::hash::BuildHasher for $hash {
            type Hasher = $hasher;

            #[inline]
            fn build_hasher(&self) -> Self::Hasher {
                $hasher::new()
            }
        }

        impl $crate::hasher::BuildHasherExt for $hash {
            type FastHasher = $hasher;

            #[inline]
            fn build_hasher_with_seed(seed: &$crate::hasher::Seed) -> Self::Hasher {
                $hasher::with_seed((*seed).into())
            }
        }
    )
}

#[doc(hidden)]
#[macro_export]
macro_rules! impl_hasher_ext {
    ($hasher:ident, $hash:ident) => (
/// An implementation of `std::hash::Hasher` and `fasthash::HasherExt`.
        #[derive(Default, Clone)]
        pub struct $hasher {
            seed: Option<<$hash as $crate::hasher::FastHash>::Seed>,
            bytes: Vec<u8>,
        }

        impl $hasher {
            #[inline]
            fn finalize(&self) -> u128 {
                self.seed.map_or_else(
                    || $hash::hash(&self.bytes),
                    |seed| $hash::hash_with_seed(&self.bytes, seed))
            }
        }

        impl ::std::hash::Hasher for $hasher {
            #[inline]
            fn finish(&self) -> u64 {
                self.finalize().low64()
            }
            #[inline]
            fn write(&mut self, bytes: &[u8]) {
                self.bytes.extend_from_slice(bytes)
            }
        }

        impl $crate::hasher::FastHasher for $hasher {
            type Seed = <$hash as $crate::hasher::FastHash>::Seed;

            #[inline]
            fn new() -> Self {
                $hasher {
                    seed: None,
                    bytes: Vec::with_capacity(64),
                }
            }

            #[inline]
            fn with_seed(seed: Self::Seed) -> Self {
                $hasher {
                    seed: Some(seed),
                    bytes: Vec::with_capacity(64),
                }
            }
        }

        impl $crate::hasher::HasherExt for $hasher {
            #[inline]
            fn finish_ext(&self) -> u128 {
                self.finalize()
            }
        }

        impl ::std::convert::AsRef<[u8]> for $hasher {
            #[inline]
            fn as_ref(&self) -> &[u8] {
                &self.bytes
            }
        }

        impl $crate::hasher::BufHasher for $hasher {}

        impl ::std::hash::BuildHasher for $hash {
            type Hasher = $hasher;

            #[inline]
            fn build_hasher(&self) -> Self::Hasher {
                $hasher::new()
            }
        }
    )
}

#[cfg(test)]
mod tests {
    use std::convert::Into;
    use std::collections::HashMap;

    use extprim::u128::u128;

    use city::*;
    use super::*;

    #[test]
    fn test_seed() {
        let mut s = Seed::new();
        let mut u0: u32 = s.into();
        let mut u1: u64 = s.into();
        let mut u2: u128 = s.into();

        assert!(u0 != 0);
        assert!(u1 != 0);
        assert!(u2 != u128::zero());
        assert_eq!(u0, u1 as u32);
        assert_eq!(u1, u2.low64());

        s = s.next();

        u1 = s.into();

        s = s.next();

        u2 = s.into();

        assert!(u0 != 0);
        assert!(u1 != 0);
        assert!(u2 != u128::zero());
        assert!(u0 as u64!= u1);
        assert!(u1 != u2.low64());
        assert!(u1 != u2.high64());

        u0 = Seed::gen().into();
        u1 = Seed::gen().into();
        u2 = Seed::gen().into();

        assert!(u0 != 0);
        assert!(u1 != 0);
        assert!(u2 != u128::zero());
        assert!(u0 as u64!= u1);
        assert!(u1 != u2.low64());
        assert!(u1 != u2.high64());
    }

    #[test]
    fn test_hashmap() {
        let s: RandomState<CityHash64> = Default::default();
        let mut map = HashMap::with_hasher(s);

        assert_eq!(map.insert(37, "a"), None);
        assert_eq!(map.is_empty(), false);

        map.insert(37, "b");
        assert_eq!(map.insert(37, "c"), Some("b"));
        assert_eq!(map[&37], "c");
    }
}
