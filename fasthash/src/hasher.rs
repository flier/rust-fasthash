use std::cell::RefCell;
use std::hash::{BuildHasher, Hasher};
use std::io;
use std::marker::PhantomData;
#[cfg(feature = "i128")]
use std::mem;

use rand::{Rand, Rng};
use xoroshiro128::{SeedableRng, Xoroshiro128Rng};

#[cfg(feature = "i128")]
use extprim::i128::i128;
use extprim::u128::u128;

/// Generate a good, portable, forever-fixed hash value
pub trait Fingerprint<T> {
    /// This is intended to be a good fingerprinting primitive.
    fn fingerprint(&self) -> T;
}

#[doc(hidden)]
pub trait BuildHasherExt: BuildHasher {
    type FastHasher: FastHasher;
}

/// Fast non-cryptographic hash functions
pub trait FastHash: BuildHasherExt {
    /// The output hash generated value.
    type Value;
    /// The seed to generate hash value.
    type Seed: Default + Copy + Rand;

    /// Hash functions for a byte array.
    /// For convenience, a seed is also hashed into the result.
    fn hash_with_seed<T: AsRef<[u8]>>(bytes: &T, seed: Self::Seed) -> Self::Value;

    /// Hash functions for a byte array.
    fn hash<T: AsRef<[u8]>>(bytes: &T) -> Self::Value {
        Self::hash_with_seed(bytes, Default::default())
    }
}

/// Fast non-cryptographic hasher
pub trait FastHasher: Hasher
where
    Self: Sized,
{
    /// The seed to generate hash value.
    type Seed: Default + Copy + From<Seed>;

    /// Constructs a new `FastHasher`.
    #[inline]
    fn new() -> Self {
        Self::with_seed(Default::default())
    }

    /// Constructs a new `FastHasher` with a random seed.
    fn new_with_random_seed() -> Self {
        Self::with_seed(Seed::gen().into())
    }

    /// Constructs a new `FastHasher` with seed.
    fn with_seed(seed: Self::Seed) -> Self;
}

/// Hasher in the buffer mode for short key
pub trait BufHasher: FastHasher + AsRef<[u8]> {
    /// Constructs a buffered hasher with capacity and seed
    fn with_capacity_and_seed(capacity: usize, seed: Option<Self::Seed>) -> Self;

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
pub trait StreamHasher: FastHasher + Sized {
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
    #[cfg(feature = "i128")]
    #[inline]
    fn write_u128(&mut self, i: u128) {
        self.write(&unsafe { mem::transmute::<_, [u8; 16]>(i) })
    }

    /// Writes a single `i128` into this hasher.
    #[cfg(feature = "i128")]
    #[inline]
    fn write_i128(&mut self, i: i128) {
        self.write_u128(i.as_u128())
    }
}

/// Generate hash seeds
///
/// It base on the same workflow from `std::collections::RandomState`
///
/// > Historically this function did not cache keys from the OS and instead
/// > simply always called `rand::thread_rng().gen()` twice. In #31356 it
/// > was discovered, however, that because we re-seed the thread-local RNG
/// > from the OS periodically that this can cause excessive slowdown when
/// > many hash maps are created on a thread. To solve this performance
/// > trap we cache the first set of randomly generated keys per-thread.
///
/// > Later in #36481 it was discovered that exposing a deterministic
/// > iteration order allows a form of DOS attack. To counter that we
/// > increment one of the seeds on every `RandomState` creation, giving
/// > every corresponding `HashMap` a different iteration order.
///
/// # Examples
///
/// ```rust
/// use fasthash::{Seed, city};
///
/// city::hash128_with_seed(b"hello world", Seed::gen().into());
/// ```
#[derive(Clone, Copy, Debug)]
pub struct Seed(Xoroshiro128Rng);

impl Seed {
    #[inline]
    fn new() -> Seed {
        Seed(Xoroshiro128Rng::new().expect("failed to create an OS RNG"))
    }

    /// Generate a new seed
    #[inline]
    pub fn gen() -> Seed {
        thread_local!(static SEEDS: RefCell<Seed> = RefCell::new(Seed::new()));

        SEEDS.with(|seeds| {
            Seed(Xoroshiro128Rng::from_seed(
                seeds.borrow_mut().0.gen::<[u64; 2]>(),
            ))
        })
    }
}

macro_rules! impl_from_seed {
    ($target:ty) => {
        impl From<Seed> for $target {
            #[inline]
            fn from(seed: Seed) -> $target {
                let mut rng = seed.0;

                rng.gen()
            }
        }
    };
}

impl_from_seed!(u32);
impl_from_seed!(u64);
impl_from_seed!(u128);
impl_from_seed!((u64, u64));
impl_from_seed!((u64, u64, u64, u64));

/// `RandomState` provides the default state for `HashMap` or `HashSet` types.
///
/// A particular instance `RandomState` will create the same instances of
/// [`Hasher`], but the hashers created by two different `RandomState`
/// instances are unlikely to produce the same result for the same values.
///
/// ```rust
/// use std::collections::HashMap;
///
/// use fasthash::RandomState;
/// use fasthash::city::CityHash64;
///
/// let s = RandomState::<CityHash64>::new();
/// let mut map = HashMap::with_hasher(s);
///
/// assert_eq!(map.insert(37, "a"), None);
/// assert_eq!(map.is_empty(), false);
///
/// map.insert(37, "b");
/// assert_eq!(map.insert(37, "c"), Some("b"));
/// assert_eq!(map[&37], "c");
/// ```
pub struct RandomState<T: FastHash> {
    seed: Seed,
    phantom: PhantomData<T>,
}

impl<T: FastHash> RandomState<T> {
    /// Constructs a new `RandomState` that is initialized with random keys.
    #[inline]
    pub fn new() -> Self {
        RandomState {
            seed: Seed::gen(),
            phantom: PhantomData,
        }
    }
}

impl<T: FastHash> BuildHasher for RandomState<T> {
    type Hasher = T::FastHasher;

    #[inline]
    fn build_hasher(&self) -> Self::Hasher {
        T::FastHasher::with_seed(self.seed.into())
    }
}

impl<T: FastHash> Default for RandomState<T> {
    #[inline]
    fn default() -> Self {
        RandomState::new()
    }
}

#[doc(hidden)]
macro_rules! impl_fasthash {
    ($hasher:ident, $hash:ident) => {
        impl ::std::hash::BuildHasher for $hash {
            type Hasher = $hasher;

            #[inline]
            fn build_hasher(&self) -> Self::Hasher {
                $hasher::new()
            }
        }

        impl $crate::hasher::BuildHasherExt for $hash {
            type FastHasher = $hasher;
        }
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! impl_hasher {
    ($hasher:ident, $hash:ident) => {
        /// An implementation of `std::hash::Hasher`.
        #[derive(Clone)]
        pub struct $hasher {
            seed: Option<<$hash as $crate::hasher::FastHash>::Seed>,
            bytes: Vec<u8>,
        }

        impl Default for $hasher {
            fn default() -> Self {
                $hasher::new()
            }
        }

        impl ::std::hash::Hasher for $hasher {
            #[inline]
            fn finish(&self) -> u64 {
                self.seed
                    .map_or_else(
                        || $hash::hash(&self.bytes),
                        |seed| $hash::hash_with_seed(&self.bytes, seed),
                    )
                    .into()
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
                <Self as $crate::hasher::BufHasher>::with_capacity_and_seed(64, None)
            }

            #[inline]
            fn with_seed(seed: Self::Seed) -> Self {
                <Self as $crate::hasher::BufHasher>::with_capacity_and_seed(64, Some(seed))
            }
        }

        impl ::std::convert::AsRef<[u8]> for $hasher {
            #[inline]
            fn as_ref(&self) -> &[u8] {
                &self.bytes
            }
        }

        impl $crate::hasher::BufHasher for $hasher {
            #[inline]
            fn with_capacity_and_seed(capacity: usize, seed: Option<Self::Seed>) -> Self {
                $hasher {
                    seed: seed,
                    bytes: Vec::with_capacity(capacity),
                }
            }
        }

        impl_fasthash!($hasher, $hash);
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! impl_hasher_ext {
    ($hasher:ident, $hash:ident) => {
        /// An implementation of `std::hash::Hasher` and `fasthash::HasherExt`.
        #[derive(Clone)]
        pub struct $hasher {
            seed: Option<<$hash as $crate::hasher::FastHash>::Seed>,
            bytes: Vec<u8>,
        }

        impl $hasher {
            #[inline]
            fn finalize(&self) -> u128 {
                self.seed.map_or_else(
                    || $hash::hash(&self.bytes),
                    |seed| $hash::hash_with_seed(&self.bytes, seed),
                )
            }
        }

        impl Default for $hasher {
            fn default() -> Self {
                $hasher::new()
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

        impl $crate::hasher::HasherExt for $hasher {
            #[inline]
            fn finish_ext(&self) -> u128 {
                self.finalize()
            }
        }

        impl $crate::hasher::FastHasher for $hasher {
            type Seed = <$hash as $crate::hasher::FastHash>::Seed;

            #[inline]
            fn new() -> Self {
                <Self as $crate::hasher::BufHasher>::with_capacity_and_seed(64, None)
            }

            #[inline]
            fn with_seed(seed: Self::Seed) -> Self {
                <Self as $crate::hasher::BufHasher>::with_capacity_and_seed(64, Some(seed))
            }
        }

        impl ::std::convert::AsRef<[u8]> for $hasher {
            #[inline]
            fn as_ref(&self) -> &[u8] {
                &self.bytes
            }
        }

        impl $crate::hasher::BufHasher for $hasher {
            #[inline]
            fn with_capacity_and_seed(capacity: usize, seed: Option<Self::Seed>) -> Self {
                $hasher {
                    seed: seed,
                    bytes: Vec::with_capacity(capacity),
                }
            }
        }

        impl_fasthash!($hasher, $hash);
    };
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::convert::Into;

    use extprim::u128::u128;

    #[cfg(feature = "sse42")]
    use city::CityHashCrc128;
    use city::{CityHash128, CityHash32, CityHash64};

    use farm::{FarmHash128, FarmHash32, FarmHash64};
    use lookup3::Lookup3;

    #[cfg(feature = "sse42")]
    use metro::{MetroHash128Crc_1, MetroHash128Crc_2, MetroHash64Crc_1, MetroHash64Crc_2};
    use metro::{MetroHash128_1, MetroHash128_2, MetroHash64_1, MetroHash64_2};

    use mum::MumHash;
    use murmur::{Murmur, MurmurAligned};
    use murmur2::{
        Murmur2, Murmur2A, Murmur2_x64_64, Murmur2_x86_64, MurmurAligned2, MurmurNeutral2,
    };
    use murmur3::{Murmur3_x64_128, Murmur3_x86_128, Murmur3_x86_32};
    use sea::SeaHash;
    use spooky::{SpookyHash128, SpookyHash32, SpookyHash64};

    use t1ha::{T1ha0_32Be, T1ha0_32Le, T1ha1_64Be, T1ha1_64Le};

    use super::*;
    use xx::{XXHash32, XXHash64};

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
        assert_eq!(u1, u2.high64());

        s = Seed::gen();

        u1 = s.into();

        s = Seed::gen();

        u2 = s.into();

        assert!(u0 != 0);
        assert!(u1 != 0);
        assert!(u2 != u128::zero());
        assert!(u0 as u64 != u1);
        assert!(u1 != u2.low64());
        assert!(u1 != u2.high64());

        u0 = Seed::gen().into();
        u1 = Seed::gen().into();
        u2 = Seed::gen().into();

        assert!(u0 != 0);
        assert!(u1 != 0);
        assert!(u2 != u128::zero());
        assert!(u0 as u64 != u1);
        assert!(u1 != u2.low64());
        assert!(u1 != u2.high64());
    }

    macro_rules! test_hashmap_with_fixed_state {
        ($hash:ident) => {
            let mut map = HashMap::with_hasher($hash {});

            assert_eq!(map.insert(37, "a"), None);
            assert_eq!(map.is_empty(), false);

            map.insert(37, "b");
            assert_eq!(map.insert(37, "c"), Some("b"));
            assert_eq!(map[&37], "c");
        };
    }

    macro_rules! test_hashmap_with_random_state {
        ($hash:ident) => {
            let s = RandomState::<$hash>::new();
            let mut map = HashMap::with_hasher(s);

            assert_eq!(map.insert(37, "a"), None);
            assert_eq!(map.is_empty(), false);

            map.insert(37, "b");
            assert_eq!(map.insert(37, "c"), Some("b"));
            assert_eq!(map[&37], "c");
        };
    }

    macro_rules! test_hashmap_with_hashers {
        [ $( $hash:ident ),* ] => {
            $( {
                test_hashmap_with_fixed_state!( $hash );
                test_hashmap_with_random_state!( $hash );
            } )*
        }
    }

    #[test]
    fn test_hashmap_with_hashers() {
        test_hashmap_with_hashers![CityHash32, CityHash64, CityHash128];
        #[cfg(feature = "sse42")]
        test_hashmap_with_hashers![CityHashCrc128];

        test_hashmap_with_hashers![FarmHash32, FarmHash64, FarmHash128];
        test_hashmap_with_hashers![Lookup3];

        test_hashmap_with_hashers![MetroHash64_1, MetroHash64_2, MetroHash128_1, MetroHash128_2];
        #[cfg(feature = "sse42")]
        test_hashmap_with_hashers![
            MetroHash64Crc_1,
            MetroHash64Crc_2,
            MetroHash128Crc_1,
            MetroHash128Crc_2
        ];

        test_hashmap_with_hashers![MumHash];
        test_hashmap_with_hashers![Murmur, MurmurAligned];
        test_hashmap_with_hashers![
            Murmur2,
            Murmur2A,
            MurmurNeutral2,
            MurmurAligned2,
            Murmur2_x64_64,
            Murmur2_x86_64
        ];
        test_hashmap_with_hashers![Murmur3_x86_32, Murmur3_x86_128, Murmur3_x64_128];
        test_hashmap_with_hashers![SeaHash];
        test_hashmap_with_hashers![SpookyHash32, SpookyHash64, SpookyHash128];
        test_hashmap_with_hashers![T1ha1_64Le, T1ha1_64Be, T1ha0_32Le, T1ha0_32Be];
        test_hashmap_with_hashers![XXHash32, XXHash64];
    }
}
