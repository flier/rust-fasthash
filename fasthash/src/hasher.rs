use std::mem;
use std::io;

use std::hash::Hasher;

use extprim::i128::i128;
use extprim::u128::u128;

/// Generate a good, portable, forever-fixed hash value
pub trait Fingerprint<T> {
    /// This is intended to be a good fingerprinting primitive.
    fn fingerprint(&self) -> T;
}

/// Fast non-cryptographic hash functions
pub trait FastHash {
    type Value;
    type Seed: Default;

    /// Hash functions for a byte array.
    /// For convenience, a seed is also hashed into the result.
    fn hash_with_seed<T: AsRef<[u8]>>(bytes: &T, seed: Self::Seed) -> Self::Value;

    /// Hash functions for a byte array.
    fn hash<T: AsRef<[u8]>>(bytes: &T) -> Self::Value {
        Self::hash_with_seed(bytes, Default::default())
    }
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

#[doc(hidden)]
#[macro_export]
macro_rules! impl_hasher {
    ($(#[$attr:meta])*  $hasher:ident, $hash:ident) => (
        /// An implementation of `std::hash::Hasher`.
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
                    bytes: Vec::with_capacity(64),
                }
            }

            #[inline]
            pub fn with_seed(seed: <$hash as $crate::hasher::FastHash>::Seed) -> Self {
                $hasher {
                    seed: Some(seed),
                    bytes: Vec::with_capacity(64),
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

        impl ::std::convert::AsRef<[u8]> for $hasher {
            fn as_ref(&self) -> &[u8] {
                &self.bytes
            }
        }

        impl $crate::hasher::BufHasher for $hasher {}

        impl ::std::hash::BuildHasher for $hash {
            type Hasher = $hasher;

            fn build_hasher(&self) -> Self::Hasher {
                $hasher::new()
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
            pub fn new() -> Self {
                $hasher {
                    seed: None,
                    bytes: Vec::with_capacity(64),
                }
            }

            #[inline]
            pub fn with_seed(seed: <$hash as $crate::hasher::FastHash>::Seed) -> Self {
                $hasher {
                    seed: Some(seed),
                    bytes: Vec::with_capacity(64),
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

        impl ::std::convert::AsRef<[u8]> for $hasher {
            fn as_ref(&self) -> &[u8] {
                &self.bytes
            }
        }

        impl $crate::hasher::BufHasher for $hasher {}

        impl ::std::hash::BuildHasher for $hash {
            type Hasher = $hasher;

            fn build_hasher(&self) -> Self::Hasher {
                $hasher::new()
            }
        }
    )
}
