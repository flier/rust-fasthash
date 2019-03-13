//! `SeaHash`: A bizarrely fast hash function.
//!
//! by ticki <ticki@users.noreply.github.com>
//!
//! `SeaHash` is a hash function with performance better than
//! (around 3-20% improvement) xxHash and `MetroHash`.
//! Furthermore, `SeaHash` has mathematically provable statistical guarantees.
//!
//!
//! # Example
//!
//! ```
//! use std::hash::{Hash, Hasher};
//!
//! use fasthash::{sea, SeaHasher};
//!
//! fn hash<T: Hash>(t: &T) -> u64 {
//!     let mut s: SeaHasher = Default::default();
//!     t.hash(&mut s);
//!     s.finish()
//! }
//!
//! assert_eq!(sea::hash64(b"hello world\xff"), 8985868041853666652);
//!
//! assert_eq!(hash(&"hello world"), 1198299633807023012);
//! ```
//!
use seahash;

pub use seahash::{hash as hash64, hash_seeded as hash_with_seeds, SeaHasher as Hasher64};

use hasher::{FastHash, FastHasher, StreamHasher};

/// `SeaHash` 64-bit hash functions
///
/// # Example
///
/// ```
/// use fasthash::{sea::Hash64, FastHash};
///
/// assert_eq!(Hash64::hash(b"hello"), 153251464476911497);
/// assert_eq!(
///     Hash64::hash_with_seed(b"hello", (12, 34, 56, 78)),
///     3117749726954423822
/// );
/// assert_eq!(Hash64::hash(b"helloworld"), 9532038143498849405);
/// ```
pub struct Hash64;

impl FastHash for Hash64 {
    type Hash = u64;
    type Seed = (u64, u64, u64, u64);

    #[inline]
    fn hash<T: AsRef<[u8]>>(bytes: T) -> u64 {
        seahash::hash(bytes.as_ref())
    }

    #[inline]
    fn hash_with_seed<T: AsRef<[u8]>>(bytes: T, seed: (u64, u64, u64, u64)) -> u64 {
        seahash::hash_seeded(bytes.as_ref(), seed.0, seed.1, seed.2, seed.3)
    }
}

impl_fasthash!(Hasher64, Hash64);

impl FastHasher for Hasher64 {
    type Seed = (u64, u64, u64, u64);

    #[inline]
    fn new() -> Self {
        Hasher64::new()
    }

    #[inline]
    fn with_seed(seed: Self::Seed) -> Self {
        Hasher64::with_seeds(seed.0, seed.1, seed.2, seed.3)
    }
}

impl StreamHasher for Hasher64 {}

#[cfg(test)]
mod tests {
    use std::hash::Hasher;

    use super::Hasher64;

    #[test]
    fn test_seahash64() {
        let mut h = Hasher64::new();

        h.write(b"hello");
        assert_eq!(h.finish(), 11332652286493249837);

        h.write(b"world");
        assert_eq!(h.finish(), 4332207266370068704);
    }
}
