//! SeaHash: A bizarrely fast hash function.
//!
//! by ticki <ticki@users.noreply.github.com>
//!
//! SeaHash is a hash function with performance better than
//! (around 3-20% improvement) xxHash and MetroHash.
//! Furthermore, SeaHash has mathematically provable statistical guarantees.
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
//!     let mut s = SeaHasher::new();
//!     t.hash(&mut s);
//!     s.finish()
//! }
//!
//! assert_eq!(sea::hash64(b"hello world\xff"), 8985868041853666652);
//!
//! assert_eq!(hash(&"hello world"), 1198299633807023012);
//! ```
//!
use std::hash::BuildHasher;

use seahash;

pub use seahash::{SeaHasher as SeaHasher64, hash as hash64, hash_seeded as hash_with_seeds};

use hasher::{FastHash, StreamHasher};

/// SeaHash 64-bit hash functions
pub struct SeaHash {}

impl FastHash for SeaHash {
    type Value = u64;
    type Seed = (u64, u64, u64, u64);

    #[inline]
    fn hash<T: AsRef<[u8]>>(bytes: &T) -> u64 {
        seahash::hash(bytes.as_ref())
    }

    #[inline]
    fn hash_with_seed<T: AsRef<[u8]>>(bytes: &T, seed: (u64, u64, u64, u64)) -> u64 {
        seahash::hash_seeded(bytes.as_ref(), seed.0, seed.1, seed.2, seed.3)
    }
}

impl BuildHasher for SeaHash {
    type Hasher = SeaHasher64;

    fn build_hasher(&self) -> Self::Hasher {
        SeaHasher64::new()
    }
}

impl StreamHasher for SeaHasher64 {}

#[cfg(test)]
mod tests {
    use std::hash::Hasher;

    use hasher::FastHash;
    use super::*;

    #[test]
    fn test_seahash64() {
        assert_eq!(SeaHash::hash(b"hello"), 153251464476911497);
        assert_eq!(SeaHash::hash_with_seed(b"hello", (12, 34, 56, 78)),
                   3117749726954423822);
        assert_eq!(SeaHash::hash(b"helloworld"), 9532038143498849405);

        let mut h = SeaHasher64::new();

        h.write(b"hello");
        assert_eq!(h.finish(), 11332652286493249837);

        h.write(b"world");
        assert_eq!(h.finish(), 4332207266370068704);
    }
}
