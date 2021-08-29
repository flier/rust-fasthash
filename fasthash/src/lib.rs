//! A suite of non-cryptographic hash functions for Rust.
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
//! By default, `HashMap` uses a hashing algorithm selected to
//! provide resistance against `HashDoS` attacks.
//! The hashing algorithm can be replaced on a per-`HashMap` basis
//! using the `HashMap::with_hasher` or
//! `HashMap::with_capacity_and_hasher` methods.
//!
//! It also cowork with `HashMap` or `HashSet`, act as a hash function
//!
//! ```
//! use std::collections::HashSet;
//!
//! use fasthash::spooky::Hash128;
//!
//! let mut set = HashSet::with_hasher(Hash128);
//! set.insert(2);
//! ```
//!
//! Or use `RandomState<CityHash64>` with a random seed.
//!
//! ```
//! use std::collections::HashMap;
//!
//! use fasthash::{city, RandomState};
//!
//! let s = RandomState::<city::Hash64>::new();
//! let mut map = HashMap::with_hasher(s);
//!
//! assert_eq!(map.insert(37, "a"), None);
//! assert_eq!(map.is_empty(), false);
//!
//! map.insert(37, "b");
//! assert_eq!(map.insert(37, "c"), Some("b"));
//! assert_eq!(map[&37], "c");
//! ```
#![warn(missing_docs)]

#[macro_use]
extern crate cfg_if;
extern crate fasthash_sys as ffi;

cfg_if! {
    if #[cfg(feature = "digest")] {
        pub extern crate digest;

        pub use crate::hasher::Output;
    }
}

#[macro_use]
mod hasher;

pub use crate::hasher::{
    BufHasher, FastHash, FastHasher, Fingerprint, HasherExt, RandomState, Seed, StreamHasher,
};

cfg_if! {
    if #[cfg(feature = "city")] {
        pub mod city;

        cfg_if! {
            if #[cfg(any(feature = "sse42", target_feature = "sse4.2"))] {
                pub use crate::city::{Hasher64 as CityHasher, crc::Hasher128 as CityHasherExt};
            } else {
                pub use city::{Hasher128 as CityHasherExt, Hasher64 as CityHasher};
            }
        }
    }
}

cfg_if! {
    if #[cfg(feature = "farm")] {
        pub mod farm;

        pub use crate::farm::{Hasher128 as FarmHasherExt, Hasher64 as FarmHasher};
    }
}

cfg_if! {
    if #[cfg(feature = "lookup3")] {
        pub mod lookup3;

        pub use crate::lookup3::Hasher32 as Lookup3Hasher;
    }
}

cfg_if! {
    if #[cfg(all(feature = "metro", feature = "aes"))] {
        pub mod meow;
    }
}

cfg_if! {
    if #[cfg(feature = "metro")] {
        pub mod metro;

        cfg_if! {
            if #[cfg(any(feature = "sse42", target_feature = "sse4.2"))] {
                pub use crate::metro::{crc::Hasher128_1 as MetroHasherExt, crc::Hasher64_1 as MetroHasher};
            } else {
                pub use metro::{Hasher128_1 as MetroHasherExt, Hasher64_1 as MetroHasher};
            }
        }
    }
}

cfg_if! {
    if #[cfg(feature = "mum")] {
        pub mod mum;

        pub use crate::mum::Hasher64 as MumHasher;
    }
}

cfg_if! {
    if #[cfg(feature = "murmur")] {
        pub mod murmur;
        pub mod murmur2;
        pub mod murmur3;

        pub use crate::murmur::Hasher32 as MurmurHasher;
        pub use crate::murmur3::Hasher32 as Murmur3Hasher;

        cfg_if! {
            if #[cfg(target_pointer_width = "64")] {
                pub use crate::murmur2::Hasher64_x64 as Murmur2Hasher;
                pub use crate::murmur3::Hasher128_x64 as Murmur3HasherExt;
            } else {
                pub use murmur2::Hasher64_x86 as Murmur2Hasher;
                pub use murmur3::Hasher128_x86 as Murmur3HasherExt;
            }
        }
    }
}

cfg_if! {
    if #[cfg(feature = "spooky")] {
        pub mod spooky;

        pub use crate::spooky::{Hasher128 as SpookyHasherExt, Hasher64 as SpookyHasher};
    }
}

cfg_if! {
    if #[cfg(feature = "ahash")] {
        pub mod ahash;

        pub use crate::ahash::{AHasher, Hash64};
    }
}

cfg_if! {
    if #[cfg(feature = "t1ha")] {
        pub mod t1ha;

        pub use crate::t1ha::{t1ha0, t1ha1, t1ha2};
        pub use crate::t1ha2::{Hasher128 as T1haHasherExt, Hasher128 as T1haHasher};
    }
}

cfg_if! {
    if #[cfg(feature = "highway")] {
        pub mod highway;

        pub use crate::highway::{Hasher64 as HighwayHasher, Hasher128 as HighwayHasherExt};
    }
}

cfg_if! {
    if #[cfg(feature = "seahash")] {
        pub mod sea;

        #[doc(no_inline)]
        pub use crate::sea::Hasher64 as SeaHasher;
    }
}

cfg_if! {
    if #[cfg(feature = "wy")] {
        pub mod wy;

        pub use crate::wy::Hasher64 as WYHasher;
    }
}

cfg_if! {
    if #[cfg(feature = "xx")] {
        pub mod xx;
        pub mod xxh3;

        pub use crate::xx::Hasher64 as XXHasher;
    }
}
