//! `MumHash`, Hashing functions and PRNGs based on them
//!
//! by Vladimir Makarov <vmakarov@gcc.gnu.org>
//!
//! https://github.com/vnmakarov/mum-hash
//!
//! * MUM hash is a **fast non-cryptographic hash function**
//!   suitable for different hash table implementations
//! * MUM means **MU**ltiply and **M**ix
//!   * It is a name of the base transformation on which hashing is implemented
//!   * Modern processors have a fast logic to do long number multiplications
//!   * It is very attractable to use it for fast hashing
//!     * For example, 64x64-bit multiplication can do the same work as 32
//!       shifts and additions
//!   * I'd like to call it Multiply and Reduce.  Unfortunately, MUR
//!     (Multiply and Rotate) is already taken for famous hashing
//!     technique designed by Austin Appleby
//!   * I've chosen the name also as I am releasing it on Mother's day
//! * MUM hash passes **all** [`SMHasher`](https://github.com/aappleby/smhasher) tests
//!   * For comparison, only 4 out of 15 non-cryptographic hash functions
//!     in `SMHasher` passes the tests, e.g. well known FNV, Murmur2,
//!     Lookup, and Superfast hashes fail the tests
//! * MUM algorithm is **simpler** than City64 and Spooky ones
//! * MUM is specifically **designed for 64-bit CPUs** (Sorry, I did not want to
//!   spend my time on dying architectures)
//!   * Still MUM will work for 32-bit CPUs and it will be sometimes
//!     faster Spooky and City
//! * On x86-64 MUM hash is **faster** than City64 and Spooky on all tests except for one
//!   test for the bulky speed
//!   * Starting with 240-byte strings, City uses Intel SSE4.2 crc32 instruction
//!   * I could use the same instruction but I don't want to complicate the algorithm
//!   * In typical scenario, such long strings are rare.  Usually another
//!     interface (see `mum_hash_step`) is used for hashing big data structures
//! * MUM has a **fast startup**.  It is particular good to hash small keys
//!   which are a majority of hash table applications
//!
//! # Example
//!
//! ```
//! use std::hash::{Hash, Hasher};
//!
//! use fasthash::{mum, MumHasher};
//!
//! fn hash<T: Hash>(t: &T) -> u64 {
//!     let mut s: MumHasher = Default::default();
//!     t.hash(&mut s);
//!     s.finish()
//! }
//!
//! let h = mum::hash64(b"hello world\xff");
//!
//! assert_eq!(h, hash(&"hello world"));
//! ```
//!
#![allow(non_camel_case_types)]
use std::os::raw::c_void;

use ffi;

use hasher::FastHash;

/// `MumHash` 64-bit hash functions
///
/// # Example
///
/// ```
/// use fasthash::{mum::Hash64, FastHash};
///
/// assert_eq!(Hash64::hash(b"hello"), 9723359729180093834);
/// assert_eq!(Hash64::hash_with_seed(b"hello", 123), 12693953100868515521);
/// assert_eq!(Hash64::hash(b"helloworld"), 9122204010978352975);
/// ```
#[derive(Clone)]
pub struct Hash64;

impl FastHash for Hash64 {
    type Hash = u64;
    type Seed = u64;

    #[inline(always)]
    fn hash_with_seed<T: AsRef<[u8]>>(bytes: T, seed: u64) -> u64 {
        unsafe {
            ffi::mum_hash_(
                bytes.as_ref().as_ptr() as *const c_void,
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

use fasthash::{mum::Hasher64, FastHasher};

let mut h = Hasher64::new();

h.write(b"hello");
assert_eq!(h.finish(), 9723359729180093834);

h.write(b"world");
assert_eq!(h.finish(), 9122204010978352975);
```
"#]
    Hasher64,
    Hash64
);

/// `MumHash` 64-bit hash functions for a byte array.
#[inline(always)]
pub fn hash64<T: AsRef<[u8]>>(v: T) -> u64 {
    Hash64::hash(v)
}

/// `MumHash` 64-bit hash function for a byte array.
/// For convenience, a 64-bit seed is also hashed into the result.
#[inline(always)]
pub fn hash64_with_seed<T: AsRef<[u8]>>(v: T, seed: u64) -> u64 {
    Hash64::hash_with_seed(v, seed)
}
