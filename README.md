## rust-fasthash [![travis build](https://travis-ci.org/flier/rust-fasthash.svg?branch=master)](https://travis-ci.org/flier/rust-fasthash) [![crate](https://img.shields.io/crates/v/fasthash.svg)](https://crates.io/crates/fasthash) [![docs](https://docs.rs/fasthash/badge.svg)](https://docs.rs/crate/fasthash/)
A suite of non-cryptographic hash functions for Rust, binding the [smhasher](https://github.com/rurban/smhasher/).

## Usage

```toml
[dependencies]
fasthash = "0.4"
```

### `hash` and `hash_with_seed` function

```rust
use fasthash::*;

let h = city::hash64("hello world");

let h = metro::hash64_with_seed("hello world", 123);
```

### `std::hash::Hash`

```rust
use std::hash::{Hash, Hasher};

use fasthash::{MetroHasher, FastHasher};

fn hash<T: Hash>(t: &T) -> u64 {
    // Or use any of the `*Hasher` struct's available as aliases from
    // root or in their respective modules as Hasher32/64 and some 128.
    let mut s = MetroHasher::default();
    t.hash(&mut s);
    s.finish()
}

hash(&"hello world");
```

### `HashMap` and `HashSet`

```rust
use std::collections::HashSet;

use fasthash::spooky::Hash128;

let mut set = HashSet::with_hasher(Hash128);

set.insert(2);
```

### `RandomState`

```rust
use std::collections::HashMap;

use fasthash::RandomState;
use fasthash::city::Hash64;

let s = RandomState::<Hash64>::new();
let mut map = HashMap::with_hasher(s);

assert_eq!(map.insert(37, "a"), None);
assert_eq!(map.is_empty(), false);

map.insert(37, "b");
assert_eq!(map.insert(37, "c"), Some("b"));
assert_eq!(map[&37], "c");
```

## Hash Functions



- Modern Hash Functions
  - [City Hash](https://github.com/google/cityhash)
  - [Farm Hash](https://github.com/google/farmhash)
  - [Highway Hash](https://github.com/google/highwayhash)
  - [Komi Hash](https://github.com/avaneev/komihash) **new**
  - [Lookup3](https://en.wikipedia.org/wiki/Jenkins_hash_function)
  - [Meow Hash](https://github.com/cmuratori/meow_hash) **new**
  - [Metro Hash](https://github.com/jandrewrogers/MetroHash)
  - [Mum Hash](https://github.com/vnmakarov/mum-hash)
  - [Murmur Hash](https://sites.google.com/site/murmurhash/)
  - [mx3 Hash](https://github.com/jonmaiga/mx3) **new**
  - [NmHash](https://github.com/gzm55/hash-garage) **new**
  - [PengyHash](https://github.com/tinypeng/pengyhash) **new**
  - [PrvHash](https://github.com/avaneev/prvhash) **new**
  - [Sea Hash](https://github.com/ticki/tfs/tree/master/seahash)
  - [Spooky Hash](http://burtleburtle.net/bob/hash/spooky.html)
  - [T1ha Hash](https://github.com/leo-yuriev/t1ha)
  - [wyhash](https://github.com/wangyi-fudan/wyhash) (final3)
  - [xx Hash](https://github.com/Cyan4973/xxHash) with  **experimental** [XXH3](https://github.com/Cyan4973/xxHash#new-experimental-hash-algorithm) hash algorithm
- Compatibility
  - [Hasher](https://doc.rust-lang.org/std/hash/trait.Hasher.html)
  - std::collections::{[HashMap](https://doc.rust-lang.org/std/collections/struct.HashMap.html), [HashSet](https://doc.rust-lang.org/std/collections/struct.HashSet.html)} with `RandomState`
  - [Digest](https://docs.rs/digest/0.8.1/digest/trait.Digest.html) (optional)

## Benchmark

```bash
$ cargo bench
```
