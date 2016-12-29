# rust-fasthash [![travis build](https://travis-ci.org/flier/rust-fasthash.svg?branch=master)](https://travis-ci.org/flier/rust-fasthash) [![crate](https://img.shields.io/crates/v/fasthash.svg)](https://crates.io/crates/fasthash)
A suite of non-cryptographic hash functions for Rust, base on a forked [smhasher](https://github.com/rurban/smhasher/).

## API Document

- [master](https://flier.github.io/rust-fasthash/docs/master/fasthash/index.html)
- [v0.2.2](https://flier.github.io/rust-fasthash/docs/v0.2.2/fasthash/index.html)

# Usage

To use `fasthash`, first add this to your `Cargo.toml`:

```toml
[dependencies]
fasthash = "0.2"
```

Then, add this to your crate root:

```rust
extern crate fasthash;

use fasthash::*;
```

And then, use hash function with module or hasher

```rust
let h = city::hash64("hello world");
```

```rust
fn hash<T: Hash>(t: &T) -> u64 {
    let mut s = MetroHasher::new();
    t.hash(&mut s);
    s.finish()
}

hash(&"hello world");
```

It also cowork with `HashMap` or `HashSet`, act as a hash function

```rust
use std::collections::HashSet;

use fasthash::spooky::SpookyHash128;

let mut set = HashSet::with_hasher(SpookyHash128 {});
set.insert(2);
```

Or use RandomState<CityHash64> with a random seed.

```rust
use std::hash::{Hash, Hasher};
use std::collections::HashMap;

use fasthash::RandomState;
use fasthash::city::CityHash64;

let s = RandomState::<CityHash64>::new();
let mut map = HashMap::with_hasher(s);

assert_eq!(map.insert(37, "a"), None);
assert_eq!(map.is_empty(), false);

map.insert(37, "b");
assert_eq!(map.insert(37, "c"), Some("b"));
assert_eq!(map[&37], "c");
```

# Goal
- High performance
- Zero cost
- Compatibility with libstd

# Features

- Modern Hash Functions
  - [x] [City Hash](https://github.com/google/cityhash)
  - [x] [Farm Hash](https://github.com/google/farmhash)
  - [x] [Metro Hash](https://github.com/jandrewrogers/MetroHash)
  - [x] [Mum Hash](https://github.com/vnmakarov/mum-hash)
  - [x] [Murmur Hash](https://sites.google.com/site/murmurhash/)
  - [x] [Sea Hash](https://github.com/ticki/tfs/tree/master/seahash)
  - [x] [Spooky Hash](http://burtleburtle.net/bob/hash/spooky.html)
  - [x] [T1 Hash](https://github.com/leo-yuriev/t1ha)
  - [x] [xx Hash](https://github.com/Cyan4973/xxHash)
- Compatibility
  - [x] [Hasher](https://doc.rust-lang.org/std/hash/trait.Hasher.html)
  - [x] std::collections::{[HashMap](https://doc.rust-lang.org/std/collections/struct.HashMap.html), [HashSet](https://doc.rust-lang.org/std/collections/struct.HashSet.html)} with `RandomState`

# Performance

To bench the hash function, we need nighly rust

```bash
$ rustup run nightly cargo bench
```

Please check [smhasher](https://github.com/rurban/smhasher/tree/master/doc) reports for more details.