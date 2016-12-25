# rust-fasthash [![travis build](https://travis-ci.org/flier/rust-fasthash.svg?branch=master)](https://travis-ci.org/flier/rust-fasthash) [![crate](https://img.shields.io/crates/v/fasthash.svg)](https://crates.io/crates/fasthash)
A suite of non-cryptographic hash functions for Rust, base on a forked [smhasher](https://github.com/rurban/smhasher/).

[API Document](https://docs.rs/fasthash/)

# Usage

To use `fasthash`, first add this to your `Cargo.toml`:

```toml
[dependencies]
fasthash = "0.1"
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

# Goal
- High performance
- Zero cost
- Compatibility with [std::hash::Hasher](https://doc.rust-lang.org/std/hash/trait.Hasher.html)

# Features

- Modern Hash Functions
  - [x] [City Hash](https://github.com/google/cityhash)
  - [x] [Farm Hash](https://github.com/google/farmhash)
  - [x] [Metro Hash](https://github.com/jandrewrogers/MetroHash)
  - [x] [Mum Hash](https://github.com/vnmakarov/mum-hash)
  - [x] [Murmur Hash](https://sites.google.com/site/murmurhash/)
  - [x] [Spooky Hash](http://burtleburtle.net/bob/hash/spooky.html)
  - [x] [t1ha Hash](https://github.com/leo-yuriev/t1ha)
  - [x] [xx Hash](https://github.com/Cyan4973/xxHash)

# Performance

To bench the hash function, we need nighly rust

```bash
$ rustup run nightly cargo bench
```

Please check [smhasher](https://github.com/rurban/smhasher/tree/master/doc) reports for more details.