extern crate extprim;
extern crate fasthash_sys as ffi;

#[macro_use]
mod hasher;
pub mod city;
pub mod farm;
pub mod metro;
pub mod murmur;
pub mod murmur2;
pub mod murmur3;
pub mod spooky;
pub mod t1ha;
pub mod xx;

pub use hasher::HasherExt;

pub use city::{CityHasher64 as CityHasher, CityHasher128 as CityHasherExt};
pub use farm::{FarmHasher64 as FarmHasher, FarmHasher128 as FarmHasherExt};
pub use metro::{MetroHasher64_1 as MetroHasher, MetroHasher128_1 as MetroHasherExt};
pub use murmur::MurmurHasher;
pub use murmur2::Murmur2Hasher_x64_64 as Murmur2Hasher;
pub use murmur3::{Murmur3Hasher_x86_32 as Murmur3Hasher, Murmur3Hasher_x64_128 as Murmur3HasherExt};
pub use spooky::{SpookyHasher64 as SpookyHasher, SpookyHasher128 as SpookyHasherExt};
pub use t1ha::T1ha64BeHasher as T1haHasher;
pub use xx::XXHasher64 as XXHasher;
