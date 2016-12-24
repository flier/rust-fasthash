extern crate extprim;
extern crate fasthash_sys as ffi;

#[macro_use]
mod hasher;
pub mod city;
pub mod murmur;
pub mod murmur2;
pub mod murmur3;
pub mod spooky;

pub use hasher::HasherExt;
pub use city::{CityHash32, CityHash64, CityHash128};
pub use murmur::{Murmur, MurmurAligned};
pub use murmur2::{Murmur2A, Murmur2Neutral, Murmur2Aligned, Murmur2_x64_64, Murmur2_x86_64};
pub use murmur3::{Murmur3_x86_32, Murmur3_x86_128, Murmur3_x64_128};
pub use spooky::Spooky;
