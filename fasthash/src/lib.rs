extern crate fasthash_sys as ffi;

#[macro_use]
mod hasher;
pub mod murmur;

pub use murmur::{Murmur, MurmurAligned};
