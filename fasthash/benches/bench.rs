#![allow(deprecated)]

#![feature(test)]
extern crate test;
extern crate rand;
extern crate fnv;

extern crate fasthash;

use std::hash::*;

use test::Bencher;
use rand::{thread_rng, Rng};
use fnv::*;

use fasthash::*;

const ITERATERS: usize = 1000;

#[inline]
fn bench_hash<F, T>(b: &mut Bencher, func: F, size: usize)
    where F: Fn(&[u8]) -> T
{
    let key = thread_rng().gen_iter::<u8>().take(size).collect::<Vec<u8>>();

    b.bytes = (size * ITERATERS) as u64;
    b.iter(|| {
        let n = test::black_box(ITERATERS);

        (0..n).fold(0, |_, _| {
            func(key.as_slice());
            0
        })
    });
}

#[inline]
fn bench_hasher<H: Hasher + Default>(b: &mut Bencher, size: usize) {
    let key = thread_rng().gen_iter::<u8>().take(size).collect::<Vec<u8>>();

    b.bytes = (size * ITERATERS) as u64;
    b.iter(|| {
        let n = test::black_box(ITERATERS);

        (0..n).fold(0, |_, _| {
            let mut h: H = Default::default();
            h.write(key.as_slice());
            h.finish()
        })
    });
}

include!(concat!(env!("OUT_DIR"), "/benches.rs"));
