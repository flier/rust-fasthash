#![allow(deprecated)]
#![feature(test)]
extern crate fnv;
extern crate rand;
extern crate test;

extern crate fasthash;

use std::hash::*;

use fnv::*;
use rand::{thread_rng, Rng};
use test::Bencher;

use fasthash::*;

const ITERATERS: usize = 1000;

fn gen_key(size: usize) -> Vec<u8> {
    thread_rng()
        .gen_iter::<u8>()
        .take(size)
        .collect::<Vec<u8>>()
}

#[inline]
fn bench_fasthash<H: FastHash>(b: &mut Bencher, size: usize) {
    let key = gen_key(size);

    b.bytes = (size * ITERATERS) as u64;
    b.iter(|| {
        let n = test::black_box(ITERATERS);

        (0..n).fold(0, |_, _| {
            H::hash(&key);
            0
        })
    });
}

#[inline]
fn bench_hasher<H: Hasher + Default>(b: &mut Bencher, size: usize) {
    let key = gen_key(size);

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

#[inline]
fn bench_buf_hasher<H: BufHasher>(b: &mut Bencher, size: usize) {
    let key = gen_key(size);

    b.bytes = (size * ITERATERS) as u64;
    b.iter(|| {
        let n = test::black_box(ITERATERS);

        (0..n).fold(0, |_, _| {
            let mut h = H::with_capacity_and_seed(size, None);
            h.write(key.as_slice());
            h.finish()
        })
    });
}

include!(concat!(env!("OUT_DIR"), "/benches.rs"));
