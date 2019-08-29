#![allow(deprecated)]

#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate criterion;

use std::mem;
use std::slice;

use criterion::{black_box, Criterion, ParameterizedBenchmark, Throughput};

use fasthash::*;

const KB: usize = 1024;
const SEED: u64 = 0x0123456789ABCDEF;
const PARAMS: [usize; 7] = [7, 8, 32, 256, KB, 4 * KB, 16 * KB];

lazy_static! {
    static ref DATA: Vec<u8> = (0..16 * KB).map(|b| b as u8).collect::<Vec<_>>();
}

fn bench_memory(c: &mut Criterion) {
    c.bench(
        "memory",
        ParameterizedBenchmark::new(
            "sum",
            move |b, &&size| {
                let s = unsafe {
                    slice::from_raw_parts(DATA.as_ptr() as *mut u32, size / mem::size_of::<u32>())
                };

                b.iter(|| {
                    black_box(s.iter().fold(0u64, |acc, &x| acc + x as u64));
                })
            },
            &PARAMS,
        )
        .throughput(|&&size| Throughput::Bytes(size as u64)),
    );
}

fn bench_hash32(c: &mut Criterion) {
    c.bench(
        "hash32",
        ParameterizedBenchmark::new(
            "city::hash32",
            move |b, &&size| {
                b.iter(|| city::hash32_with_seed(&DATA.as_slice()[..size], SEED as u32));
            },
            &PARAMS,
        )
        .with_function("farm::hash32", move |b, &&size| {
            b.iter(|| farm::hash32_with_seed(&DATA[..size], SEED as u32));
        })
        .with_function("farm::finterprint32", move |b, &&size| {
            b.iter(|| farm::fingerprint32(&DATA[..size]));
        })
        .with_function("lookup3::hash32", move |b, &&size| {
            b.iter(|| lookup3::hash32_with_seed(&DATA[..size], SEED as u32));
        })
        .with_function("murmur::hash32", move |b, &&size| {
            b.iter(|| murmur::hash32_with_seed(&DATA[..size], SEED as u32));
        })
        .with_function("murmur::hash32_aligned", move |b, &&size| {
            b.iter(|| murmur::hash32_aligned_with_seed(&DATA[..size], SEED as u32));
        })
        .with_function("murmur2::hash32", move |b, &&size| {
            b.iter(|| murmur2::Hash32::hash_with_seed(&DATA[..size], SEED as u32));
        })
        .with_function("murmur2::hash32_a", move |b, &&size| {
            b.iter(|| murmur2::Hash32A::hash_with_seed(&DATA[..size], SEED as u32));
        })
        .with_function("murmur2::hash32_neutral", move |b, &&size| {
            b.iter(|| murmur2::Hash32Neutral::hash_with_seed(&DATA[..size], SEED as u32));
        })
        .with_function("murmur2::hash32_aligned", move |b, &&size| {
            b.iter(|| murmur2::Hash32Aligned::hash_with_seed(&DATA[..size], SEED as u32));
        })
        .with_function("murmur3::hash32", move |b, &&size| {
            b.iter(|| murmur3::hash32_with_seed(&DATA[..size], SEED as u32));
        })
        .with_function("spooky::hash32", move |b, &&size| {
            b.iter(|| spooky::hash32_with_seed(&DATA[..size], SEED as u32));
        })
        .with_function("xx::hash32", move |b, &&size| {
            b.iter(|| xx::hash32_with_seed(&DATA[..size], SEED as u32));
        })
        .throughput(|&&size| Throughput::Bytes(size as u64)),
    );
}

fn bench_hash64(c: &mut Criterion) {
    let mut bench = ParameterizedBenchmark::new(
        "city::hash64",
        move |b, &&size| {
            b.iter(|| city::hash64_with_seed(&DATA.as_slice()[..size], SEED));
        },
        &PARAMS,
    )
    .with_function("farm::hash64", move |b, &&size| {
        b.iter(|| farm::hash64_with_seed(&DATA[..size], SEED));
    })
    .with_function("farm::finterprint64", move |b, &&size| {
        b.iter(|| farm::fingerprint32(&DATA[..size]));
    })
    .with_function("metro::hash64_1", move |b, &&size| {
        b.iter(|| metro::Hash64_1::hash_with_seed(&DATA[..size], SEED as u32));
    })
    .with_function("metro::hash64_2", move |b, &&size| {
        b.iter(|| metro::Hash64_2::hash_with_seed(&DATA[..size], SEED as u32));
    })
    .with_function("mum::hash64", move |b, &&size| {
        b.iter(|| mum::hash64_with_seed(&DATA[..size], SEED));
    })
    .with_function("murmur2::hash64_x64", move |b, &&size| {
        b.iter(|| murmur2::Hash64_x64::hash_with_seed(&DATA[..size], SEED));
    })
    .with_function("murmur2::hash64_x86", move |b, &&size| {
        b.iter(|| murmur2::Hash64_x86::hash_with_seed(&DATA[..size], SEED));
    })
    .with_function("sea::hash64", move |b, &&size| {
        b.iter(|| sea::hash64_with_seeds(&DATA[..size], SEED, SEED, SEED, SEED));
    })
    .with_function("spooky::hash64", move |b, &&size| {
        b.iter(|| spooky::hash64_with_seed(&DATA[..size], SEED));
    })
    .with_function("t1ha0::hash64", move |b, &&size| {
        b.iter(|| t1ha0::Hash64::hash_with_seed(&DATA[..size], SEED));
    })
    .with_function("t1ha1::hash64", move |b, &&size| {
        b.iter(|| t1ha1::Hash64::hash_with_seed(&DATA[..size], SEED));
    })
    .with_function("t1ha2::hash64_atonce", move |b, &&size| {
        b.iter(|| t1ha2::Hash64AtOnce::hash_with_seed(&DATA[..size], SEED));
    })
    .with_function("xx::hash64", move |b, &&size| {
        b.iter(|| xx::hash64_with_seed(&DATA[..size], SEED));
    })
    .with_function("xxh3::hash64", move |b, &&size| {
        b.iter(|| xxh3::hash64_with_seed(&DATA[..size], SEED));
    });

    if cfg!(any(feature = "sse4.2", target_feature = "sse4.2")) {
        bench = bench
            .with_function("metro::crc::hash64_1", move |b, &&size| {
                b.iter(|| metro::crc::Hash64_1::hash_with_seed(&DATA[..size], SEED as u32));
            })
            .with_function("metro::crc::hash64_2", move |b, &&size| {
                b.iter(|| metro::crc::Hash64_2::hash_with_seed(&DATA[..size], SEED as u32));
            });
    }

    c.bench(
        "hash64",
        bench.throughput(|&&size| Throughput::Bytes(size as u64)),
    );
}

fn bench_hash128(c: &mut Criterion) {
    let mut bench = ParameterizedBenchmark::new(
        "city::hash128",
        move |b, &&size| {
            b.iter(|| city::Hash128::hash_with_seed(&DATA[..size], SEED as u128));
        },
        &PARAMS,
    )
    .with_function("farm::hash128", move |b, &&size| {
        b.iter(|| farm::hash128_with_seed(&DATA[..size], SEED as u128));
    })
    .with_function("farm::fingerprint128", move |b, &&size| {
        b.iter(|| farm::fingerprint128(&DATA[..size]));
    })
    .with_function("metro::Hash128_1", move |b, &&size| {
        b.iter(|| metro::Hash128_1::hash_with_seed(&DATA[..size], SEED as u32));
    })
    .with_function("metro::Hash128_2", move |b, &&size| {
        b.iter(|| metro::Hash128_2::hash_with_seed(&DATA[..size], SEED as u32));
    })
    .with_function("murmur3::hash128_x64", move |b, &&size| {
        b.iter(|| murmur3::Hash128_x64::hash_with_seed(&DATA[..size], SEED as u32));
    })
    .with_function("murmur3::hash128_x86", move |b, &&size| {
        b.iter(|| murmur3::Hash128_x86::hash_with_seed(&DATA[..size], SEED as u32));
    })
    .with_function("spooky::hash128", move |b, &&size| {
        b.iter(|| spooky::hash128_with_seed(&DATA[..size], SEED as u128));
    })
    .with_function("t1ha2::hash128_atonce", move |b, &&size| {
        b.iter(|| t1ha2::Hash128AtOnce::hash_with_seed(&DATA[..size], SEED));
    })
    .with_function("xxh3::hash128", move |b, &&size| {
        b.iter(|| t1ha2::Hash128AtOnce::hash_with_seed(&DATA[..size], SEED));
    });

    if cfg!(any(feature = "sse4.2", target_feature = "sse4.2")) {
        bench = bench
            .with_function("city::crc::hash128", move |b, &&size| {
                b.iter(|| city::crc::Hash128::hash_with_seed(&DATA[..size], SEED as u128));
            })
            .with_function("metro::crc::hash128_1", move |b, &&size| {
                b.iter(|| metro::crc::Hash128_1::hash_with_seed(&DATA[..size], SEED as u32));
            })
            .with_function("metro::crc::hash128_2", move |b, &&size| {
                b.iter(|| metro::crc::Hash128_2::hash_with_seed(&DATA[..size], SEED as u32));
            });
    }

    c.bench(
        "hash128",
        bench.throughput(|&&size| Throughput::Bytes(size as u64)),
    );
}

criterion_group!(
    benches,
    bench_memory,
    bench_hash32,
    bench_hash64,
    bench_hash128,
);
criterion_main!(benches);
