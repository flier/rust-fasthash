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
    static ref DATA: Vec<u8> = (0..16 * KB).map(|b| b as _).collect::<Vec<_>>();
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
        .throughput(|&&size| Throughput::Bytes(size as _)),
    );
}

fn bench_hash32(c: &mut Criterion) {
    c.bench(
        "hash32",
        ParameterizedBenchmark::new(
            "city",
            move |b, &&size| {
                b.iter(|| city::hash32_with_seed(&DATA.as_slice()[..size], SEED as _));
            },
            &PARAMS,
        )
        .with_function("farm", move |b, &&size| {
            b.iter(|| farm::hash32_with_seed(&DATA[..size], SEED as _));
        })
        .with_function("farm_finterprint", move |b, &&size| {
            b.iter(|| farm::fingerprint32(&DATA[..size]));
        })
        .with_function("lookup3", move |b, &&size| {
            b.iter(|| lookup3::hash32_with_seed(&DATA[..size], SEED as _));
        })
        .with_function("murmur", move |b, &&size| {
            b.iter(|| murmur::hash32_with_seed(&DATA[..size], SEED as _));
        })
        .with_function("murmur_aligned", move |b, &&size| {
            b.iter(|| murmur::hash32_aligned_with_seed(&DATA[..size], SEED as _));
        })
        .with_function("murmur2", move |b, &&size| {
            b.iter(|| murmur2::Hash32::hash_with_seed(&DATA[..size], SEED as _));
        })
        .with_function("murmur2_a", move |b, &&size| {
            b.iter(|| murmur2::Hash32A::hash_with_seed(&DATA[..size], SEED as _));
        })
        .with_function("murmur2_neutral", move |b, &&size| {
            b.iter(|| murmur2::Hash32Neutral::hash_with_seed(&DATA[..size], SEED as _));
        })
        .with_function("murmur2_aligned", move |b, &&size| {
            b.iter(|| murmur2::Hash32Aligned::hash_with_seed(&DATA[..size], SEED as _));
        })
        .with_function("murmur3", move |b, &&size| {
            b.iter(|| murmur3::hash32_with_seed(&DATA[..size], SEED as _));
        })
        .with_function("nm", move |b, &&size| {
            b.iter(|| nm::hash32_with_seed(&DATA[..size], SEED as _));
        })
        .with_function("spooky", move |b, &&size| {
            b.iter(|| spooky::hash32_with_seed(&DATA[..size], SEED as _));
        })
        .with_function("xx", move |b, &&size| {
            b.iter(|| xx::hash32_with_seed(&DATA[..size], SEED as _));
        })
        .throughput(|&&size| Throughput::Bytes(size as _)),
    );
}

fn bench_hash64(c: &mut Criterion) {
    let mut bench = ParameterizedBenchmark::new(
        "city",
        move |b, &&size| {
            b.iter(|| city::hash64_with_seed(&DATA.as_slice()[..size], SEED));
        },
        &PARAMS,
    )
    .with_function("ahash", move |b, &&size| {
        b.iter(|| ahash::hash64_with_seed(&DATA[..size], (SEED as _, SEED as _)))
    })
    .with_function("farm", move |b, &&size| {
        b.iter(|| farm::hash64_with_seed(&DATA[..size], SEED));
    })
    .with_function("farm_finterprint", move |b, &&size| {
        b.iter(|| farm::fingerprint32(&DATA[..size]));
    })
    .with_function("komi", move |b, &&size| {
        b.iter(|| komi::hash64_with_seed(&DATA[..size], SEED));
    })
    .with_function("metro_1", move |b, &&size| {
        b.iter(|| metro::Hash64_1::hash_with_seed(&DATA[..size], SEED as _));
    })
    .with_function("metro_2", move |b, &&size| {
        b.iter(|| metro::Hash64_2::hash_with_seed(&DATA[..size], SEED as _));
    })
    .with_function("mum", move |b, &&size| {
        b.iter(|| mum::hash64_with_seed(&DATA[..size], SEED));
    })
    .with_function("murmur2_x64", move |b, &&size| {
        b.iter(|| murmur2::Hash64_x64::hash_with_seed(&DATA[..size], SEED));
    })
    .with_function("murmur2_x86", move |b, &&size| {
        b.iter(|| murmur2::Hash64_x86::hash_with_seed(&DATA[..size], SEED));
    })
    .with_function("mx3", move |b, &&size| {
        b.iter(|| mx3::hash64_with_seed(&DATA[..size], SEED));
    })
    .with_function("pengy", move |b, &&size| {
        b.iter(|| pengy::hash64_with_seed(&DATA[..size], SEED as _));
    })
    .with_function("prv", move |b, &&size| {
        b.iter(|| prv::hash64_with_seed(&DATA[..size], SEED));
    })
    .with_function("sea", move |b, &&size| {
        b.iter(|| sea::hash64_with_seeds(&DATA[..size], SEED, SEED, SEED, SEED));
    })
    .with_function("spooky", move |b, &&size| {
        b.iter(|| spooky::hash64_with_seed(&DATA[..size], SEED));
    })
    .with_function("xx", move |b, &&size| {
        b.iter(|| xx::hash64_with_seed(&DATA[..size], SEED));
    })
    .with_function("xxh3", move |b, &&size| {
        b.iter(|| xxh3::hash64_with_seed(&DATA[..size], SEED));
    })
    .with_function("highway", move |b, &&size| {
        b.iter(|| highway::hash64_with_seed(&DATA[..size], [SEED, SEED, SEED, SEED]));
    })
    .with_function("umash", move |b, &&size| {
        b.iter(|| umash::hash64_with_seed(&DATA[..size], SEED));
    })
    .with_function("wy", move |b, &&size| {
        b.iter(|| wy::hash64_with_seed(&DATA[..size], SEED));
    });

    #[cfg(feature = "t1ha")]
    {
        bench = bench
            .with_function("t1ha0", move |b, &&size| {
                b.iter(|| t1ha0::Hash64::hash_with_seed(&DATA[..size], SEED));
            })
            .with_function("t1ha1", move |b, &&size| {
                b.iter(|| t1ha1::Hash64::hash_with_seed(&DATA[..size], SEED));
            })
            .with_function("t1ha2_atonce", move |b, &&size| {
                b.iter(|| t1ha2::Hash64AtOnce::hash_with_seed(&DATA[..size], SEED));
            });
    }

    if cfg!(any(feature = "sse4.2", target_feature = "sse4.2")) {
        bench = bench
            .with_function("metro_crc_1", move |b, &&size| {
                b.iter(|| metro::crc::Hash64_1::hash_with_seed(&DATA[..size], SEED as _));
            })
            .with_function("metro_crc_2", move |b, &&size| {
                b.iter(|| metro::crc::Hash64_2::hash_with_seed(&DATA[..size], SEED as _));
            });
    }

    c.bench(
        "hash64",
        bench.throughput(|&&size| Throughput::Bytes(size as _)),
    );
}

fn bench_hash128(c: &mut Criterion) {
    let mut bench = ParameterizedBenchmark::new(
        "city",
        move |b, &&size| {
            b.iter(|| city::Hash128::hash_with_seed(&DATA[..size], SEED as _));
        },
        &PARAMS,
    )
    .with_function("farm", move |b, &&size| {
        b.iter(|| farm::hash128_with_seed(&DATA[..size], SEED as _));
    })
    .with_function("farm_fingerprint", move |b, &&size| {
        b.iter(|| farm::fingerprint128(&DATA[..size]));
    })
    .with_function("metro_1", move |b, &&size| {
        b.iter(|| metro::Hash128_1::hash_with_seed(&DATA[..size], SEED as _));
    })
    .with_function("metro_2", move |b, &&size| {
        b.iter(|| metro::Hash128_2::hash_with_seed(&DATA[..size], SEED as _));
    })
    .with_function("murmur3_x64", move |b, &&size| {
        b.iter(|| murmur3::Hash128_x64::hash_with_seed(&DATA[..size], SEED as _));
    })
    .with_function("murmur3_x86", move |b, &&size| {
        b.iter(|| murmur3::Hash128_x86::hash_with_seed(&DATA[..size], SEED as _));
    })
    .with_function("spooky", move |b, &&size| {
        b.iter(|| spooky::hash128_with_seed(&DATA[..size], SEED as _));
    })
    .with_function("xxh3", move |b, &&size| {
        b.iter(|| xxh3::hash128_with_seed(&DATA[..size], SEED));
    })
    .with_function("highway", move |b, &&size| {
        b.iter(|| highway::hash128_with_seed(&DATA[..size], [SEED, SEED, SEED, SEED]));
    })
    .with_function("umash", move |b, &&size| {
        b.iter(|| umash::hash128_with_seed(&DATA[..size], SEED));
    });

    #[cfg(feature = "t1ha")]
    {
        bench = bench.with_function("t1ha2_atonce", move |b, &&size| {
            b.iter(|| t1ha2::Hash128AtOnce::hash_with_seed(&DATA[..size], SEED));
        });
    }

    if cfg!(any(feature = "sse4.2", target_feature = "sse4.2")) {
        bench = bench
            .with_function("city_crc", move |b, &&size| {
                b.iter(|| city::crc::Hash128::hash_with_seed(&DATA[..size], SEED as _));
            })
            .with_function("metro_crc_1", move |b, &&size| {
                b.iter(|| metro::crc::Hash128_1::hash_with_seed(&DATA[..size], SEED as _));
            })
            .with_function("metro_crc_2", move |b, &&size| {
                b.iter(|| metro::crc::Hash128_2::hash_with_seed(&DATA[..size], SEED as _));
            });
    }

    if cfg!(any(feature = "aes", target_feature = "aes")) {
        bench = bench.with_function("meow", move |b, &&size| {
            b.iter(|| meow::hash128(&DATA[..size]));
        });
    }

    c.bench(
        "hash128",
        bench.throughput(|&&size| Throughput::Bytes(size as _)),
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
