use std::env;
use std::path::Path;

use lazy_static::lazy_static;
use raw_cpuid::{CpuId, ExtendedFeatures, FeatureInfo};

lazy_static! {
    static ref CPU_ID: CpuId = CpuId::new();
    static ref CPU_FEATURES: Option<FeatureInfo> = CPU_ID.get_feature_info();
    static ref CPU_EXTENDED_FEATURES: Option<ExtendedFeatures> = CPU_ID.get_extended_feature_info();
    static ref TARGET_FEATURES: Vec<String> = env::var("CARGO_CFG_TARGET_FEATURE")
        .map_or_else(|_| vec![], |s| s.split(',').map(|s| s.to_owned()).collect());
    static ref TARGET_ARCH: String = env::var("CARGO_CFG_TARGET_ARCH").unwrap();
    static ref TARGET_ENV: String = env::var("CARGO_CFG_TARGET_ENV").unwrap();
}

fn has_target_feature(feature: &str) -> bool {
    TARGET_FEATURES.iter().any(|name| name == feature)
}

fn has_aesni() -> bool {
    cfg!(feature = "native")
        && CPU_FEATURES
            .as_ref()
            .map_or(false, |features| features.has_aesni())
}

fn has_sse41() -> bool {
    cfg!(feature = "native")
        && CPU_FEATURES
            .as_ref()
            .map_or(false, |features| features.has_sse41())
}

fn has_sse42() -> bool {
    cfg!(feature = "native")
        && CPU_FEATURES
            .as_ref()
            .map_or(false, |features| features.has_sse42())
}

fn has_avx() -> bool {
    cfg!(feature = "native")
        && CPU_FEATURES
            .as_ref()
            .map_or(false, |features| features.has_avx())
}

fn has_avx2() -> bool {
    cfg!(feature = "native")
        && CPU_EXTENDED_FEATURES
            .as_ref()
            .map_or(false, |features| features.has_avx2())
}

fn support_aesni() -> bool {
    cfg!(feature = "aes") || has_target_feature("aes") || has_aesni()
}

#[allow(dead_code)]
fn support_sse41() -> bool {
    cfg!(feature = "sse41") || has_target_feature("sse41") || has_sse41()
}

fn support_sse42() -> bool {
    cfg!(feature = "sse42") || has_target_feature("sse42") || has_sse42()
}

fn support_avx() -> bool {
    cfg!(feature = "avx") || has_target_feature("avx") || has_avx()
}

fn support_avx2() -> bool {
    cfg!(feature = "avx2") || has_target_feature("avx2") || has_avx2()
}

#[cfg(all(not(feature = "gen"), any(target_os = "macos", target_os = "linux")))]
fn generate_binding(_out_file: &Path) {
    cargo_emit::warning!("pregenerated binding file.");
}

#[cfg(any(feature = "gen", not(any(target_os = "macos", target_os = "linux"))))]
fn generate_binding(out_file: &Path) {
    let _ = bindgen::builder()
        .clang_args(&["-x", "c++", "-std=c++11"])
        .clang_args(&[
            "-Dt1ha_EXPORTS",
            "-DXXH_STATIC_LINKING_ONLY",
            "-Isrc/highwayhash",
        ])
        .clang_args(if support_aesni() {
            &[
                "-maes",
                "-DT1HA0_RUNTIME_SELECT=1",
                "-DT1HA0_AESNI_AVAILABLE=1",
            ][..]
        } else {
            &[][..]
        })
        .clang_args(
            vec![
                if cfg!(feature = "native") {
                    Some("-march=native")
                } else {
                    None
                },
                if support_sse41() {
                    Some("-msse4.1")
                } else {
                    None
                },
                if support_sse42() {
                    Some("-msse4.2")
                } else {
                    None
                },
                if support_avx() { Some("-mavx") } else { None },
                if support_avx2() { Some("-mavx2") } else { None },
                if cfg!(feature = "city") {
                    Some("-DCITY_HASH=1")
                } else {
                    None
                },
                if cfg!(feature = "farm") {
                    Some("-DFARM_HASH=1")
                } else {
                    None
                },
                if cfg!(feature = "highway") {
                    Some("-DHIGHWAY_HASH=1")
                } else {
                    None
                },
                if cfg!(feature = "komi") {
                    Some("-DKOMI_HASH=1")
                } else {
                    None
                },
                if cfg!(feature = "lookup3") {
                    Some("-DLOOKUP3=1")
                } else {
                    None
                },
                if cfg!(feature = "meow") && matches!(TARGET_ARCH.as_str(), "x86" | "x86_64") {
                    Some("-DMEOW_HASH=1")
                } else {
                    None
                },
                if cfg!(feature = "metro") {
                    Some("-DMETRO_HASH=1")
                } else {
                    None
                },
                if cfg!(feature = "mum") {
                    Some("-DMUM_HASH=1")
                } else {
                    None
                },
                if cfg!(feature = "murmur") {
                    Some("-DMURMUR_HASH=1")
                } else {
                    None
                },
                if cfg!(feature = "mx3") {
                    Some("-DMX3_HASH=1")
                } else {
                    None
                },
                if cfg!(feature = "nm") {
                    Some("-DNM_HASH=1")
                } else {
                    None
                },
                if cfg!(feature = "pengy") {
                    Some("-DPENGY_HASH=1")
                } else {
                    None
                },
                if cfg!(feature = "prv") {
                    Some("-DPRV_HASH=1")
                } else {
                    None
                },
                if cfg!(feature = "spooky") {
                    Some("-DSPOOKY_HASH=1")
                } else {
                    None
                },
                if cfg!(feature = "t1ha") {
                    Some("-DT1_HASH=1")
                } else {
                    None
                },
                if cfg!(feature = "umash")
                    && matches!(TARGET_ARCH.as_str(), "x86" | "x86_64" | "aarch64")
                {
                    Some("-DUMASH=1")
                } else {
                    None
                },
                if cfg!(feature = "wy") {
                    Some("-DWY_HASH=1")
                } else {
                    None
                },
                if cfg!(feature = "xx") {
                    Some("-DXX_HASH=1")
                } else {
                    None
                },
            ]
            .into_iter()
            .flatten(),
        )
        .header("src/fasthash.hpp")
        .size_t_is_usize(true)
        .generate_inline_functions(true)
        .disable_name_namespacing()
        .allowlist_function("^CityHash.*")
        .allowlist_function("^farmhash.*")
        .allowlist_function("^HighwayHash.*")
        .allowlist_function("^komi.*")
        .allowlist_function("^lookup3.*")
        .allowlist_function("^metrohash.*")
        .allowlist_function("^mum_hash.*")
        .allowlist_function("^MurmurHash.*")
        .allowlist_function("^mx3hash.*")
        .allowlist_function("^NMHASH.*")
        .allowlist_function("^pengy.*")
        .allowlist_function("^prvhash.*")
        .allowlist_function("^SpookyHasher.*")
        .allowlist_function("^t1ha.*")
        .allowlist_function("^umash.*")
        .allowlist_function("^wyhash.*")
        .allowlist_function("^XXH.*")
        .allowlist_function("^Meow.*")
        .blocklist_function("^t1ha_selfcheck__.*")
        .allowlist_var("^Meow.*")
        .allowlist_var("^PRH64S_.*")
        .allowlist_var("^umash_.*")
        .generate()
        .unwrap()
        .write_to_file(out_file)
        .expect("fail to write bindings");

    cargo_emit::warning!("generate binding file @ {:?}.", out_file);
}

fn build_fasthash() {
    let mut build = cc::Build::new();

    build
        .cpp(true)
        .include("src/highwayhash")
        .flag("-std=c++11")
        .flag_if_supported("-Wno-implicit-fallthrough")
        .flag_if_supported("-Wno-unknown-attributes")
        .flag_if_supported("-Wno-sign-compare")
        .file("src/fasthash.cpp");

    if cfg!(feature = "city") {
        build.flag("-DCITY_HASH=1").file("src/smhasher/City.cpp");
    }

    if cfg!(feature = "farm") {
        build
            .flag("-DFARM_HASH=1")
            .file("src/smhasher/farmhash-c.c");
    }

    if cfg!(feature = "komi") {
        build.flag("-DKOMI_HASH=1");
    }

    if cfg!(feature = "highway") {
        build.flag("-DHIGHWAY_HASH=1");
    }

    if cfg!(feature = "lookup3") {
        build.flag("-DLOOKUP3=1").file("src/smhasher/lookup3.cpp");
    }

    if cfg!(feature = "meow") && matches!(TARGET_ARCH.as_str(), "x86" | "x86_64") {
        build.flag("-DMEOW_HASH=1");
    }

    if cfg!(feature = "mx3") {
        build.flag("-DMX3_HASH=1");
    }

    if cfg!(feature = "nm") {
        build.flag("-DNM_HASH=1");
    }

    if cfg!(feature = "pengy") {
        build
            .flag("-DPENGY_HASH=1")
            .file("src/pengyhash/pengyhash.c");
    }

    if cfg!(feature = "prv") {
        build.flag("-DPRV_HASH=1");
    }

    if cfg!(feature = "t1ha") {
        build.flag("-DT1_HASH=1");
    }

    if cfg!(feature = "metro") {
        build
            .flag("-DMETRO_HASH=1")
            .file("src/smhasher/metrohash/metrohash64.cpp")
            .file("src/smhasher/metrohash/metrohash128.cpp");

        if support_sse42() {
            build
                .file("src/smhasher/metrohash/metrohash64crc.cpp")
                .file("src/smhasher/metrohash/metrohash128crc.cpp");
        }
    }

    if cfg!(feature = "mum") {
        build.flag("-DMUM_HASH=1").file("src/smhasher/mum.cc");
    }

    if cfg!(feature = "murmur") {
        build
            .flag("-DMURMUR_HASH=1")
            .file("src/smhasher/MurmurHash1.cpp")
            .file("src/smhasher/MurmurHash2.cpp")
            .file("src/smhasher/MurmurHash3.cpp");
    }

    if cfg!(feature = "spooky") {
        build
            .flag("-DSPOOKY_HASH=1")
            .file("src/smhasher/Spooky.cpp");
    }

    if cfg!(feature = "wy") {
        build.flag("-DWY_HASH=1");
    }

    if cfg!(feature = "xx") {
        build.flag("-DXX_HASH=1").file("src/xxHash/xxhash.c");
    }

    if cfg!(feature = "native") {
        build.flag("-march=native");
    } else {
        if has_target_feature("aes") {
            build.flag("-maes");
        }
        if has_target_feature("sse41") {
            build.flag("-msse41");
        }
        if has_target_feature("sse42") {
            build.flag("-msse4.2");
        }
        if has_target_feature("avx") {
            build.flag("-mavx");
        }
        if has_target_feature("avx2") {
            build.flag("-mavx2");
        }
    }

    build.static_flag(true).compile("fasthash");
}

fn build_t1() {
    let mut build = cc::Build::new();

    build
        .file("src/smhasher/t1ha/t1ha0.c")
        .file("src/smhasher/t1ha/t1ha1.c")
        .file("src/smhasher/t1ha/t1ha2.c");

    // indirect functions are not supported on all targets (e.g. x86_64-unknown-linux-musl)
    if TARGET_ENV.as_str() == "musl" {
        build.define("T1HA_USE_INDIRECT_FUNCTIONS", Some("0"));
    }

    if support_aesni() {
        build
            .define("T1HA0_RUNTIME_SELECT", Some("1"))
            .define("T1HA0_AESNI_AVAILABLE", Some("1"))
            .flag("-maes")
            .file("src/smhasher/t1ha/t1ha0_ia32aes_noavx.c")
            .file("src/smhasher/t1ha/t1ha0_ia32aes_avx.c")
            .file("src/smhasher/t1ha/t1ha0_ia32aes_avx2.c");

        if support_avx() {
            build.flag("-mavx");
        }

        if support_avx2() {
            build.flag("-mavx2");
        }
    }

    build.static_flag(true).compile("t1ha");
}

fn build_umash() {
    let mut build = cc::Build::new();

    if cfg!(feature = "native") {
        build.flag("-march=native");
    }

    build
        .define("UMASH_LONG_INPUTS", "1")
        .file("src/smhasher/umash.c")
        .static_flag(true)
        .compile("umash");
}

fn build_highway() {
    let mut build = cc::Build::new();

    build
        .cpp(true)
        .flag("-std=c++11")
        .flag_if_supported("-Wno-sign-compare")
        .include("src/highwayhash")
        .file("src/highwayhash/highwayhash/arch_specific.cc")
        .file("src/highwayhash/highwayhash/instruction_sets.cc")
        .file("src/highwayhash/highwayhash/os_specific.cc")
        .file("src/highwayhash/highwayhash/hh_portable.cc")
        .file("src/highwayhash/highwayhash/c_bindings.cc");

    match TARGET_ARCH.as_str() {
        "x86" | "x86_64" => {
            build
                .flag("-msse4.1")
                .flag("-mavx2")
                .file("src/highwayhash/highwayhash/hh_sse41.cc")
                .file("src/highwayhash/highwayhash/hh_avx2.cc");
        }

        "aarch64" => {
            build.file("src/highwayhash/highwayhash/hh_neon.cc");
        }

        "powerpc64" => {
            build
                .flag("-mvsx")
                .flag("-mpower8-vector")
                .file("src/highwayhash/highwayhash/hh_vsx.cc");
        }
        _ => {}
    }

    build.static_flag(true).compile("highwayhash");
}

fn main() {
    if has_aesni() {
        cargo_emit::rustc_cfg!(r#"feature="aes""#);
    }
    if has_sse41() {
        cargo_emit::rustc_cfg!(r#"feature="sse41""#);
    }
    if has_sse42() {
        cargo_emit::rustc_cfg!(r#"feature="sse42""#);
    }
    if has_avx() {
        cargo_emit::rustc_cfg!(r#"feature="avx""#);
    }
    if has_avx2() {
        cargo_emit::rustc_cfg!(r#"feature="avx2""#);
    }

    build_fasthash();
    if cfg!(feature = "t1ha") {
        build_t1();
    }
    if cfg!(feature = "highway") {
        build_highway();
    }
    if cfg!(feature = "umash") && matches!(TARGET_ARCH.as_str(), "x86" | "x86_64" | "aarch64") {
        build_umash();
    }

    let out_dir = env::var("OUT_DIR").unwrap();
    let out_file = Path::new(&out_dir).join("fasthash.rs");

    cargo_emit::rerun_if_changed!("src/fasthash.hpp");
    cargo_emit::rerun_if_changed!("src/fasthash.cpp");

    generate_binding(&out_file);
}
