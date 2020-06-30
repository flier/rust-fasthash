use std::env;
use std::path::Path;

use lazy_static::lazy_static;
use raw_cpuid::CpuId;

lazy_static! {
    static ref CPUID: CpuId = CpuId::new();
}

fn has_aesni() -> bool {
    cfg!(feature = "native")
        && CPUID
            .get_feature_info()
            .map_or(false, |features| features.has_aesni())
}

fn has_sse41() -> bool {
    cfg!(feature = "native")
        && CPUID
            .get_feature_info()
            .map_or(false, |features| features.has_sse41())
}

fn has_sse42() -> bool {
    cfg!(feature = "native")
        && CPUID
            .get_feature_info()
            .map_or(false, |features| features.has_sse42())
}

fn has_avx() -> bool {
    cfg!(feature = "native")
        && CPUID
            .get_feature_info()
            .map_or(false, |features| features.has_avx())
}

fn has_avx2() -> bool {
    cfg!(feature = "native")
        && CPUID
            .get_extended_feature_info()
            .map_or(false, |features| features.has_avx2())
}

fn support_aesni() -> bool {
    cfg!(any(feature = "aes", target_feature = "aes")) || has_aesni()
}

fn support_sse41() -> bool {
    cfg!(any(feature = "sse41", target_feature = "sse41")) || has_sse41()
}

fn support_sse42() -> bool {
    cfg!(any(feature = "sse42", target_feature = "sse42")) || has_sse42()
}

fn support_avx() -> bool {
    cfg!(any(feature = "avx", target_feature = "avx")) || has_avx()
}

fn support_avx2() -> bool {
    cfg!(any(feature = "avx2", target_feature = "avx2")) || has_avx2()
}

#[cfg(feature = "gen")]
fn generate_binding(out_file: &Path) {
    println!("generate binding file @ {:?}.", out_file);

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
        .clang_arg(if cfg!(feature = "native") {
            "-march=native"
        } else {
            ""
        })
        .clang_arg(if support_sse42() { "-msse4.2" } else { "" })
        .clang_arg(if support_avx() { "-mavx" } else { "" })
        .clang_arg(if support_avx2() { "-mavx2" } else { "" })
        .header("src/fasthash.hpp")
        .size_t_is_usize(true)
        .generate_inline_functions(true)
        .disable_name_namespacing()
        .whitelist_function("^CityHash.*")
        .whitelist_function("^farmhash.*")
        .whitelist_function("^lookup3.*")
        .whitelist_function("^metrohash.*")
        .whitelist_function("^mum_hash.*")
        .whitelist_function("^MurmurHash.*")
        .whitelist_function("^SpookyHasher.*")
        .whitelist_function("^t1ha.*")
        .blacklist_function("^t1ha_selfcheck__.*")
        .whitelist_function("^XXH.*")
        .whitelist_function("^HighwayHash.*")
        .generate()
        .unwrap()
        .write_to_file(out_file)
        .expect("fail to write bindings");
}

#[cfg(not(feature = "gen"))]
fn generate_binding(_out_file: &Path) {
    println!("direct include pregenerated binding file.");
}

fn build_fasthash() {
    let mut build = cc::Build::new();

    build
        .cpp(true)
        .flag("-std=c++11")
        .flag("-Wno-implicit-fallthrough")
        .flag("-Wno-unknown-attributes")
        .include("src/highwayhash")
        .file("src/fasthash.cpp")
        .file("src/smhasher/City.cpp")
        .file("src/smhasher/farmhash-c.c")
        .file("src/smhasher/lookup3.cpp")
        .file("src/smhasher/mum.cc")
        .file("src/smhasher/metrohash/metrohash64.cpp")
        .file("src/smhasher/metrohash/metrohash128.cpp")
        .file("src/smhasher/MurmurHash1.cpp")
        .file("src/smhasher/MurmurHash2.cpp")
        .file("src/smhasher/MurmurHash3.cpp")
        .file("src/smhasher/Spooky.cpp")
        .file("src/xxHash/xxhash.c");

    if support_sse42() {
        build
            .flag("-msse4.2")
            .file("src/smhasher/metrohash/metrohash64crc.cpp")
            .file("src/smhasher/metrohash/metrohash128crc.cpp");
    }

    build.static_flag(true).compile("fasthash");
}

fn build_t1() {
    let mut build = cc::Build::new();

    build
        .file("src/t1ha/src/t1ha0.c")
        .file("src/t1ha/src/t1ha1.c")
        .file("src/t1ha/src/t1ha2.c");

    // indirect functions are not supported on all targets (e.g. x86_64-unknown-linux-musl)
    build.define("T1HA_USE_INDIRECT_FUNCTIONS", Some("0"));

    if support_aesni() {
        build
            .define("T1HA0_RUNTIME_SELECT", Some("1"))
            .define("T1HA0_AESNI_AVAILABLE", Some("1"))
            .flag("-maes")
            .file("src/t1ha/src/t1ha0_ia32aes_noavx.c")
            .file("src/t1ha/src/t1ha0_ia32aes_avx.c")
            .file("src/t1ha/src/t1ha0_ia32aes_avx2.c");

        if support_avx() {
            build.flag("-mavx");
        }

        if support_avx2() {
            build.flag("-mavx2");
        }
    }

    build.static_flag(true).compile("t1ha");
}

fn build_highway() {
    let mut build = cc::Build::new();

    build
        .cpp(true)
        .flag("-std=c++11")
        .include("src/highwayhash")
        .file("src/highwayhash/highwayhash/arch_specific.cc")
        .file("src/highwayhash/highwayhash/instruction_sets.cc")
        .file("src/highwayhash/highwayhash/os_specific.cc")
        .file("src/highwayhash/highwayhash/hh_portable.cc")
        .file("src/highwayhash/highwayhash/c_bindings.cc");

    if cfg!(any(target_arch = "x86", target_arch = "x86_64")) {
        if support_sse41() {
            build
                .flag("-msse4.1")
                .file("src/highwayhash/highwayhash/hh_sse41.cc");
        }

        if support_avx2() {
            build
                .flag("-mavx2")
                .file("src/highwayhash/highwayhash/hh_avx2.cc");
        }
    }

    build.static_flag(true).compile("highwayhash");
}

fn main() {
    if has_aesni() {
        println!(r#"cargo:rustc-cfg=feature="aes""#);
    }
    if has_sse41() {
        println!(r#"cargo:rustc-cfg=feature="sse41""#);
    }
    if has_sse42() {
        println!(r#"cargo:rustc-cfg=feature="sse42""#);
    }
    if has_avx() {
        println!(r#"cargo:rustc-cfg=feature="avx""#);
    }
    if has_avx2() {
        println!(r#"cargo:rustc-cfg=feature="avx2""#);
    }

    build_fasthash();
    if cfg!(feature = "t1ha") {
        build_t1();
    }
    build_highway();

    let out_dir = env::var("OUT_DIR").unwrap();
    let out_file = Path::new(&out_dir).join("fasthash.rs");

    println!("cargo:rerun-if-changed=src/fasthash.hpp");
    println!("cargo:rerun-if-changed=src/fasthash.cpp");

    generate_binding(&out_file);
}
