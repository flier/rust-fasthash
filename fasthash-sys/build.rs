#[cfg(feature = "bindgen")]
extern crate bindgen;
extern crate gcc;

use std::env;
#[cfg(not(feature = "bindgen"))]
use std::fs;
use std::path::Path;

#[cfg(feature = "bindgen")]
fn generate_binding(out_file: &Path) {
    let _ = bindgen::builder()
        .clang_arg("--std=c++11")
        .clang_arg(if cfg!(feature = "sse42") {
            "-msse4.2"
        } else {
            ""
        })
        .clang_arg(if cfg!(feature = "aes") { "-maes" } else { "" })
        .clang_arg(if cfg!(feature = "avx") { "-mavx" } else { "" })
        .clang_arg(if cfg!(feature = "avx2") { "-mavx2" } else { "" })
        .header("src/fasthash.hpp")
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
        .whitelist_function("^XXH.*")
        .generate()
        .unwrap()
        .write_to_file(out_file)
        .expect("fail to write bindings");
}

#[cfg(not(feature = "bindgen"))]
fn generate_binding(out_file: &Path) {
    let os = if cfg!(target_os = "macos") {
        "macos"
    } else {
        "linux"
    };

    fs::copy(format!("src/{}/fasthash.rs", os), out_file).expect("fail to copy bindings");
}

fn main() {
    let mut gcc_config = gcc::Build::new();

    gcc_config
        .define("T1HA0_RUNTIME_SELECT", Some("1"))
        .flag("-Wno-implicit-fallthrough")
        .flag("-Wno-unknown-attributes")
        .file("src/fasthash.cpp")
        .file("src/smhasher/City.cpp")
        .file("src/smhasher/farmhash-c.c")
        .file("src/smhasher/lookup3.cpp")
        .file("src/smhasher/mum.cc")
        .file("src/smhasher/metrohash64.cpp")
        .file("src/smhasher/metrohash128.cpp")
        .file("src/smhasher/MurmurHash1.cpp")
        .file("src/smhasher/MurmurHash2.cpp")
        .file("src/smhasher/MurmurHash3.cpp")
        .file("src/smhasher/Spooky.cpp")
        .file("src/smhasher/t1ha/t1ha0.c")
        .file("src/smhasher/t1ha/t1ha1.c")
        .file("src/smhasher/t1ha/t1ha2.c")
        .file("src/smhasher/xxhash.c");

    if cfg!(feature = "sse42") {
        gcc_config
            .flag("-msse4.2")
            .file("src/smhasher/metrohash64crc.cpp")
            .file("src/smhasher/metrohash128crc.cpp");
    }

    if cfg!(feature = "aes") {
        gcc_config
            .define("T1HA0_AESNI_AVAILABLE", Some("1"))
            .flag("-maes")
            .file("src/smhasher/t1ha/t1ha0_ia32aes_noavx.c");

        if cfg!(feature = "avx") {
            gcc_config
                .flag("-mavx")
                .file("src/smhasher/t1ha/t1ha0_ia32aes_avx.c");
        }

        if cfg!(feature = "avx2") {
            gcc_config
                .flag("-mavx2")
                .file("src/smhasher/t1ha/t1ha0_ia32aes_avx2.c");
        }
    }

    gcc_config.compile("libfasthash.a");

    let out_dir = env::var("OUT_DIR").unwrap();
    let out_file = Path::new(&out_dir).join("src/fasthash.rs");

    generate_binding(&out_file);

    if cfg!(target_os = "macos") {
        println!("cargo:rustc-link-lib=dylib=c++");
    } else {
        println!("cargo:rustc-link-lib=dylib=stdc++");
        println!("cargo:rustc-link-lib=dylib=gcc");
    }
}
