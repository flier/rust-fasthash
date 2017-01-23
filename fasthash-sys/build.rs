extern crate gcc;
#[cfg(feature = "bindgen")]
extern crate libbindgen;

#[cfg(not(feature = "bindgen"))]
use std::fs;
use std::env;
use std::path::Path;

#[cfg(feature = "bindgen")]
fn generate_binding(out_file: &Path) {
    let _ = libbindgen::builder()
        .clang_arg("-xc++")
        .clang_arg("--std=c++11")
        .clang_arg(if cfg!(feature = "sse42") {
            "-msse4.2"
        } else {
            "-march=native"
        })
        .header("src/fasthash.hpp")
        .no_unstable_rust()
        .disable_name_namespacing()
        .hide_type(".*PCCP.*")
        .whitelisted_function("^CityHash.*")
        .whitelisted_function("^farmhash.*")
        .whitelisted_function("^lookup3.*")
        .whitelisted_function("^metrohash.*")
        .whitelisted_function("^mum_hash.*")
        .whitelisted_function("^MurmurHash.*")
        .whitelisted_function("^SpookyHasher.*")
        .whitelisted_function("^t1ha.*")
        .whitelisted_function("^XXH.*")
        .link_static("fasthash")
        .generate()
        .unwrap()
        .write_to_file(out_file)
        .expect("fail to write bindings");
}

#[cfg(not(feature = "bindgen"))]
fn generate_binding(out_file: &Path) {
    let suffix = if cfg!(target_os = "macos") {
        "macos"
    } else {
        "linux"
    };

    fs::copy(format!("src/fasthash_{}.rs", suffix), out_file).expect("fail to copy bindings");
}

fn main() {
    let mut gcc_config = gcc::Config::new();

    gcc_config.file("src/fasthash.cpp")
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
        .file("src/smhasher/t1ha.cc")
        .file("src/smhasher/xxhash.c");

    if cfg!(feature = "sse42") {
        gcc_config.flag("-msse4.2")
            .file("src/smhasher/metrohash64crc.cpp")
            .file("src/smhasher/metrohash128crc.cpp");
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
