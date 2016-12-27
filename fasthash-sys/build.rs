extern crate gcc;
extern crate libbindgen;

use std::env;
use std::path::Path;

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
        .write_to_file(Path::new(&out_dir).join("fasthash.rs"))
        .expect("Couldn't write bindings!");

    if cfg!(target_os = "macos") {
        println!("cargo:rustc-link-lib=dylib=c++");
    } else {
        println!("cargo:rustc-link-lib=dylib=stdc++");
    }
}
