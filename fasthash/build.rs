use std::env;
use std::fs::File;
use std::io::Write;
use std::path::Path;

fn main() {
    let out_dir = env::var("OUT_DIR").unwrap();
    let dest_path = Path::new(&out_dir).join("benches.rs");
    let mut f = File::create(&dest_path).unwrap();

    let hashes = vec![("city", vec!["hash32", "hash64", "hash128"]),
                      ("farm", vec!["hash32", "hash64", "hash128"]),
                      ("metro", vec!["hash64", "hash128"]),
                      ("mum", vec!["hash64"]),
                      ("murmur", vec!["hash32"]),
                      ("murmur2", vec!["hash32", "hash64"]),
                      ("murmur3", vec!["hash32", "hash128"]),
                      ("spooky", vec!["hash32", "hash64", "hash128"]),
                      ("t1ha", vec!["hash32", "hash64"]),
                      ("xx", vec!["hash32", "hash64"])];

    for (hash, methods) in hashes {
        for method in methods {
            for shift in 4..10 {
                let bench = format!("
#[bench]
fn bench_{hash}_{method}_key_{keysize}(b: &mut Bencher) {{
    bench_hash(b, {hash}::{method}, {keysize});
}}",
                                    hash = hash,
                                    method = method,
                                    keysize = 1 << shift);

                f.write_all(bench.as_str().as_bytes()).unwrap();
            }
        }
    }
}
