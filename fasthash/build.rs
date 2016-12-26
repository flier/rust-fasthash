use std::env;
use std::fs::File;
use std::io::Write;
use std::path::Path;

fn snake_case_name(name: &str) -> String {
    name.chars()
        .enumerate()
        .map(|(i, c)| if c.is_uppercase() {
            format!("{}{}",
                    if i == 0 { "" } else { "_" },
                    c.to_lowercase().next().unwrap())
        } else {
            format!("{}", c)
        })
        .collect::<Vec<String>>()
        .join("")
}

fn main() {
    let out_dir = env::var("OUT_DIR").unwrap();
    let dest_path = Path::new(&out_dir).join("benches.rs");
    let mut f = File::create(&dest_path).unwrap();

    let hashes = vec![("city", vec!["CityHash32", "CityHash64", "CityHash128", "CityHashCrc128"]),
                      ("farm", vec!["FarmHash32", "FarmHash64", "FarmHash128"]),
                      ("metro",
                       vec!["MetroHash64_1",
                            "MetroHash64_2",
                            "MetroHash128_1",
                            "MetroHash128_2",
                            "MetroHash64Crc_1",
                            "MetroHash64Crc_2",
                            "MetroHash128Crc_1",
                            "MetroHash128Crc_2"]),
                      ("mum", vec!["MumHash"]),
                      ("murmur", vec!["Murmur", "MurmurAligned"]),
                      ("murmur2",
                       vec!["Murmur2",
                            "Murmur2A",
                            "MurmurNeutral2",
                            "MurmurAligned2",
                            "Murmur2_x64_64",
                            "Murmur2_x86_64"]),
                      ("murmur3", vec!["Murmur3_x86_32", "Murmur3_x86_128", "Murmur3_x64_128"]),
                      ("spooky", vec!["SpookyHash32", "SpookyHash64", "SpookyHash128"]),
                      ("t1ha", vec!["T1ha32Le", "T1ha32Be", "T1ha64Le", "T1ha64Be", "T1ha64Crc"]),
                      ("xx", vec!["XXHash32", "XXHash64"])];

    for (module, methods) in hashes {
        for method in methods {
            for shift in 4..10 {
                let bench = format!("
#[bench]
fn bench_{name}_key_{keysize}(b: &mut Bencher) {{
    bench_fasthash::<{module}::{method}>(b, {keysize});
}}",
                                    module = module,
                                    name = snake_case_name(method),
                                    method = method,
                                    keysize = 1 << shift);

                f.write_all(bench.as_str().as_bytes()).unwrap();
            }
        }
    }

    let hashers = vec!["SipHasher",
                       "FnvHasher",
                       "CityHasher",
                       "CityHasherExt",
                       "FarmHasher",
                       "FarmHasherExt",
                       "MetroHasher",
                       "MetroHasherExt",
                       "MumHasher",
                       "MurmurHasher",
                       "Murmur2Hasher",
                       "Murmur3Hasher",
                       "Murmur3HasherExt",
                       "SpookyHasher",
                       "SpookyHasherExt",
                       "T1haHasher",
                       "XXHasher"];

    for hasher in hashers {
        let name = snake_case_name(hasher);

        for shift in 4..10 {
            let bench = format!("
#[bench]
fn bench_{name}_key_{keysize}(b: &mut \
                                 Bencher) {{
    bench_hasher::<{hasher}>(b, {keysize});
}}",
                                name = name,
                                hasher = hasher,
                                keysize = 1 << shift);

            f.write_all(bench.as_str().as_bytes()).unwrap();
        }
    }
}
