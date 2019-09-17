#![allow(non_camel_case_types, non_snake_case, non_upper_case_globals)]

use cfg_if::cfg_if;

cfg_if! {
    if #[cfg(feature = "gen")] {
        include!(concat!(env!("OUT_DIR"), "/fasthash.rs"));
    } else if #[cfg(target_os = "linux")] {
        include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/linux.rs"));
    } else if #[cfg(target_os = "macos")] {
        include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/macos.rs"));
    }
}
