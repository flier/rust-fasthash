#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

use cfg_if::cfg_if;

cfg_if! {
    if #[cfg(feature = "gen")] {
        include!(concat!(env!("OUT_DIR"), "/fasthash.rs"));
    } else {
        include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/fasthash.rs"));
    }
}
