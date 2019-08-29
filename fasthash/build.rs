fn main() {
    let cpuid = raw_cpuid::CpuId::new();

    if cfg!(feature = "native") {
        if let Some(features) = cpuid.get_feature_info() {
            if features.has_aesni() {
                println!(r#"cargo:rustc-cfg=feature="aes""#);
            }
            if features.has_sse41() {
                println!(r#"cargo:rustc-cfg=feature="sse41""#);
            }
            if features.has_sse42() {
                println!(r#"cargo:rustc-cfg=feature="sse42""#);
            }
            if features.has_avx() {
                println!(r#"cargo:rustc-cfg=feature="avx""#);
            }
        }

        if let Some(features) = cpuid.get_extended_feature_info() {
            if features.has_avx2() {
                println!(r#"cargo:rustc-cfg=feature="avx2""#);
            }
        }
    }
}
