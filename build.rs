fn main() {
    // Check if the target OS is Windows
    if std::env::var("CARGO_CFG_TARGET_OS").unwrap() == "windows" {
        println!("cargo:rustc-link-lib=dylib:+verbatim=resources/resources.res");
    }
}
