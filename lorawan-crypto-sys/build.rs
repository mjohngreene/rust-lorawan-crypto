#[cfg(workaround_build)]
fn main() {
    use std::env;
    use std::path::PathBuf;
    use std::process::Command;
    use cmake;
    use cmake::Config;

    let dst = Config::new("lorawan-crypto")
        .define("BUILD_TESTING", "OFF")
        .define("CMAKE_C_COMPILER_WORKS", "1")
        .define("CMAKE_CXX_COMPILER_WORKS", "1")
        .pic(false)
        .build();

    println!("cargo:rustc-link-search=native={}/lib", dst.display());
    println!("cargo:rustc-link-lib=static=lorawan-crypto");

    // make the bindings
    let bindings = bindgen::Builder::default()
        .raw_line("use cty;")
        .use_core()
        .ctypes_prefix("cty")
        .detect_include_paths(true)
        .header("lorawan-crypto/aes.h")
        .header("lorawan-crypto/cmac.h")
        .trust_clang_mangling(false)
        .rustfmt_bindings(true)
        .whitelist_type("aes_context")
        .whitelist_function("aes_set_key")
        .whitelist_function("aes_encrypt")
        .whitelist_function("aes_decrypt")
        .whitelist_type("AES_CMAC_CTX")
        .whitelist_function("AES_CMAC_Init")
        .whitelist_function("AES_CMAC_SetKey")
        .whitelist_function("AES_CMAC_Update")
        .whitelist_function("AES_CMAC_Final")
        .derive_copy(false)
        .derive_debug(false)
        .layout_tests(false)
        .generate()
        .expect("Failed to generate lorawan-crypto bindings!");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}

#[cfg(not(workaround_build))]
fn main() {
    cargo_5730::run_build_script();
}