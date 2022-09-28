fn main() {
    use std::env;
    use std::path::PathBuf;
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
        .allowlist_type("aes_context")
        .allowlist_function("aes_set_key")
        .allowlist_function("aes_encrypt")
        .allowlist_function("aes_decrypt")
        .allowlist_type("AES_CMAC_CTX")
        .allowlist_function("AES_CMAC_Init")
        .allowlist_function("AES_CMAC_SetKey")
        .allowlist_function("AES_CMAC_Update")
        .allowlist_function("AES_CMAC_Final")
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
