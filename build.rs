fn main() {
    cxx_build::bridge("src/lib.rs")
        .file(&env!("WITNESS_CPP"))
        .flag_if_supported("-std=c++14")
        .flag_if_supported("-w")
        .flag_if_supported("-d")
        .compile("witness");

    // println!("cargo:rerun-if-changed=src/main.rs");
    // println!("cargo:rerun-if-changed=src/blobstore.cc");
    // println!("cargo:rerun-if-changed=include/blobstore.h");
}
