use std::{
    env, fs,
    path::{Path, PathBuf},
};

fn watch_circom_files(path: &Path) {
    if path.is_dir() {
        for entry in fs::read_dir(path).unwrap() {
            watch_circom_files(&entry.unwrap().path());
        }
    } else if path
        .extension()
        .is_some_and(|extension| extension == "circom")
    {
        println!("cargo:rerun-if-changed={}", path.display());
    }
}

fn main() {
    if !cfg!(feature = "build-witness") {
        return;
    }

    println!("cargo:rerun-if-env-changed=CIRCOM_WITNESS");
    println!("cargo:rerun-if-env-changed=CIRCOM_LIBRARY_PATH");
    // Kept as a compatibility alias for existing users.
    println!("cargo:rerun-if-env-changed=WITNESS_CPP");

    let manifest_dir = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let circuit_path = env::var_os("CIRCOM_WITNESS")
        .or_else(|| env::var_os("WITNESS_CPP"))
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            if cfg!(feature = "test-semaphore") {
                manifest_dir.join("tests/fixtures/semaphore/semaphore.circom")
            } else if cfg!(feature = "test-world-id-query") {
                manifest_dir
                    .join("tests/fixtures/world-id-protocol/circom/main/OPRFQueryProof.circom")
            } else if cfg!(feature = "test-world-id") {
                manifest_dir
                    .join("tests/fixtures/world-id-protocol/circom/main/OPRFNullifierProof.circom")
            } else {
                panic!("CIRCOM_WITNESS must point to the Circom circuit to compile");
            }
        });
    let circuit_path = fs::canonicalize(&circuit_path).unwrap_or_else(|error| {
        panic!(
            "failed to resolve Circom circuit {}: {error}",
            circuit_path.display()
        )
    });
    let circuit_name = circuit_path.file_stem().unwrap().to_str().unwrap();

    let library_path = env::var_os("CIRCOM_LIBRARY_PATH")
        .map(PathBuf::from)
        .or_else(|| {
            (circuit_name == "OPRFQueryProof" || circuit_name == "OPRFNullifierProof")
                .then(|| manifest_dir.join("tests/fixtures/world-id-protocol/circom"))
        })
        .map(|path| fs::canonicalize(path).unwrap());

    if let Some(library_path) = &library_path {
        watch_circom_files(library_path);
        println!(
            "cargo:rustc-env=CIRCOM_WITNESS_LIBRARY_PATH={}",
            library_path.display()
        );
    } else {
        watch_circom_files(circuit_path.parent().unwrap());
    }
    println!(
        "cargo:rustc-env=CIRCOM_WITNESS_CIRCUIT={}",
        circuit_path.display()
    );

    if cfg!(feature = "test-semaphore")
        || cfg!(feature = "test-world-id")
        || cfg!(feature = "test-world-id-query")
    {
        println!("cargo:rustc-env=CIRCOM_WITNESS_TEST_CIRCUIT={circuit_name}");
    }
}
