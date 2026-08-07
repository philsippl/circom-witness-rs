use std::{
    env,
    ffi::OsString,
    fs,
    path::{Path, PathBuf},
    process::Command,
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
    if cfg!(feature = "build-witness") {
        println!("cargo:rerun-if-env-changed=CIRCOM");
        println!("cargo:rerun-if-env-changed=CIRCOM_LIBRARY_PATH");
        println!("cargo:rerun-if-env-changed=WITNESS_CPP");

        let manifest_dir = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
        let witness_cpp = env::var_os("WITNESS_CPP").unwrap_or_else(|| {
            if cfg!(feature = "test-semaphore") {
                manifest_dir
                    .join("tests/fixtures/semaphore/semaphore.circom")
                    .into_os_string()
            } else if cfg!(feature = "test-world-id-query") {
                manifest_dir
                    .join("tests/fixtures/world-id-protocol/circom/main/OPRFQueryProof.circom")
                    .into_os_string()
            } else if cfg!(feature = "test-world-id") {
                manifest_dir
                    .join("tests/fixtures/world-id-protocol/circom/main/OPRFNullifierProof.circom")
                    .into_os_string()
            } else {
                panic!("WITNESS_CPP must point to the Circom circuit to compile");
            }
        });
        let circom = env::var_os("CIRCOM").unwrap_or_else(|| OsString::from("circom"));
        let circuit_file = PathBuf::from(witness_cpp);
        let circuit_name = circuit_file
            .file_stem()
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned();
        let library_path = env::var_os("CIRCOM_LIBRARY_PATH").or_else(|| {
            (circuit_name == "OPRFQueryProof" || circuit_name == "OPRFNullifierProof").then(|| {
                manifest_dir
                    .join("tests/fixtures/world-id-protocol/circom")
                    .into_os_string()
            })
        });
        if let Some(library_path) = &library_path {
            watch_circom_files(Path::new(library_path));
        } else {
            watch_circom_files(circuit_file.parent().unwrap());
        }
        if cfg!(feature = "test-semaphore")
            || cfg!(feature = "test-world-id")
            || cfg!(feature = "test-world-id-query")
        {
            println!("cargo:rustc-env=CIRCOM_WITNESS_TEST_CIRCUIT={circuit_name}");
        }

        let mut cmd = Command::new(circom);
        cmd.current_dir(&manifest_dir)
            .arg(fs::canonicalize(&circuit_file).unwrap())
            .arg("--c")
            .arg("--O2")
            .arg("--output")
            .arg(&manifest_dir);
        if let Some(library_path) = library_path {
            cmd.arg("-l").arg(fs::canonicalize(library_path).unwrap());
        }
        let status = cmd.status().unwrap();
        assert!(status.success());

        let cpp = manifest_dir
            .join(circuit_name.clone() + "_cpp")
            .join(circuit_name + ".cpp");

        println!("cargo:warning=\"{}\"", cpp.to_str().unwrap());

        let status = Command::new(manifest_dir.join("script/replace.sh"))
            .current_dir(&manifest_dir)
            .arg(cpp.to_str().unwrap())
            .status()
            .unwrap();
        assert!(status.success());

        cxx_build::bridge("src/generate.rs")
            .file("src/circuit.cc")
            .flag_if_supported("-std=c++14")
            .flag_if_supported("-w")
            .flag_if_supported("-d")
            .flag_if_supported("-g")
            .compile("circom-witness-rs");

        println!("cargo:rerun-if-changed=src/generate.rs");
        println!("cargo:rerun-if-changed=src/circuit.cc");
        println!("cargo:rerun-if-changed=include/circuit.h");
    }
}
