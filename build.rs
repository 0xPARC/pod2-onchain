extern crate bindgen;

use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    println!("out_path: {:?}", out_path);

    let static_filepath = out_path.join("libgo.a");
    let header_filepath = out_path.join("libgo.h");
    let go_filepath = Path::new("ffi/main.go");

    if !static_filepath.exists()
        || static_filepath.metadata().unwrap().modified().unwrap()
            < go_filepath.metadata().unwrap().modified().unwrap()
    {
        // go build -buildmode=c-archive -o libgo.a ffi/main.go
        let mut go_build = Command::new("go");
        go_build
            .arg("build")
            .arg("-buildmode=c-archive")
            .arg("-o")
            .arg(static_filepath)
            .arg(go_filepath);

        go_build.status().expect("Go build failed");

        let bindings = bindgen::Builder::default()
            .header(header_filepath.to_str().unwrap())
            .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
            .generate()
            .expect("Unable to generate bindings");

        bindings
            .write_to_file(out_path.join("bindings.rs"))
            .expect("Couldn't write bindings!");
    }

    println!("cargo:rerun-if-changed=go/{:?}", go_filepath.to_str());
    println!(
        "cargo:rustc-link-search=native={}",
        out_path.to_str().unwrap()
    );
    println!("cargo:rustc-link-lib=static=go");
}
