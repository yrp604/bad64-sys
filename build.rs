use std::env;
use std::ffi::OsStr;
use std::path::PathBuf;

fn main() {
    let ignorelist: Vec<&OsStr> = [
        "test.c", "gofer.c", "format.c", "encodings_fmt.c",
    ].iter().map(OsStr::new).collect();

    let dotc_files = glob::glob("arch-arm64/disassembler/*.c")
        .expect("Failed to read glob pattern")
        .map(|x| x.unwrap())
        .filter(|x| !ignorelist.as_slice().contains(&x.file_name().unwrap()));

    // Compile the library
    cc::Build::new()
        .files(dotc_files)
        .include("arch-arm64/disassembler")
        .compile("arm64decode");

    // Generate the bindings

    // Tell cargo to tell rustc to link the compiled disassembler
    println!("cargo:rustc-link-lib=arm64decode");

    // Tell cargo to invalidate the built crate whenever the wrapper changes
    println!("cargo:rerun-if-changed=wrapper.h");

    // The bindgen::Builder is the main entry point
    // to bindgen, and lets you build up options for
    // the resulting bindings.
    let bindings = bindgen::Builder::default()
        // The input header we would like to generate
        // bindings for.
        .header("wrapper.h")
        // Tell cargo to invalidate the built crate whenever any of the
        // included header files changed.
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        // common derives
        .derive_debug(true)
        .derive_eq(true)
        .derive_hash(true)
        .derive_partialeq(true)
        .rustified_enum("OperandClass")
        .rustified_enum("ShiftType")
        .rustified_enum("ArrangementSpec")
        // Finish the builder and generate the bindings.
        .generate()
        // Unwrap the Result and panic on failure.
        .expect("Unable to generate bindings");

    // Write the bindings to the $OUT_DIR/bindings.rs file.
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
