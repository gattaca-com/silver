//! Regenerates the checked-in protobuf code (`just proto`): every `protobuf/`
//! folder under a crate's `src/` into the `generated/` folder beside it. Not a
//! build script: buffa's buf mode reruns whenever a crate lacks a `buf.yaml`,
//! so codegen at build time rebuilt every dependent crate on each cargo
//! invocation.

use std::{collections::BTreeMap, env, path::PathBuf};

use buffa_build::Config;

fn main() {
    let pattern = concat!(env!("CARGO_MANIFEST_DIR"), "/../*/src/**/protobuf/*.proto");
    let mut protos_by_dir = BTreeMap::<PathBuf, Vec<String>>::new();
    for proto in glob::glob(pattern).expect("glob pattern") {
        let proto = proto.expect("readable proto path");
        let name = proto.file_name().unwrap().to_string_lossy();
        let module_dir = proto.parent().and_then(|dir| dir.parent()).expect("module dir");
        protos_by_dir.entry(module_dir.into()).or_default().push(format!("protobuf/{name}"));
    }
    for (module_dir, protos) in protos_by_dir {
        // buf resolves `protobuf/` from the working directory.
        env::set_current_dir(&module_dir).expect("module dir");
        Config::new()
            .use_buf()
            .files(&protos)
            .includes(&["protobuf"])
            .out_dir("generated")
            .compile()
            .unwrap_or_else(|e| panic!("{}: {e}", module_dir.display()));
    }
}
