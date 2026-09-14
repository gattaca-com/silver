fn main() {
    buffa_build::Config::new()
        .use_buf()
        .use_bytes_type()
        .preserve_unknown_fields(false)
        .files(&["protobuf/eraftpb.proto"])
        .includes(&["protobuf"])
        .out_dir("src/cluster/generated")
        .compile()
        .unwrap();
}
