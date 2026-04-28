fn main() {
    buffa_build::Config::new()
        .use_buf()
        .files(&["protobuf/gossipsub.proto"])
        .includes(&["protobuf"])
        .out_dir("src/generated")
        .compile()
        .unwrap();
}
