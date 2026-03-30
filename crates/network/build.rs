fn main() {
    buffa_build::Config::new()
        .use_buf()
        .files(&["protobuf/gossipsub.proto", "protobuf/identify.proto"])
        .includes(&["protobuf"])
        .out_dir("src/p2p/generated")
        .compile()
        .unwrap();
}
