# Protobuf code

A `.proto` file lives in a `protobuf/` folder beside the module that uses it,
e.g. `crates/control/src/cluster/protobuf/`. The Rust generated from it is
checked in under the `generated/` folder next to that, so building needs no
protobuf tooling.

After adding or editing a `.proto`:

1. Run `just proto`. It needs [`buf`](https://buf.build/docs/installation).
2. Commit the regenerated files with the `.proto` change.

`just proto` runs `crates/proto_gen`, which compiles every `protobuf/` folder
under a crate's `src/` with buffa's default options. A new proto file or folder
needs no other edit. Code that hands generated messages to another library
converts at that boundary, as `control/src/cluster/wire.rs` does for
`raft-proto`.

Codegen is not a build script on purpose. buffa's buf mode watches a `buf.yaml`
at each crate root, and a missing one is always stale. Every cargo invocation
then reran the build scripts and relinked their dependents: about 10 s per test
build and 36 s per `perf-local` build.
