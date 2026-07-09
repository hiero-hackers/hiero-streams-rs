//! Compile the vendored Hedera protobufs.
//!
//! The `.proto` files under `proto/` are copied verbatim from
//! `@hashgraph/proto@2.25.0` — the same definitions the reference
//! TypeScript parser (hiero-recordstreams) compiles — so the two
//! implementations are version-locked by construction. Only the root
//! files are listed; protoc pulls in their import closure. The
//! definitions span multiple protobuf packages (`proto`,
//! `com.hedera.hapi.*`), so `include_file` generates one nested-module
//! wrapper covering all of them.

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=proto");
    prost_build::Config::new()
        .include_file("hiero_protos.rs")
        .compile_protos(
            &[
                "proto/streams_record_stream_file.proto",
                "proto/streams_signature_file.proto",
                "proto/services_transaction_contents.proto",
            ],
            &["proto"],
        )?;
    Ok(())
}
