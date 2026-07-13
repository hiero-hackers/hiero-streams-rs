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
    println!("cargo:rerun-if-changed=proto-hapi");
    let out = std::env::var("OUT_DIR")?;
    // Each unit gets its own out dir: both trees contain a `proto`
    // protobuf package, and sharing OUT_DIR lets the second unit
    // clobber the first's generated files.
    std::fs::create_dir_all(format!("{out}/rcd"))?;
    std::fs::create_dir_all(format!("{out}/hapi"))?;
    prost_build::Config::new()
        .out_dir(format!("{out}/rcd"))
        .include_file("hiero_protos.rs")
        .compile_protos(
            &[
                "proto/streams_record_stream_file.proto",
                "proto/streams_signature_file.proto",
                "proto/services_transaction_contents.proto",
            ],
            &["proto"],
        )?;
    // Second, independent compile unit: the block-stream protos from
    // hiero-consensus-node (see proto-hapi/VENDOR_COMMIT). Kept
    // separate because that tree uses its own directory layout and
    // re-declares `package proto` services types; isolation avoids
    // any clash with the record-file unit above.
    prost_build::Config::new()
        .out_dir(format!("{out}/hapi"))
        .include_file("hapi_protos.rs")
        .compile_protos(&["proto-hapi/block/stream/block.proto"], &["proto-hapi"])?;
    Ok(())
}
