//! Compile the protobuf definitions when the `grpc` feature is on.
//!
//! `protoc` is vendored rather than expected on PATH, so the build works in a container
//! with no toolchain installed and produces identical output everywhere. No network
//! access: a build script that downloads anything breaks hermetic and air-gapped builds.

fn main() -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(feature = "grpc")]
    {
        println!("cargo:rerun-if-changed=proto/secreton.proto");

        // SAFETY: build scripts run single-threaded before anything else observes the
        // environment.
        #[allow(unsafe_code)]
        unsafe {
            std::env::set_var("PROTOC", protoc_bin_vendored::protoc_bin_path()?);
        }

        let out_dir = std::path::PathBuf::from(std::env::var("OUT_DIR")?);

        // `compile` was renamed to `compile_protos` in tonic-build 0.13, and prost codegen
        // moved into `tonic-prost-build` in 0.14.
        tonic_prost_build::configure()
            .build_server(true)
            .build_client(true)
            // The descriptor set backs the reflection service, so `grpcurl` can describe
            // the API without being handed the .proto file.
            .file_descriptor_set_path(out_dir.join("secreton_descriptor.bin"))
            .compile_protos(&["proto/secreton.proto"], &["proto"])?;
    }
    Ok(())
}
