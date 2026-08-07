//! Compile the protobuf definitions when the `grpc` feature is on.
//!
//! `protoc` is vendored rather than expected on PATH, so a build works in a container
//! with no toolchain installed and produces the same output everywhere.

fn main() -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(feature = "grpc")]
    {
        println!("cargo:rerun-if-changed=proto/secreton.proto");
        // SAFETY-adjacent note: this runs single-threaded in the build script, before
        // any other code observes the environment.
        unsafe {
            std::env::set_var("PROTOC", protoc_bin_vendored::protoc_bin_path()?);
        }
        // `compile` was renamed in tonic-build 0.13; prost codegen moved to
        // `tonic-prost-build` in 0.14.
        tonic_prost_build::configure()
            .build_server(true)
            .build_client(true)
            .compile_protos(&["proto/secreton.proto"], &["proto"])?;
    }
    Ok(())
}
