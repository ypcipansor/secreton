pub mod secreton {
    pub mod v1 {
        tonic::include_proto!("secreton.v1");
    }
}

pub use secreton::v1::*;
