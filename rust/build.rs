extern crate prost_build;

fn main() {
    prost_build::compile_protos(&["../pb/message.proto", "../pb/security.proto"], &["../pb/"]).unwrap();
}
