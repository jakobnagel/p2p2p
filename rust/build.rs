extern crate prost_build;

fn main() {
    let proto_dir = "../pb"; // Path to your proto files

    let mut config = prost_build::Config::new();
    config.include_file("your_package_name.rs"); // If you are using include_file

    config
        .compile_protos(
            &[
                format!("{}/message.proto", proto_dir),
                format!("{}/security.proto", proto_dir),
            ],
            &[proto_dir], // Specify the directory to search for imports
        )
        .unwrap();
}
