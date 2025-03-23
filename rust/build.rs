use std::io::Result;

fn main() -> Result<()> {
    let proto_dir = "../pb";

    prost_build::compile_protos(
        &[
            format!("{}/message.proto", proto_dir),
            format!("{}/security.proto", proto_dir),
        ],
        &[proto_dir],
    )?;
    Ok(())
}
