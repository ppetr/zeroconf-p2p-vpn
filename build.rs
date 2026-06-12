use std::io::Result;

fn main() -> Result<()> {
    prost_build::compile_protos(&["proto/p2p_vpn/control/v1/control.proto"], &["proto/"])?;
    Ok(())
}
