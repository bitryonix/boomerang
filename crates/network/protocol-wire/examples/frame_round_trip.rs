//! Round-trips one typed protocol message through the framed wire codec.

use protocol::magic::SETUP_NISO_OUTPUT_2_MAGIC;
use protocol::messages::setup::from_niso::to_user::SetupNisoOutput2;
use protocol_wire::WireMessage;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let message = SetupNisoOutput2::new(SETUP_NISO_OUTPUT_2_MAGIC);
    let frame_bytes = message.encode_frame()?;
    let decoded = SetupNisoOutput2::decode_frame_checked(&frame_bytes)?;

    println!("round-tripped {:?}", decoded.into_parts());
    Ok(())
}
