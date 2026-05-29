use crate::{Result, utils};

/// Lumension LEMSS (lqf)
pub fn unquarantine(data: &[u8]) -> Result<Vec<Vec<u8>>> {
    // raw DEFLATE payload after a 32-byte header
    let body = utils::tail(data, 32, "lumension header")?;
    Ok(vec![utils::inflate(body)?])
}
