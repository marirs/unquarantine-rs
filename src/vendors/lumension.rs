use crate::{error::Error, Result};

/// Lumension LEMSS (lqf)
pub fn unquarantine(data: &[u8]) -> Result<Vec<Vec<u8>>> {
    // WANT_GZIP
    let dec2 = inflate::inflate_bytes(&data[32..]).map_err(Error::InflateError)?;
    Ok(vec![dec2])
}
