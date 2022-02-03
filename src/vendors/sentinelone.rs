use crate::{utils::bytearray_xor, Result};

/// Sentinel One (MAL)
pub fn unquarantine(data: &[u8]) -> Result<Vec<Vec<u8>>> {
    Ok(vec![bytearray_xor(data.to_owned(), 255)])
}
