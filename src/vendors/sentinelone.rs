use crate::{utils::bytearray_xor, Result};

/// Sentinel One (MAL)
pub fn unquarantine(data: &Vec<u8>) -> Result<Vec<Vec<u8>>> {
    Ok(vec![bytearray_xor(data.clone(), 255)])
}
