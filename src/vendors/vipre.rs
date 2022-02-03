use crate::{utils::bytearray_xor, Result};

/// Vipre (<GUID>_ENC2)
pub fn unquarantine(data: &[u8]) -> Result<Vec<Vec<u8>>> {
    Ok(vec![bytearray_xor(data.to_vec(), 51)])
}
