use crate::{Result, utils::bytearray_xor};

/// Vipre (<GUID>_ENC2)
pub fn unquarantine(data: &Vec<u8>) -> Result<Vec<Vec<u8>>> {
    Ok(vec![bytearray_xor(data.to_vec(), 51)])
}
