use crate::{
    Result,
    utils::{self, bytearray_xor, unpack_i32},
};

/// K7 Antivirus (`<md5>`.QNT)
pub fn unquarantine(data: &[u8]) -> Result<Vec<Vec<u8>>> {
    let len = unpack_i32(utils::tail(data, 0x128, "k7 length")?)? as usize;
    let body = utils::slice(data, 0x178, len, "k7 body")?;
    Ok(vec![bytearray_xor(body.to_vec(), 0xFF)])
}
