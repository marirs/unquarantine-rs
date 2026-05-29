use crate::{
    Result,
    utils::{self, bytearray_xor, unpack_i32},
};

/// Avira QUA Files
pub fn unquarantine(data: &[u8]) -> Result<Vec<Vec<u8>>> {
    let o2d = unpack_i32(utils::tail(data, 16, "avira offset")?)? as usize;
    let body = utils::tail(data, o2d, "avira body")?;
    Ok(vec![bytearray_xor(body.to_vec(), 170)])
}
