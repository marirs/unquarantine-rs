use crate::{Result, utils::{unpack_i32, bytearray_xor}};

/// "Avira QUA Files
pub fn unquarantine(data: &Vec<u8>) -> Result<Vec<Vec<u8>>> {
    let o2d = unpack_i32(&data[16..])? as usize;
    let newdata = bytearray_xor(data[o2d..].to_vec(), 170);
    Ok(vec![newdata])
}
