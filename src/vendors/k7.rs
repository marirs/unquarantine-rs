use crate::{
    error::Error,
    utils::{bytearray_xor, unpack_i32},
    Result,
};

/// K7 Antivirus (<md5>.QNT)
pub fn unquarantine(data: &[u8]) -> Result<Vec<Vec<u8>>> {
    let len = unpack_i32(&data[0x128..])? as usize;
    if len > data.len() {
        return Err(Error::UndefinedQuarantineMethod("k7".to_string()));
    }
    let newdata = bytearray_xor(data[0x178..0x178 + len].to_vec(), 0xFF);
    Ok(vec![newdata])
}
