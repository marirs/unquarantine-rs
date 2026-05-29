use crate::{
    Result,
    error::Error,
    utils::{self, unpack_i32},
};

const KEY: &[u8] = &[
    0x76, 0x33, 0x62, 0x61, 0x63, 0x6B, 0x75, 0x70, 0x21, 0x40, 0x23, 0x24, 0x25, 0x5E, 0x26, 0x29,
];

/// AhnLab (V3B)
pub fn unquarantine(data: &[u8]) -> Result<Vec<Vec<u8>>> {
    let o2d = unpack_i32(utils::tail(data, 58, "ahnlab header")?)? as i64 + 0x58;
    if o2d < 0 {
        return Err(Error::Invalid("ahnlab offset"));
    }
    let o2d = o2d as usize;
    let end = data
        .len()
        .checked_sub(o2d)
        .ok_or(Error::Invalid("ahnlab length"))?;
    if o2d > end {
        return Err(Error::Invalid("ahnlab range"));
    }
    let body = &data[o2d..end];
    let mut dec = Vec::with_capacity(body.len());
    let mut ki = 0_usize;
    for &b in body {
        dec.push(b ^ KEY[ki]);
        ki = (ki + 1) % KEY.len();
    }
    Ok(vec![dec])
}
