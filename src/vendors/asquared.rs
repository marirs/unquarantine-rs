use crate::{
    Result,
    utils::{self, rc4_decrypt, unpack_i32},
};
use md5::Digest;

/// ASquared (EQF)
pub fn unquarantine(data: &[u8]) -> Result<Vec<Vec<u8>>> {
    let data = utils::tail(data, 0x1A, "asquared header")?;
    let doo = unpack_i32(utils::tail(data, 0x24, "asquared data offset")?)? as usize;
    let body = utils::tail(data, doo, "asquared body")?;
    let newdata = rc4_decrypt(&mut ksa(), body);
    Ok(vec![newdata])
}

fn ksa() -> Vec<u8> {
    let mut hasher = md5::Md5::new();
    hasher.update(b"{A4A1BFF9-301A-40D3-86D3-D1F29E413B28}");
    let key = hasher.finalize().to_vec();
    let mut sbox: Vec<u8> = (0..=255).collect();
    let mut j = 0_usize;
    for i in 0..256 {
        j = (j + sbox[i] as usize + key[i % key.len()] as usize) % 256;
        sbox.swap(i, j)
    }
    sbox
}
