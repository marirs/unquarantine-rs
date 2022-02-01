use crate::{Result, utils::{rc4_decrypt, unpack_i32}};
use md5::Digest;

/// ASquared (EQF)
pub fn unquarantine(data: &Vec<u8>) -> Result<Vec<Vec<u8>>> {
    let data = &data[0x1A..];
    let fno = unpack_i32(&data[0x14..])? as usize;
    let fnl = unpack_i32(&data[0x18..])? as usize;
    let mut fnn = data[fno..fno + fnl].to_vec();
    fnn.push(0);
    let dn = unpack_i32(&data[0x1C..])? as usize;
    let mut tn = data[dn + 32..dn + 32 + 256].to_vec();
    tn.push(0);
    let doo = unpack_i32(&data[0x24..])? as usize;
    let data = &data[doo..];
    let newdata = rc4_decrypt(&mut ksa(), &mut data.to_vec());
    Ok(vec![newdata])
}

fn ksa() -> Vec<u8> {
    let mut hasher = md5::Md5::new();
    hasher.update(b"{A4A1BFF9-301A-40D3-86D3-D1F29E413B28}");
    let key = hasher.finalize().to_vec();
    let mut sbox: Vec<u8> = (0..=255).collect();
    let mut j = 0 as usize;
    for i in 0..256 {
        j = (j + sbox[i] as usize + key[i % key.len()] as usize) % 256;
        let tmp = sbox[i];
        sbox[i] = sbox[j];
        sbox[j] = tmp;
    }
    sbox
}
