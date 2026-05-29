use crate::{
    Result,
    error::Error,
    utils::{self, rc4_decrypt, unpack_i32},
};

const KEY: &[i32] = &[
    0xA7, 0xBF, 0x73, 0xA0, 0x9F, 0x03, 0xD3, 0x11, 0x85, 0x6F, 0x00, 0x80, 0xAD, 0xA9, 0x6E, 0x9B,
];

/// G-Data (Q) (Magic@0=0xCAFEBABE)
pub fn unquarantine(data: &[u8]) -> Result<Vec<Vec<u8>>> {
    let hdr_len = unpack_i32(utils::tail(data, 4, "gdata hdr_len")?)? as u32 as usize;
    let _hdr = utils::slice(data, 8, hdr_len, "gdata hdr")?;
    let after_hdr = hdr_len
        .checked_add(8)
        .ok_or(Error::Invalid("gdata hdr len"))?;
    let data = utils::tail(data, after_hdr, "gdata after hdr")?;
    if !data.starts_with(&[0xBA, 0xAD, 0xF0, 0x0D]) {
        return Err(Error::CannotUnQuarantineFile("gdata".to_string()));
    }
    let body_len = unpack_i32(utils::tail(data, 4, "gdata body_len")?)? as u32 as usize;
    let _body = utils::slice(data, 8, body_len, "gdata body")?;
    let after_body = body_len
        .checked_add(8)
        .ok_or(Error::Invalid("gdata body len"))?;
    let data = utils::tail(data, after_body, "gdata after body")?;

    let newdata = rc4_decrypt(&mut ksa(), data);
    Ok(vec![newdata])
}

fn ksa() -> Vec<u8> {
    let mut sbox: Vec<u8> = (0..=255).collect();
    let mut j = 0_usize;
    for i in 0..256 {
        j = (j + sbox[i] as usize + KEY[i % KEY.len()] as usize) % 256;
        sbox.swap(i, j);
    }
    sbox
}
