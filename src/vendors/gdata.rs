use crate::{
    error::Error,
    utils::{rc4_decrypt, unpack_i32},
    Result,
};

lazy_static! {
    static ref KEY: Vec<i32> = vec![
        0xA7, 0xBF, 0x73, 0xA0, 0x9F, 0x03, 0xD3, 0x11, 0x85, 0x6F, 0x00, 0x80, 0xAD, 0xA9, 0x6E,
        0x9B,
    ];
}

/// G-Data (Q) (Magic@0=0xCAFEBABE)
pub fn unquarantine(data: &[u8]) -> Result<Vec<Vec<u8>>> {
    let size = data.len();
    let hdr_len = unpack_i32(&data[4..])? as usize;
    if hdr_len > data.len() {
        return Err(Error::UndefinedQuarantineMethod("gdata".to_string()));
    }
    let _hdr = &data[8..8 + hdr_len as usize];
    let data = &data[8 + hdr_len as usize..];
    if data[..4] != vec![0xBA, 0xAD, 0xF0, 0x0D] {
        return Err(Error::UndefinedQuarantineMethod("gdata".to_string()));
    }
    let body_len = unpack_i32(&data[4..])? as usize;
    if body_len > size {
        return Err(Error::UndefinedQuarantineMethod("gdata".to_string()));
    }
    let _body = &data[8..8 + body_len];
    let data = &data[8 + body_len as usize..];

    let newdata = rc4_decrypt(&mut ksa(), &mut data.to_vec());
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
