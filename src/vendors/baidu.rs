use crate::{
    error::Error,
    utils::{unpack_i16, unpack_i32},
    Result,
};

lazy_static! {
    static ref KEY: Vec<u8> = vec![
        0xD9, 0xA7, 0xA3, 0xBF, 0x85, 0xFF, 0x43, 0x77, 0xAD, 0x06, 0xCF, 0xFD, 0x1F, 0x94, 0xE9,
        0xCC,
    ];
}

/// Baidu QV Files
pub fn unquarantine(data: &[u8]) -> Result<Vec<Vec<u8>>> {
    let _magic = unpack_i32(data)?;
    let _time1 = unpack_i32(&data[4..])?;
    let _task = unpack_i32(&data[8..])?;
    let _scanstat = unpack_i32(&data[0xC..])?;
    let mut md5 = data[0x10..0x10 + 0x42].to_vec();
    md5.push(0);

    let data = &data[0x52..];
    let leng = unpack_i32(data)? as usize;
    if leng > data.len() {
        return Err(Error::UndefinedQuarantineMethod("baidu".to_string()));
    }
    let mut path = data[4..4 + leng].to_vec();
    path.push(0);

    let data = &data[4 + leng..];
    let leng = unpack_i32(data)? as usize;
    let mut clientid = data[4..4 + leng].to_vec();
    clientid.push(0);

    let data = &data[4 + leng..];
    let _st = unpack_i32(data)? as usize;
    let data = &data[4..];
    let leng = unpack_i32(data)? as usize;
    let mut threat = data[4..4 + leng].to_vec();
    threat.push(0);

    let data = &data[4 + leng..];
    let leng = unpack_i32(data)? as usize;
    let mut maltype = data[4..4 + leng].to_vec();
    maltype.push(0);

    let data = &data[4 + leng..];
    let leng = unpack_i32(data)? as usize;
    let mut packtype = data[4..4 + leng].to_vec();
    packtype.push(0);

    let data = &data[4 + leng..];
    let leng = unpack_i32(data)? as usize;
    let mut reserved = data[4..4 + leng].to_vec();
    reserved.push(0);

    let data = &data[4 + leng..];
    let _crc32 = unpack_i32(data)? as usize;

    let mut data = &data[4..];
    let mut dec = vec![];
    while !data.is_empty() {
        let lend = unpack_i16(data)? as usize;
        data = &data[2..];
        let dec2 = inflate::inflate_bytes(data).map_err(Error::InflateError)?;
        let mut b = dec2[0];
        for i in 0..dec2.len() {
            b ^= KEY[i % KEY.len()];
        }
        data = &data[lend..];
        dec.push(b);
        dec.extend(dec2[1..].to_vec());
    }
    Ok(vec![dec])
}
