use crate::{
    Result,
    utils::{self, unpack_i16, unpack_i32},
};

const KEY: &[u8] = &[
    0xD9, 0xA7, 0xA3, 0xBF, 0x85, 0xFF, 0x43, 0x77, 0xAD, 0x06, 0xCF, 0xFD, 0x1F, 0x94, 0xE9, 0xCC,
];

/// Baidu QV Files
pub fn unquarantine(data: &[u8]) -> Result<Vec<Vec<u8>>> {
    // Header fields are validated for presence; their values are unused.
    let _magic = unpack_i32(data)?;
    let _time1 = unpack_i32(utils::tail(data, 4, "baidu time1")?)?;
    let _task = unpack_i32(utils::tail(data, 8, "baidu task")?)?;
    let _scanstat = unpack_i32(utils::tail(data, 0xC, "baidu scanstat")?)?;
    let _md5 = utils::slice(data, 0x10, 0x42, "baidu md5")?;

    let mut data = utils::tail(data, 0x52, "baidu body")?;
    for what in ["baidu path", "baidu clientid"] {
        let leng = unpack_i32(data)? as u32 as usize;
        let _field = utils::slice(data, 4, leng, what)?;
        data = utils::tail(data, 4 + leng, what)?;
    }

    let _st = unpack_i32(data)?;
    data = utils::tail(data, 4, "baidu st")?;
    for what in [
        "baidu threat",
        "baidu maltype",
        "baidu packtype",
        "baidu reserved",
    ] {
        let leng = unpack_i32(data)? as u32 as usize;
        let _field = utils::slice(data, 4, leng, what)?;
        data = utils::tail(data, 4 + leng, what)?;
    }

    let _crc32 = unpack_i32(data)?;
    let mut data = utils::tail(data, 4, "baidu crc")?;

    let mut dec = vec![];
    while !data.is_empty() {
        let lend = unpack_i16(data)? as u16 as usize;
        data = utils::tail(data, 2, "baidu chunk len")?;
        let dec2 = utils::inflate(data)?;
        if dec2.is_empty() {
            break;
        }
        let mut b = dec2[0];
        for i in 0..dec2.len() {
            b ^= KEY[i % KEY.len()];
        }
        data = utils::tail(data, lend, "baidu chunk")?;
        dec.push(b);
        dec.extend_from_slice(&dec2[1..]);
    }
    Ok(vec![dec])
}
