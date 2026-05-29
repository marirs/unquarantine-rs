use crate::{
    Result,
    error::Error,
    utils::{self, unpack_i32},
};

const KLQ_KEY: &[u8] = &[0xE2, 0x45, 0x48, 0xEC, 0x69, 0x0E, 0x5C, 0xAC];
const SYSW_KEY: &[u8] = &[0x39, 0x7b, 0x4d, 0x58, 0xc9, 0x39, 0x7b, 0x4d, 0x58, 0xc9];

/// Kaspersky KLQ files
pub fn av_unquarantine(data: &[u8]) -> Result<Vec<Vec<u8>>> {
    let mut data = data.to_owned();
    if unpack_i32(&data)? != 0x42514C4B {
        return Err(Error::CannotUnQuarantineFile("kav".to_string()));
    }
    let fsize = data.len();

    let headerlen = unpack_i32(utils::tail(&data, 8, "kav headerlen")?)?;
    let metaoffset = unpack_i32(utils::tail(&data, 0x10, "kav metaoffset")?)?;
    let metalen = unpack_i32(utils::tail(&data, 0x20, "kav metalen")?)?;
    let origlen = unpack_i32(utils::tail(&data, 0x30, "kav origlen")?)?;
    if headerlen < 0 || metaoffset < 0 || metalen < 0 || origlen < 0 {
        return Err(Error::Invalid("kav negative field"));
    }
    let (headerlen, metaoffset, metalen, origlen) = (
        headerlen as usize,
        metaoffset as usize,
        metalen as usize,
        origlen as usize,
    );
    let hdr_orig = headerlen
        .checked_add(origlen)
        .ok_or(Error::Invalid("kav size overflow"))?;
    let need = hdr_orig
        .checked_add(metalen)
        .ok_or(Error::Invalid("kav size overflow"))?;
    if fsize < need || metaoffset < hdr_orig {
        return Err(Error::CannotUnQuarantineFile("kav".to_string()));
    }
    let meta_end = metaoffset
        .checked_add(metalen)
        .filter(|&v| v <= fsize)
        .ok_or(Error::Invalid("kav meta range"))?;

    let mut curoffset = metaoffset;
    while curoffset + 4 <= fsize {
        let length = unpack_i32(&data[curoffset..])?;
        if length <= 0 {
            break;
        }
        let length = length as usize;
        // while-guard guarantees `curoffset + 4 <= fsize`, so this cannot underflow.
        if length > fsize - curoffset - 4 {
            return Err(Error::Invalid("kav chunk range"));
        }
        for i in 0..length {
            data[curoffset + 4 + i] ^= KLQ_KEY[i % KLQ_KEY.len()];
        }
        curoffset += 4 + length;
        if curoffset >= meta_end {
            break;
        }
    }

    let body_end = headerlen
        .checked_add(origlen)
        .filter(|&v| v <= fsize)
        .ok_or(Error::Invalid("kav body range"))?;
    for i in 0..origlen {
        data[headerlen + i] ^= KLQ_KEY[i % KLQ_KEY.len()];
    }
    Ok(vec![data[headerlen..body_end].to_vec()])
}

/// Kaspersky (System Watcher's `<md5>`.bin)
pub fn system_watcher_unquarantine(data: &[u8]) -> Result<Vec<Vec<u8>>> {
    let newdata = data
        .iter()
        .enumerate()
        .map(|(i, &b)| b ^ SYSW_KEY[i % SYSW_KEY.len()])
        .collect();
    Ok(vec![newdata])
}
