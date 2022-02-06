use crate::{error::Error, utils::unpack_i32, Result};

lazy_static! {
    static ref KLQ_KEY: Vec<u8> = vec![0xE2, 0x45, 0x48, 0xEC, 0x69, 0x0E, 0x5C, 0xAC];
    static ref SYSW_KEY: Vec<u8> = vec![0x39, 0x7b, 0x4d, 0x58, 0xc9, 0x39, 0x7b, 0x4d, 0x58, 0xc9];
}

/// Kaspersky KLQ files
pub fn av_unquarantine(data: &[u8]) -> Result<Vec<Vec<u8>>> {
    let mut data = data.to_owned();
    let magic = unpack_i32(&data)?;
    if magic != 0x42514C4B {
        return Err(Error::CannotUnQuarantineFile("kav".to_string()));
    }
    let fsize = data.len();

    let headerlen = unpack_i32(&data[8..])?;
    let metaoffset = unpack_i32(&data[0x10..])?;
    let metalen = unpack_i32(&data[0x20..])?;
    let origlen = unpack_i32(&data[0x30..])?;

    if fsize < (headerlen + origlen + metalen) as usize {
        return Err(Error::CannotUnQuarantineFile("kav".to_string()));
    }
    if metaoffset < headerlen + origlen {
        return Err(Error::CannotUnQuarantineFile("kav".to_string()));
    }

    let mut curoffset = metaoffset as usize;
    let mut length = unpack_i32(&data[curoffset..])?;
    while length > 0 {
        for i in 0..length {
            data[curoffset + 4 + i as usize] ^= KLQ_KEY[(i % KLQ_KEY.len() as i32) as usize];
        }
        curoffset += (4 + length) as usize;
        if curoffset >= (metaoffset + metalen) as usize {
            break;
        }
        length = unpack_i32(&data[curoffset..])?;
    }
    for i in 0..origlen {
        data[(headerlen + i) as usize] ^= KLQ_KEY[(i % KLQ_KEY.len() as i32) as usize];
    }
    Ok(vec![data
        [headerlen as usize..(headerlen + origlen) as usize]
        .to_vec()])
}

/// Kaspersky (System Watcher's <md5>.bin)
pub fn system_watcher_unquarantine(data: &[u8]) -> Result<Vec<Vec<u8>>> {
    let mut newdata = vec![];
    for i in 0..data.len() {
        newdata.push(data[i] ^ SYSW_KEY[i % SYSW_KEY.len()]);
    }
    Ok(vec![newdata])
}
