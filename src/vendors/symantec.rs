use crate::{
    Result,
    error::Error,
    utils::{self, blowfishit, bytearray_xor, unpack_i32, unpack_i64},
    vendors::others,
};
use std::io::{Cursor, Read, copy};

/// Per-entry cap on decompressed output, guarding against zip-bomb inputs.
const MAX_DECOMPRESSED: u64 = 512 << 20; // 512 MiB

/// Symantec Quarantine files (VBN), including from SEP on Linux
pub fn ep_unquarantine(data: &[u8]) -> Result<Vec<Vec<u8>>> {
    let qdata = data.to_vec();
    let filesize = qdata.len();
    let mut dataoffset = unpack_i32(&qdata)?;
    if dataoffset != 0x1290 {
        return Err(Error::CannotUnQuarantineFile("sep".to_string()));
    }
    let mut data = bytearray_xor(qdata, 0x5A);
    dataoffset += 0x28;
    let mut offset = dataoffset as usize;
    let mut decode_next_container = false;
    let mut xor_next_container = false;
    let mut has_header = true;
    let mut binsize = 0_usize;
    let mut collectedsize = 0_usize;
    let mut bindata = vec![];
    let mut iters = 0;
    let mut lastlen = 0_i64;

    while iters < 20000 {
        iters += 1;
        let (code, length, codeval, tagdata) = read_ep_tag(&data, offset)?;
        let mut extralen = tagdata.len();
        if code == 9 {
            if xor_next_container {
                let body_start = offset + 5;
                let body_end = body_start
                    .checked_add(tagdata.len())
                    .ok_or(Error::Invalid("sep body range"))?;
                if body_end > data.len() {
                    return Err(Error::Invalid("sep body range"));
                }
                for b in &mut data[body_start..body_end] {
                    *b ^= 0xFF;
                }
                if has_header {
                    let headerlen =
                        unpack_i32(utils::tail(&data, body_start + 8, "sep headerlen")?)? as i64;
                    if headerlen < 12 {
                        return Err(Error::Invalid("sep headerlen"));
                    }
                    let headerlen = headerlen as usize;
                    let binsize_at = body_start
                        .checked_add(headerlen)
                        .and_then(|v| v.checked_sub(12))
                        .ok_or(Error::Invalid("sep binsize offset"))?;
                    binsize = unpack_i32(utils::tail(&data, binsize_at, "sep binsize")?)? as usize;
                    collectedsize += tagdata.len().saturating_sub(headerlen);
                    let binlen = collectedsize.min(binsize);
                    let bin_start = body_start
                        .checked_add(headerlen)
                        .ok_or(Error::Invalid("sep bin start"))?;
                    let chunk = utils::slice(&data, bin_start, binlen, "sep bin")?;
                    bindata.extend_from_slice(chunk);
                    has_header = false;
                } else {
                    let mut binlen = tagdata.len();
                    collectedsize += binlen;
                    if collectedsize > binsize {
                        binlen = binlen.saturating_sub(collectedsize - binsize);
                    }
                    let chunk = utils::slice(&data, body_start, binlen, "sep bin2")?;
                    bindata.extend_from_slice(chunk);
                }
            } else if decode_next_container {
                extralen = 0;
                decode_next_container = false;
            } else if codeval == 0x10 || codeval == 0x8 {
                if codeval == 0x8 {
                    xor_next_container = true;
                    lastlen = unpack_i64(utils::tail(&data, offset + 5, "sep lastlen")?)?;
                } else {
                    xor_next_container = false;
                    decode_next_container = true;
                }
            }
        } else if code == 4 && xor_next_container && lastlen == codeval {
            binsize = codeval as usize;
            has_header = false;
        }
        offset = offset
            .checked_add(length)
            .and_then(|v| v.checked_add(extralen))
            .ok_or(Error::Invalid("sep offset"))?;
        if offset >= filesize {
            break;
        }
    }
    Ok(vec![bindata])
}

/// Symantec ccSubSdk files: {GUID} files and submissions.idx
pub fn cc_sub_sdk_unquarantine(data: &[u8]) -> Result<Vec<Vec<u8>>> {
    let body = utils::tail(data, 32, "symc body")?;
    let key = utils::slice(data, 16, 16, "symc key")?;
    Ok(vec![blowfishit(body, key)?])
}

/// Symantec Quarantine Index files (QBI)
pub fn idx_unquarantine(data: &[u8]) -> Result<Vec<Vec<u8>>> {
    let mut data = utils::tail(data, 0x30, "symc idx header")?;
    let mut res = vec![];
    while data.starts_with(&[0x40, 0x99, 0xC6, 0x89]) {
        let len1 = unpack_i32(utils::tail(data, 24, "symc idx len1")?)? as usize;
        let key = utils::slice(data, 40, 16, "symc idx key")?;
        let body = utils::slice(data, 56, len1, "symc idx body")?;
        res.push(blowfishit(body, key)?);
        // Advance past this record (56-byte header + len1 body); guard against
        // a zero-length record that would otherwise spin forever.
        let next = 56_usize
            .checked_add(len1)
            .filter(|&n| n > 0)
            .ok_or(Error::Invalid("symc idx record"))?;
        data = utils::tail(data, next, "symc idx next")?;
    }
    Ok(res)
}

/// Symantec Quarantine Index files (QBD)
pub fn qbd_unquarantine(data: &[u8]) -> Result<Vec<Vec<u8>>> {
    others::data_unquarantine(data, 0xB3)
}

/// Symantec Quarantine files on MAC (quarantine.qtn)
pub fn qtn_unquarantine(data: &[u8]) -> Result<Vec<Vec<u8>>> {
    let mut ress = vec![];
    let mut zip = zip::ZipArchive::new(Cursor::new(data))?;
    for i in 0..zip.len() {
        let file = zip.by_index(i)?;
        let mut res: Vec<u8> = vec![];
        copy(&mut file.take(MAX_DECOMPRESSED), &mut res)?;
        ress.push(res);
    }
    Ok(ress)
}

fn read_ep_tag(data: &[u8], offset: usize) -> Result<(u8, usize, i64, Vec<u8>)> {
    let code = *data.get(offset).ok_or(Error::Truncated("sep tag code"))?;
    let codeval;
    let mut retdata = vec![];
    let length;

    match code {
        1 | 10 => {
            length = 2;
            codeval = code as i64;
        }
        3 | 6 => {
            length = 5;
            codeval = unpack_i32(utils::tail(data, offset + 1, "sep tag i32")?)? as i64;
        }
        4 => {
            length = 9;
            codeval = unpack_i64(utils::tail(data, offset + 1, "sep tag i64")?)?;
        }
        _ => {
            length = 5;
            codeval = unpack_i32(utils::tail(data, offset + 1, "sep tag len")?)? as i64;
            if codeval < 0 {
                return Err(Error::Invalid("sep tag len"));
            }
            retdata = utils::slice(data, offset + 5, codeval as usize, "sep tag body")?.to_vec();
        }
    }
    Ok((code, length, codeval, retdata))
}
