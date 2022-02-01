use crate::{
    error::Error,
    utils::{unpack_i32, unpack_i64, bytearray_xor, blowfishit},
    Result,
};
use std::convert::TryInto;

/// Symantec Quarantine files (VBN), including from SEP on Linux
pub fn ep_unquarantine(data: &Vec<u8>) -> Result<Vec<Vec<u8>>> {
    let qdata = data.clone();
    let filesize = qdata.len();
    let mut dataoffset = unpack_i32(&qdata)?;
    if dataoffset != 0x1290 {
        return Err(Error::UndefinedQuarantineMethod("sep".to_string()));
    }
    let mut data = bytearray_xor(qdata, 0x5A);
    dataoffset += 0x28;
    let mut offset = dataoffset as usize;
    let mut decode_next_container = false;
    let mut xor_next_container = false;
    let mut has_header = true;
    let mut binsize = 0;
    let mut collectedsize = 0;
    let mut bindata = vec![];
    let mut iters = 0;
    let mut lastlen = 0;

    while iters < 20000 {
        iters += 1;
        let (code, length, codeval, tagdata) = read_sep_tag(&data, offset)?;
        let mut extralen = tagdata.len();
        if code == 9 {
            if xor_next_container {
                for i in 0..tagdata.len() {
                    data[offset + 5 + i] ^= 0xFF;
                }
                if has_header {
                    let headerlen_vec: &[u8; 4] =
                        data[offset + 5 + 8..offset + 5 + 12].try_into()?;
                    let headerlen = i32::from_le_bytes(*headerlen_vec) as usize;
                    let binsize_vec: &[u8; 4] =
                        data[offset + 5 + headerlen - 12..offset + 5 + headerlen - 8].try_into()?;
                    let binsize = i32::from_le_bytes(*binsize_vec) as usize;
                    collectedsize += tagdata.len() - headerlen;
                    let binlen = if collectedsize > binsize {
                        binsize
                    } else {
                        collectedsize
                    } as usize;
                    bindata.extend(
                        data[offset + 5 + headerlen..offset + 5 + headerlen + binlen].to_vec(),
                    );
                    has_header = false;
                } else {
                    let mut binlen = tagdata.len();
                    collectedsize += binlen;
                    if collectedsize > binsize {
                        binlen -= collectedsize - binsize;
                    }
                    bindata.extend(data[offset + 5..offset + 5 + binlen].to_vec());
                }
            } else {
                if decode_next_container {
                    extralen = 0;
                    decode_next_container = false;
                } else if codeval == 0x10 || codeval == 0x8 {
                    if codeval == 0x8 {
                        xor_next_container = true;
                        let lastlen_vec: &[u8; 8] = data[offset + 5..offset + 5 + 8].try_into()?;
                        lastlen = i64::from_le_bytes(*lastlen_vec);
                    } else {
                        xor_next_container = false;
                        decode_next_container = true;
                    }
                }
            }
        } else if code == 4 {
            if xor_next_container && lastlen == codeval as i64 {
                binsize = codeval as usize;
                has_header = false;
            }
        }
        offset += length + extralen;
        if offset == filesize {
            break;
        }
    }
    Ok(vec![bindata])
}

/// Symantec ccSubSdk files: {GUID} files and submissions.idx
pub fn sym_cc_sub_sdk_unquarantine(data: &Vec<u8>) -> Result<Vec<Vec<u8>>> {
    Ok(vec![blowfishit(
        &data[32..].to_vec(),
        &data[16..32].to_vec(),
    )?])
}

/// Symantec Quarantine Index files (QBI)
pub fn sym_submissionsidx_unquarantine(data: &Vec<u8>) -> Result<Vec<Vec<u8>>> {
    let data = &data[0x30..];
    let mut res = vec![];
    while &data[..4] == &vec![0x40, 0x99, 0xC6, 0x89] {
        let len1 = unpack_i32(&data[24..])? as usize;
        let _len2 = unpack_i32(&data[28..])? as usize;
        let dec = blowfishit(&data[56..56 + len1].to_vec(), &data[40..40 + 16].to_vec())?;
        res.push(dec);
    }
    Ok(res)
}

/// Symantec Quarantine files on MAC (quarantine.qtn)
pub fn sym_qtn_unquarantine(data: &Vec<u8>) -> Result<Vec<Vec<u8>>> {
    let mut ress = vec![];
    let mut zip =
        zip::ZipArchive::new(std::io::BufReader::new(std::io::Cursor::new(data.to_vec())))?;

    for i in 0..zip.len() {
        let mut file = zip.by_index(i)?;
        let mut res: Vec<u8> = vec![];
        std::io::copy(&mut file, &mut res)?;
        ress.push(res);
    }
    Ok(ress)
}

fn read_sep_tag(data: &Vec<u8>, offset: usize) -> Result<(u8, usize, i64, Vec<u8>)> {
    let code = data[offset];
    let codeval;
    let mut retdata = vec![];
    let length;

    match code {
        1 | 10 => {
            length = 2;
            codeval = data[offset] as i64;
        }
        3 | 6 => {
            length = 5;
            codeval = unpack_i32(&data[offset + 1..])? as i64;
        }
        4 => {
            length = 9;
            codeval = unpack_i64(&data[offset + 1..])?;
        }
        _ => {
            length = 5;
            codeval = unpack_i32(&data[offset + 1..])? as i64;
            retdata = data[offset + 5..offset + 5 + codeval as usize].to_vec();
        }
    }
    Ok((code, length, codeval, retdata))
}
