use crate::{
    Result,
    error::Error,
    utils::{self, unpack_i16, unpack_i32},
};
use std::io::{Cursor, Read, copy};
use zip::ZipArchive;

/// Per-entry cap on decompressed output, guarding against zip-bomb inputs.
const MAX_DECOMPRESSED: u64 = 512 << 20; // 512 MiB

/// CMC Antivirus (CMC)
pub fn unquarantine(data: &[u8]) -> Result<Vec<Vec<u8>>> {
    let ofn = unpack_i16(utils::tail(data, 0x50, "cmc ofn")?)? as usize;
    let tnl = unpack_i16(utils::tail(data, 0x6C, "cmc tnl")?)? as usize;

    let start = 0x200usize
        .checked_add(ofn)
        .and_then(|v| v.checked_add(tnl))
        .ok_or(Error::Invalid("cmc offset"))?;
    let rest = utils::tail(data, start, "cmc payload header")?;
    let buflen = unpack_i32(rest)? as usize;
    let payload = utils::slice(rest, 4, buflen, "cmc payload")?;

    let mut dec = vec![];
    let mut zip = ZipArchive::new(Cursor::new(payload))?;
    for i in 0..zip.len() {
        let file = zip.by_index(i)?;
        let mut res: Vec<u8> = vec![];
        copy(&mut file.take(MAX_DECOMPRESSED), &mut res)?;
        dec.push(res);
    }
    Ok(dec)
}
