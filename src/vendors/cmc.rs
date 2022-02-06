use crate::{
    utils::{bytearray_xor, unpack_i16, unpack_i32},
    Result,
};
use std::io::{copy, BufReader, Cursor};
use zip::ZipArchive;

/// CMC Antivirus (CMC)
pub fn unquarantine(data: &[u8]) -> Result<Vec<Vec<u8>>> {
    let _magic = &data[..32];
    let _ffv = unpack_i32(&data[0x20..])?;
    let _crc = unpack_i32(&data[0x28..])?;
    let _adler = unpack_i32(&data[0x2C..])?;
    let ofn = unpack_i16(&data[0x50..])? as usize;
    let _us = unpack_i32(&data[0x54..])?;
    let _qs = unpack_i32(&data[0x58..])?;
    let tnl = unpack_i16(&data[0x6C..])? as usize;

    let _fnn = &data[0x200..0x200 + ofn];
    let _tn = &data[0x200 + ofn..0x200 + ofn + tnl];
    let _md5 = &data[0x30..0x30 + 16];
    let _submitid = &data[0x40..0x40 + 16];

    let data = &data[0x200 + ofn + tnl..];
    let buflen = unpack_i32(data)? as usize;
    let data = &data[4..4 + buflen];
    let _meta_dec = bytearray_xor(data.to_vec(), 30);
    let mut dec = vec![];
    let mut zip = ZipArchive::new(BufReader::new(Cursor::new(data.to_vec())))?;

    for i in 0..zip.len() {
        let mut file = zip.by_index(i)?;
        let _s = file.size();
        let mut res: Vec<u8> = vec![];
        copy(&mut file, &mut res)?;
        dec.push(res);
    }
    Ok(dec)
}
