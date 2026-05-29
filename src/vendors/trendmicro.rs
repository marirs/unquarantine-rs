use crate::{
    Result,
    error::Error,
    utils::{self, bytearray_xor, unpack_i16, unpack_i32},
};

/// TrendMicro (Magic@0=A9 AC BD A7 which is a 'VSBX' string ^ 0xFF)
pub fn unquarantine(data: &[u8]) -> Result<Vec<Vec<u8>>> {
    let mut data = bytearray_xor(data.to_owned(), 0xFF);
    let magic = unpack_i32(&data)?;
    let mut dataoffset = unpack_i32(utils::tail(&data, 4, "trend dataoffset")?)? as u32 as usize;
    let numtags = unpack_i16(utils::tail(&data, 8, "trend numtags")?)?;
    if magic != 0x58425356 {
        // VSBX
        return Err(Error::CannotUnQuarantineFile("trend".to_string()));
    }
    let mut basekey = 0x00000000;
    let mut encmethod = 0;

    if numtags > 15 {
        return Err(Error::CannotUnQuarantineFile("trend".to_string()));
    }
    dataoffset += 10;
    let offset = 10;
    for _ in 0..numtags {
        let (code, tagdata) = read_tag(&data, offset)?;
        match code {
            6 => {
                basekey = unpack_i32(&tagdata)?;
            }
            7 => {
                encmethod = unpack_i16(&tagdata)?;
            }
            _ => {}
        }
    }
    if dataoffset > data.len() {
        return Err(Error::Invalid("trend dataoffset"));
    }
    if encmethod != 2 {
        return Ok(vec![data[dataoffset..].to_vec()]);
    }
    let mut bytesleft = data.len() - dataoffset;
    let mut unaligned = dataoffset % 4;
    let mut firstiter = true;
    let mut curoffset = dataoffset;
    while bytesleft > 0 {
        let mut off = curoffset;
        if firstiter {
            off = curoffset - unaligned;
            firstiter = false;
        }
        let keyval = basekey.wrapping_add(off as i32);
        let cc = crc::Crc::<u32>::new(&crc::CRC_32_ISCSI);
        let crcbuf = cc.checksum(&keyval.to_le_bytes()[..]).to_le_bytes();
        for &kb in crcbuf.iter().skip(unaligned) {
            if bytesleft == 0 {
                break;
            }
            data[curoffset] ^= kb;
            curoffset += 1;
            bytesleft -= 1;
        }
        unaligned = 0;
    }
    Ok(vec![data[dataoffset..].to_vec()])
}

fn read_tag(data: &[u8], offset: usize) -> Result<(u8, Vec<u8>)> {
    let code = *data.get(offset).ok_or(Error::Truncated("trend tag code"))?;
    let length = unpack_i16(utils::tail(data, offset + 1, "trend tag len")?)? as usize;
    let body = utils::slice(data, offset + 3, length, "trend tag body")?.to_vec();
    Ok((code, body))
}
