use crate::{Result, utils::bytearray_xor};
use std::io::{Cursor, Read, copy};

/// Per-entry cap on decompressed output, guarding against zip-bomb inputs.
const MAX_DECOMPRESSED: u64 = 512 << 20; // 512 MiB

/// Zip Unquarantine:
/// Total AV, SpyBOT
pub fn zip_unquarantine(data: &[u8], password: Option<&[u8]>) -> Result<Vec<Vec<u8>>> {
    let mut ress = vec![];
    let mut zip = zip::ZipArchive::new(Cursor::new(data))?;

    for i in 0..zip.len() {
        let mut res: Vec<u8> = vec![];
        match password {
            Some(pw) => {
                let file = zip.by_index_decrypt(i, pw)?;
                copy(&mut file.take(MAX_DECOMPRESSED), &mut res)?;
            }
            None => {
                let file = zip.by_index(i)?;
                copy(&mut file.take(MAX_DECOMPRESSED), &mut res)?;
            }
        }
        ress.push(res);
    }
    Ok(ress)
}

/// Data Unquarantine
/// SUPERAntiSpyware, Symantec QBD and QBI Files
pub fn data_unquarantine(data: &[u8], key: u8) -> Result<Vec<Vec<u8>>> {
    let newdata = bytearray_xor(data.to_vec(), key);
    Ok(vec![newdata])
}

/// XORFF
pub fn xorff_unquarantine(data: &[u8]) -> Result<Vec<Vec<u8>>> {
    let qdata = bytearray_xor(data.to_owned(), 0xFF);
    Ok(vec![qdata])
}
