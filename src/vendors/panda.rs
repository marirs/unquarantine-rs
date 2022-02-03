use crate::{error::Error, utils::blowfishit, Result};
use std::io::{BufReader, Cursor};
use zip::ZipArchive;

lazy_static! {
    static ref KEY: Vec<u8> = vec![
        0x3D, 0xD8, 0x22, 0x66, 0x65, 0x16, 0xE3, 0xB8, 0xC5, 0xD6, 0x18, 0x71, 0xE7, 0x19, 0xE0,
        0x5A,
    ];
}

/// Panda <GUID> Zip files
pub fn unquarantine(data: &[u8]) -> Result<Vec<Vec<u8>>> {
    let mut ress = vec![];
    let mut zip = ZipArchive::new(BufReader::new(Cursor::new(data.to_vec())))?;

    for i in 0..zip.len() {
        let mut file = zip.by_index(i)?;
        let mut res: Vec<u8> = vec![];
        std::io::copy(&mut file, &mut res)?;
        let dec = blowfishit(&res, &KEY)?;
        let dec2 = inflate::inflate_bytes(&dec).map_err(|e| Error::InflateError(e))?;
        ress.push(dec2);
    }
    Ok(ress)
}
