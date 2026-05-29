use crate::{
    Result,
    utils::{self, blowfishit},
};
use std::io::{Cursor, Read, copy};
use zip::ZipArchive;

/// Per-entry cap on decompressed output, guarding against zip-bomb inputs.
const MAX_DECOMPRESSED: u64 = 512 << 20; // 512 MiB

const KEY: &[u8] = &[
    0x3D, 0xD8, 0x22, 0x66, 0x65, 0x16, 0xE3, 0xB8, 0xC5, 0xD6, 0x18, 0x71, 0xE7, 0x19, 0xE0, 0x5A,
];

/// Panda <GUID> Zip files
pub fn unquarantine(data: &[u8]) -> Result<Vec<Vec<u8>>> {
    let mut ress = vec![];
    let mut zip = ZipArchive::new(Cursor::new(data))?;

    for i in 0..zip.len() {
        let file = zip.by_index(i)?;
        let mut res: Vec<u8> = vec![];
        copy(&mut file.take(MAX_DECOMPRESSED), &mut res)?;
        let dec = blowfishit(&res, KEY)?;
        let dec2 = utils::inflate(&dec)?;
        ress.push(dec2);
    }
    Ok(ress)
}
