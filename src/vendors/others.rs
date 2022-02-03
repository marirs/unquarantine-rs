use crate::{utils::bytearray_xor, Result};

/// Zip Unqurantine:
/// Total AV, SpyBOT
pub fn zip_unquarantine(data: &[u8]) -> Result<Vec<Vec<u8>>> {
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

/// Data Unquarantine
/// SUPERAntiSpyware, Symantec QBD and QBI Files
pub fn data_unquarantine(data: &[u8], key: u8) -> Result<Vec<Vec<u8>>> {
    let newdata = bytearray_xor(data.to_vec(), key);
    Ok(vec![newdata])
}

/// XORFF
///
pub fn xorff_unquarantine(data: &[u8]) -> Result<Vec<Vec<u8>>> {
    let qdata = bytearray_xor(data.to_owned(), 0xFF);
    Ok(vec![qdata])
}
