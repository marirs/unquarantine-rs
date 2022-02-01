use crate::Result;

/// BullGuard Q Files
pub fn unquarantine(data: &Vec<u8>) -> Result<Vec<Vec<u8>>> {
    let mut dec = vec![];
    for i in 0..data.len() {
        dec.push(data[i] ^ if i % 2 == 0 { 0x00 } else { 0x3F });
    }
    Ok(vec![dec])
}

