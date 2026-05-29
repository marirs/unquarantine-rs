use crate::Result;

/// BullGuard Q Files
pub fn unquarantine(data: &[u8]) -> Result<Vec<Vec<u8>>> {
    let dec = data
        .iter()
        .enumerate()
        .map(|(i, &b)| b ^ if i % 2 == 0 { 0x00 } else { 0x3F })
        .collect();
    Ok(vec![dec])
}
