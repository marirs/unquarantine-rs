use crate::Result;

/// QuickHeal `<hash>` files
pub fn unquarantine(data: &[u8]) -> Result<Vec<Vec<u8>>> {
    // nibble swap
    let dec = data.iter().map(|&b| b.rotate_left(4)).collect();
    Ok(vec![dec])
}
