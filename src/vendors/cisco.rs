use crate::Result;

/// Cisco AMP
pub fn amp_unquarantine(data: &[u8]) -> Result<Vec<Vec<u8>>> {
    let dec = data.iter().map(|b| b ^ 0x77).collect();
    Ok(vec![dec])
}
