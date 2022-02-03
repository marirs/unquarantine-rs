use crate::Result;

/// Cisco AMP
pub fn amp_unquarantine(data: &[u8]) -> Result<Vec<Vec<u8>>> {
    let mut dec = vec![];
    for i in 0..data.len() {
        dec.push(data[i] ^ 0x77);
    }
    Ok(vec![dec])
}
