use crate::Result;

/// QuickHeal <hash> files
pub fn unquarantine(data: &[u8]) -> Result<Vec<Vec<u8>>> {
    let mut dec = vec![];
    for i in 0..data.len() {
        let b1 = data[i];
        let b2 = b1;
        dec.push((b1 >> 4) | (b2 << 4));
    }
    Ok(vec![dec])
}
