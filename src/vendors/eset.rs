use crate::Result;

/// ESET (NQF)
pub fn unquarantine(data: &[u8]) -> Result<Vec<Vec<u8>>> {
    let newdata = data
        .iter()
        .map(|&b| (b as i8).wrapping_sub(84) as u8 ^ 0xa5)
        .collect();
    Ok(vec![newdata])
}
