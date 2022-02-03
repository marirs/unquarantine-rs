use crate::Result;

/// ESafe (VIR)
pub fn unquarantine(data: &[u8]) -> Result<Vec<Vec<u8>>> {
    let bytes = base64::decode(data)?;
    Ok(vec![bytes])
}
