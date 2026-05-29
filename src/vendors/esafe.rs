use crate::Result;
use base64::Engine;

/// ESafe (VIR)
pub fn unquarantine(data: &[u8]) -> Result<Vec<Vec<u8>>> {
    let bytes = base64::engine::general_purpose::STANDARD.decode(data)?;
    Ok(vec![bytes])
}
