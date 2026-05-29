use crate::Result;

/// BitDefender, Lavasoft AdAware, Total Defence BDQ Files
pub fn unquarantine(data: &[u8]) -> Result<Vec<Vec<u8>>> {
    let mut dec = Vec::with_capacity(data.len());
    let mut cl: u8 = 25;
    let mut dl: u8 = 43;
    for &b in data {
        dec.push((b as i8).wrapping_sub(dl as i8) as u8 ^ cl);
        cl = cl.wrapping_add(3);
        dl = dl.wrapping_add(20);
    }
    Ok(vec![dec])
}
