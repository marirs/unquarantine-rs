use crate::Result;

/// BitDefender, Lavasoft AdAware, Total Defence BDQ Files
pub fn unquarantine(data: &[u8]) -> Result<Vec<Vec<u8>>> {
    let mut dec = vec![];
    let mut cl: u8 = 25;
    let mut dl: u8 = 43;
    for i in 0..data.len() {
        dec.push((data[i] as i8 - dl as i8) as u8 ^ cl);
        cl = (cl as u16 + 3) as u8;
        dl = (dl as u16 + 20) as u8;
    }
    Ok(vec![dec])
}
