use crate::Result;

/// ESET (NQF)
pub fn unquarantine(data: &Vec<u8>) -> Result<Vec<Vec<u8>>> {
    let mut newdata = vec![];
    for i in 0..data.len() {
        newdata.push((data[i] as i8 - 84) as u8 ^ 0xa5);
    }
    Ok(vec![newdata])
}
