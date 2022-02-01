use crate::{utils::unpack_i32, Result};

pub fn unquarantine(data: &Vec<u8>) -> Result<Vec<Vec<u8>>> {
    let o2d = unpack_i32(&data[58..])? + 0x58;
    let data = &data[o2d as usize..data.len() - o2d as usize];
    let key = vec![
        0x76, 0x33, 0x62, 0x61, 0x63, 0x6B, 0x75, 0x70, 0x21, 0x40, 0x23, 0x24, 0x25, 0x5E, 0x26,
        0x29,
    ];
    let mut dec = vec![];
    let mut ki = 0 as usize;
    for i in 0..data.len() {
        dec.push(data[i as usize] ^ key[ki]);
        ki += 1;
        if ki > key.len() - 1 {
            ki = 0;
        }
    }
    Ok(vec![dec])
}
