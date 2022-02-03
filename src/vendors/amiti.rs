use crate::{utils::rc4_decrypt, Result};

/// Amiti (IFC)
pub fn unquarantine(data: &[u8]) -> Result<Vec<Vec<u8>>> {
    let x = b"AA79e10d15l6o2t8";
    let mut key = vec![];
    for k in 0..16 {
        key.push(x[k as usize] ^ 0xA4);
    }
    Ok(vec![rc4_decrypt(&mut ksa(), &mut data.to_owned())])
}

fn ksa() -> Vec<u8> {
    let key = b"AA79e10d15l6o2t8";
    let mut sbox: Vec<u8> = (0..=255).collect();
    let mut j = 0_usize;
    for i in 0..256 {
        j = (j + sbox[i] as usize + key[i % key.len()] as usize) % 256;
        sbox.swap(i, j);
    }
    sbox
}
