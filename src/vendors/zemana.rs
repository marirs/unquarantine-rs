use crate::{Result, utils::rc4_decrypt};

/// Zemana <hash> files+quarantine.db
pub fn unquarantine(data: &Vec<u8>) -> Result<Vec<Vec<u8>>> {
    Ok(vec![rc4_decrypt(&mut ksa(), &mut data.to_vec())])
}

fn ksa() -> Vec<u8> {
    let key = b"A8147B3ABF8533AB27FA9551B1FAA385";
    let mut sbox: Vec<u8> = (0..=255).collect();
    let mut j = 0 as usize;
    for i in 0..256 {
        j = (j + sbox[i] as usize + key[i % key.len()] as usize) % 256;
        let tmp = sbox[i];
        sbox[i] = sbox[j];
        sbox[j] = tmp;
    }
    sbox
}
