use crate::{utils::rc4_decrypt, Result};

/// Zemana <hash> files+quarantine.db
pub fn unquarantine(data: &[u8]) -> Result<Vec<Vec<u8>>> {
    Ok(vec![rc4_decrypt(&mut ksa(), &mut data.to_vec())])
}

fn ksa() -> Vec<u8> {
    let key = b"A8147B3ABF8533AB27FA9551B1FAA385";
    let mut sbox: Vec<u8> = (0..=255).collect();
    let mut j = 0_usize;
    for i in 0..256 {
        j = (j + sbox[i] as usize + key[i % key.len()] as usize) % 256;
        sbox.swap(i, j)
        // let tmp = sbox[i];
        // sbox[i] = sbox[j];
        // sbox[j] = tmp;
    }
    sbox
}
