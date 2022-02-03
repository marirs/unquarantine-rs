use crate::{error::Error, Result};
use std::convert::TryInto;
use std::{fs::File, io::Read, path::Path};

pub fn read_file<P: AsRef<Path>>(file: P) -> Result<Vec<u8>> {
    let f = File::open(file)?;
    let mut reader = std::io::BufReader::new(f);
    let mut buffer = Vec::new();
    reader.read_to_end(&mut buffer)?;
    Ok(buffer)
}

pub fn unpack_i64(data: &[u8]) -> Result<i64> {
    let vec: &[u8; 8] = data[..8].try_into()?;
    Ok(i64::from_le_bytes(*vec))
}

pub fn unpack_i32(data: &[u8]) -> Result<i32> {
    let vec: &[u8; 4] = data[..4].try_into()?;
    Ok(i32::from_le_bytes(*vec))
}

pub fn unpack_i16(data: &[u8]) -> Result<i16> {
    let vec: &[u8; 2] = data[..2].try_into()?;
    Ok(i16::from_le_bytes(*vec))
}

pub fn bytearray_xor(mut data: Vec<u8>, key: u8) -> Vec<u8> {
    for i in 0..data.len() {
        data[i] ^= key;
    }
    data
}

pub fn blowfishit(_data: &[u8], _key: &[u8]) -> Result<Vec<u8>> {
    Err(Error::NotImplementedError(file!(), line!()))
}

pub fn rc4_decrypt(sbox: &mut Vec<u8>, data: &mut Vec<u8>) -> Vec<u8> {
    let mut out = vec![0u8; data.len()];
    let mut i = 0_usize;
    let mut j = 0_usize;
    for (k, ch) in data.iter().enumerate() {
        i = (i + 1) % 256;
        j = (j + sbox[i] as usize) % 256;
        sbox.swap(i, j);
        let val = sbox[(sbox[i] as usize + sbox[j] as usize) % 256];
        out[k] = val ^ ch;
    }
    out
}
