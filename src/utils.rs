use crate::{Result, error::Error};
use blowfish::Blowfish;
use cipher::{Block, BlockCipherDecrypt, KeyInit};
use std::{
    convert::TryInto,
    fs::File,
    io::{BufReader, Read},
    path::Path,
};

pub fn read_file<P: AsRef<Path>>(file: P) -> Result<Vec<u8>> {
    let f = File::open(file)?;
    let mut buffer = Vec::new();
    {
        let mut reader = BufReader::new(f);
        reader.read_to_end(&mut buffer)?;
    }
    Ok(buffer)
}

/// Checked sub-slice: returns `data[start..start + len]` or an error instead of
/// panicking when the range is out of bounds.
pub fn slice<'a>(data: &'a [u8], start: usize, len: usize, what: &'static str) -> Result<&'a [u8]> {
    let end = start.checked_add(len).ok_or(Error::Truncated(what))?;
    data.get(start..end).ok_or(Error::Truncated(what))
}

/// Checked tail-slice: returns `data[start..]` or an error.
pub fn tail<'a>(data: &'a [u8], start: usize, what: &'static str) -> Result<&'a [u8]> {
    data.get(start..).ok_or(Error::Truncated(what))
}

pub fn unpack_i64(data: &[u8]) -> Result<i64> {
    let vec: &[u8; 8] = data.get(..8).ok_or(Error::Truncated("i64"))?.try_into()?;
    Ok(i64::from_le_bytes(*vec))
}

pub fn unpack_i32(data: &[u8]) -> Result<i32> {
    let vec: &[u8; 4] = data.get(..4).ok_or(Error::Truncated("i32"))?.try_into()?;
    Ok(i32::from_le_bytes(*vec))
}

pub fn unpack_i16(data: &[u8]) -> Result<i16> {
    let vec: &[u8; 2] = data.get(..2).ok_or(Error::Truncated("i16"))?.try_into()?;
    Ok(i16::from_le_bytes(*vec))
}

pub fn bytearray_xor(mut data: Vec<u8>, key: u8) -> Vec<u8> {
    for b in data.iter_mut() {
        *b ^= key;
    }
    data
}

/// Blowfish ECB decryption (big-endian, the variant used by the legacy
/// `rust-crypto` implementation these parsers were written against).
///
/// Decrypts whole 8-byte blocks; any trailing partial block is ignored, which
/// matches the behaviour the vendor parsers expect.
pub fn blowfishit(data: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    // Blowfish<BE> is the big-endian default; annotate so inference picks it.
    let cipher: Blowfish =
        Blowfish::new_from_slice(key).map_err(|_| Error::Invalid("blowfish key length"))?;
    let mut out = Vec::with_capacity(data.len());
    for chunk in data.chunks_exact(8) {
        let mut block =
            Block::<Blowfish>::try_from(chunk).map_err(|_| Error::Invalid("blowfish block"))?;
        cipher.decrypt_block(&mut block);
        out.extend_from_slice(&block);
    }
    Ok(out)
}

/// Raw-DEFLATE inflate (no zlib/gzip wrapper), the equivalent of the old
/// `inflate::inflate_bytes`.
pub fn inflate(data: &[u8]) -> Result<Vec<u8>> {
    // Cap output to bound decompression-bomb inputs.
    const MAX_INFLATED: usize = 512 << 20; // 512 MiB
    miniz_oxide::inflate::decompress_to_vec_with_limit(data, MAX_INFLATED)
        .map_err(|e| Error::InflateError(format!("{e:?}")))
}

pub fn rc4_decrypt(sbox: &mut [u8], data: &[u8]) -> Vec<u8> {
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
