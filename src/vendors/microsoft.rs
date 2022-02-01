use crate::{Result, error::Error, utils::{rc4_decrypt, bytearray_xor}};
use std::convert::TryInto;

lazy_static! {
    static ref KEY: Vec<i32> = vec![
        0x1E, 0x87, 0x78, 0x1B, 0x8D, 0xBA, 0xA8, 0x44, 0xCE, 0x69, 0x70, 0x2C, 0x0C, 0x78, 0xB7,
        0x86, 0xA3, 0xF6, 0x23, 0xB7, 0x38, 0xF5, 0xED, 0xF9, 0xAF, 0x83, 0x53, 0x0F, 0xB3, 0xFC,
        0x54, 0xFA, 0xA2, 0x1E, 0xB9, 0xCF, 0x13, 0x31, 0xFD, 0x0F, 0x0D, 0xA9, 0x54, 0xF6, 0x87,
        0xCB, 0x9E, 0x18, 0x27, 0x96, 0x97, 0x90, 0x0E, 0x53, 0xFB, 0x31, 0x7C, 0x9C, 0xBC, 0xE4,
        0x8E, 0x23, 0xD0, 0x53, 0x71, 0xEC, 0xC1, 0x59, 0x51, 0xB8, 0xF3, 0x64, 0x9D, 0x7C, 0xA3,
        0x3E, 0xD6, 0x8D, 0xC9, 0x04, 0x7E, 0x82, 0xC9, 0xBA, 0xAD, 0x97, 0x99, 0xD0, 0xD4, 0x58,
        0xCB, 0x84, 0x7C, 0xA9, 0xFF, 0xBE, 0x3C, 0x8A, 0x77, 0x52, 0x33, 0x55, 0x7D, 0xDE, 0x13,
        0xA8, 0xB1, 0x40, 0x87, 0xCC, 0x1B, 0xC8, 0xF1, 0x0F, 0x6E, 0xCD, 0xD0, 0x83, 0xA9, 0x59,
        0xCF, 0xF8, 0x4A, 0x9D, 0x1D, 0x50, 0x75, 0x5E, 0x3E, 0x19, 0x18, 0x18, 0xAF, 0x23, 0xE2,
        0x29, 0x35, 0x58, 0x76, 0x6D, 0x2C, 0x07, 0xE2, 0x57, 0x12, 0xB2, 0xCA, 0x0B, 0x53, 0x5E,
        0xD8, 0xF6, 0xC5, 0x6C, 0xE7, 0x3D, 0x24, 0xBD, 0xD0, 0x29, 0x17, 0x71, 0x86, 0x1A, 0x54,
        0xB4, 0xC2, 0x85, 0xA9, 0xA3, 0xDB, 0x7A, 0xCA, 0x6D, 0x22, 0x4A, 0xEA, 0xCD, 0x62, 0x1D,
        0xB9, 0xF2, 0xA2, 0x2E, 0xD1, 0xE9, 0xE1, 0x1D, 0x75, 0xBE, 0xD7, 0xDC, 0x0E, 0xCB, 0x0A,
        0x8E, 0x68, 0xA2, 0xFF, 0x12, 0x63, 0x40, 0x8D, 0xC8, 0x08, 0xDF, 0xFD, 0x16, 0x4B, 0x11,
        0x67, 0x74, 0xCD, 0x0B, 0x9B, 0x8D, 0x05, 0x41, 0x1E, 0xD6, 0x26, 0x2E, 0x42, 0x9B, 0xA4,
        0x95, 0x67, 0x6B, 0x83, 0x98, 0xDB, 0x2F, 0x35, 0xD3, 0xC1, 0xB9, 0xCE, 0xD5, 0x26, 0x36,
        0xF2, 0x76, 0x5E, 0x1A, 0x95, 0xCB, 0x7C, 0xA4, 0xC3, 0xDD, 0xAB, 0xDD, 0xBF, 0xF3, 0x82,
        0x53,
    ];
}

/// Microsoft Defender PC - partially supported (D3 45 C5 99 header)
pub fn pc_unquarantine(data: &Vec<u8>) -> Result<Vec<Vec<u8>>> {
    let mut data = data.clone();
    let fsize = data.len();
    if fsize < 12 || data[0] != 0x0B || data[1] != 0xAD || data[2] != 0x00 {
        return Err(Error::UndefinedQuarantineMethod("mse".to_string()));
    }
    let mut sbox = ksa();
    let outdata = rc4_decrypt(&mut sbox, &mut data);

    let headerlen_vec: &[u8; 4] = outdata[8..12].try_into()?;
    let headerlen = 0x28 + i32::from_le_bytes(*headerlen_vec);
    let origlen_vec: &[u8; 4] =
        outdata[headerlen as usize - 12..headerlen as usize - 8].try_into()?;
    let origlen = i32::from_le_bytes(*origlen_vec);

    if origlen + headerlen != fsize as i32 {
        return Err(Error::UndefinedQuarantineMethod("mse".to_string()));
    }

    Ok(vec![outdata[headerlen as usize..].to_vec()])
}

/// Microsoft Defender MAC
pub fn mac_unquarantine(data: &Vec<u8>) -> Result<Vec<Vec<u8>>> {
    Ok(vec![bytearray_xor(data.clone(), 0x25)])
}

/// Microsoft Antimalware / Microsoft Security Essentials
pub fn antimalware_unquarantine(data: &Vec<u8>) -> Result<Vec<Vec<u8>>> {
    Ok(vec![bytearray_xor(data.clone(), 0xff)])
}


fn ksa() -> Vec<u8> {
    let mut sbox: Vec<u8> = (0..=255).collect();
    let mut j = 0 as usize;
    for i in 0..256 {
        j = (j + sbox[i] as usize + KEY[i] as usize) % 256;
        let tmp = sbox[i];
        sbox[i] = sbox[j];
        sbox[j] = tmp;
    }
    return sbox;
}
