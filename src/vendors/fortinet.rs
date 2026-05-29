use crate::{
    Result,
    error::Error,
    utils::{self, bytearray_xor, unpack_i32},
};

/// FortiClient quarantine files (magic `QUARF\0\0\0`).
///
/// Layout (little-endian):
/// ```text
///   0x00   8  magic "QUARF\0\0\0"
///   0x08   4  unknown
///   0x0C   4  malware offset (inaccurate in practice)
///   0x10   2  unknown
///   0x12  32  SHA-256 of the original file
///   0x32   2  unknown
///   0x34   4  encrypted malware length
///   0x38  16  quarantine timestamp
///   0x48  12  unknown
///   0x54   4  file id
///   0x58   4  original filename length (UTF-16LE bytes)
///   0x5C   4  threat name length     (UTF-16LE bytes)
///   0x60      <filename><threat name><payload[mal_len]>
/// ```
/// The payload is XOR-`0xAB` encrypted. Port of DeXRAY's `extract_forticlient`
/// (originally by TheMythologist, based on NUKIB/maldump).
pub fn unquarantine(data: &[u8]) -> Result<Vec<Vec<u8>>> {
    // Fields are unsigned 32-bit; reinterpret the bits rather than sign-extend.
    let mal_len = unpack_i32(utils::tail(data, 0x34, "forti mal_len")?)? as u32 as usize;
    let fn_len = unpack_i32(utils::tail(data, 0x58, "forti fn_len")?)? as u32 as usize;
    let tn_len = unpack_i32(utils::tail(data, 0x5C, "forti tn_len")?)? as u32 as usize;

    let payload_start = 0x60usize
        .checked_add(fn_len)
        .and_then(|v| v.checked_add(tn_len))
        .ok_or(Error::Invalid("forti payload offset"))?;
    let payload = utils::slice(data, payload_start, mal_len, "forti payload")?;

    Ok(vec![bytearray_xor(payload.to_vec(), 0xAB)])
}
