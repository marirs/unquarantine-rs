use crate::{
    Result,
    error::Error,
    utils::{self, bytearray_xor, unpack_i16, unpack_i32},
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
///   0x38  16  quarantine timestamp (8 x i16: year, month, tz, day,
///             hour, minute, second, microsecond)
///   0x48  12  unknown
///   0x54   4  file id
///   0x58   4  original filename length (UTF-16LE bytes)
///   0x5C   4  threat name length     (UTF-16LE bytes)
///   0x60      <filename><threat name><payload[mal_len]>
/// ```
/// The payload is XOR-`0xAB` encrypted. Full port of DeXRAY's
/// `extract_forticlient` (originally by TheMythologist, based on NUKIB/maldump):
/// returns the decrypted payload as buffer 0, and a metadata text blob
/// (SHA-256 / timestamp / file id / original filename / threat name) as buffer 1
/// — mirroring DeXRAY's `.out` + `.met` outputs.
pub fn unquarantine(data: &[u8]) -> Result<Vec<Vec<u8>>> {
    let sha256 = utils::slice(data, 0x12, 32, "forti sha256")?;
    // Fields are unsigned 32-bit; reinterpret the bits rather than sign-extend.
    let mal_len = unpack_i32(utils::tail(data, 0x34, "forti mal_len")?)? as u32 as usize;
    let timestamp = utils::slice(data, 0x38, 16, "forti timestamp")?;
    let file_id = unpack_i32(utils::tail(data, 0x54, "forti file_id")?)? as u32;
    let fn_len = unpack_i32(utils::tail(data, 0x58, "forti fn_len")?)? as u32 as usize;
    let tn_len = unpack_i32(utils::tail(data, 0x5C, "forti tn_len")?)? as u32 as usize;

    let filename = utils::slice(data, 0x60, fn_len, "forti filename")?;
    let tn_start = 0x60usize
        .checked_add(fn_len)
        .ok_or(Error::Invalid("forti threat-name offset"))?;
    let threat = utils::slice(data, tn_start, tn_len, "forti threat name")?;
    let payload_start = tn_start
        .checked_add(tn_len)
        .ok_or(Error::Invalid("forti payload offset"))?;
    let payload = utils::slice(data, payload_start, mal_len, "forti payload")?;

    let decrypted = bytearray_xor(payload.to_vec(), 0xAB);

    let meta = format!(
        "Magic             = QUARF\n\
         SHA256            = {}\n\
         Quarantine Time   = {}\n\
         File ID           = {}\n\
         Original Filename = {}\n\
         Threat Name       = {}\n",
        to_hex(sha256),
        format_timestamp(timestamp)?,
        file_id,
        utf16le(filename),
        utf16le(threat),
    );

    Ok(vec![decrypted, meta.into_bytes()])
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn utf16le(bytes: &[u8]) -> String {
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    String::from_utf16_lossy(&units)
}

fn format_timestamp(ts: &[u8]) -> Result<String> {
    let year = unpack_i16(utils::slice(ts, 0x0, 2, "forti ts")?)?;
    let month = unpack_i16(utils::slice(ts, 0x2, 2, "forti ts")?)?;
    let tz = unpack_i16(utils::slice(ts, 0x4, 2, "forti ts")?)?;
    let day = unpack_i16(utils::slice(ts, 0x6, 2, "forti ts")?)?;
    let hour = unpack_i16(utils::slice(ts, 0x8, 2, "forti ts")?)?;
    let minute = unpack_i16(utils::slice(ts, 0xA, 2, "forti ts")?)?;
    let second = unpack_i16(utils::slice(ts, 0xC, 2, "forti ts")?)?;
    let micro = unpack_i16(utils::slice(ts, 0xE, 2, "forti ts")?)?;
    Ok(format!(
        "{month}/{day}/{year} {hour}:{minute}:{second}:{micro} +{tz}"
    ))
}
