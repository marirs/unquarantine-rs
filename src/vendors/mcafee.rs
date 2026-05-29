use crate::Result;
use std::{
    io::{Cursor, Read},
    path::PathBuf,
};

/// McAfee Quarantine files (BUP) — OLE2 / Compound File container.
///
/// Each stream is XOR-0x6A obfuscated. We decode every stream as bytes and,
/// additionally, the `Details` metadata stream as a string.
pub fn unquarantine(data: &[u8]) -> Result<Vec<Vec<u8>>> {
    let mut comp = cfb::CompoundFile::open(Cursor::new(data))?;

    // Collect stream paths first so the read-only borrow is released before we
    // take the mutable borrow needed by `open_stream`.
    let stream_paths: Vec<PathBuf> = comp
        .walk()
        .filter(|entry| entry.is_stream())
        .map(|entry| entry.path().to_path_buf())
        .collect();

    let mut response = Vec::new();
    for path in &stream_paths {
        let mut stream = comp.open_stream(path)?;
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf)?;
        response.push(decrypt_bup_bytes(&buf));
    }

    if let Ok(mut stream) = comp.open_stream("Details") {
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf)?;
        response.push(decrypt_bup_string(&buf).into_bytes());
    }

    Ok(response)
}

fn decrypt_bup_string(bup_data: &[u8]) -> String {
    bup_data.iter().map(|byte| (byte ^ 0x6A) as char).collect()
}

fn decrypt_bup_bytes(bup_data: &[u8]) -> Vec<u8> {
    bup_data.iter().map(|byte| byte ^ 0x6A).collect()
}
