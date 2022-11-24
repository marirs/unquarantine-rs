use crate::Result;
use ole::OleFile;

/// McAfee Quarantine files (BUP) /full support for OLE format/
pub fn unquarantine(file: &str) -> Result<Vec<Vec<u8>>> {
    let res = OleFile::from_file_blocking(file)?;
    let mut response = Vec::new();
    for stream_name in res.list_streams() {
        // Read File
        let data = res.open_stream(&[stream_name.as_str()])?;
        let file_data = decrypt_bup_bytes(data);
        response.push(file_data);
    }
    
    // Read File String
    let data = res.open_stream(&["Details"])?;
    let file_str = decrypt_bup_string(data);
    response.push(file_str.as_bytes().to_vec());
    Ok(response)
}

fn decrypt_bup_string(bup_data: Vec<u8>) -> String {
    bup_data.iter().map(|byte| (byte ^ 0x6A) as char).collect()
}

fn decrypt_bup_bytes(bup_data: Vec<u8>) -> Vec<u8> {
    bup_data.iter().map(|byte| byte ^ 0x6A).collect()
}
