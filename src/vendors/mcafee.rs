use crate::{error::Error, Result};

/// McAfee Quarantine files (BUP) /full support for OLE format/
pub fn unquarantine(_data: &[u8]) -> Result<Vec<Vec<u8>>> {
    //    let parser = ole::Reader::new(f)?;
    //    for _entry in parser.iterate() {
    //    }
    Err(Error::NotImplementedError(file!(), line!()))
}
