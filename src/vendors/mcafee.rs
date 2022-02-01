use crate::{Result, error::Error};

/// McAfee Quarantine files (BUP) /full support for OLE format/
pub fn unquarantine(_data: &Vec<u8>) -> Result<Vec<Vec<u8>>> {
    //    let parser = ole::Reader::new(f)?;
    //    for _entry in parser.iterate() {
    //    }
    Err(Error::NotImplementedError(file!(), line!()))
}
