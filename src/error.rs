#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("{0} not found!")]
    FileNotFound(String),
    #[error("Not Inplemented error {0} {1}")]
    NotImplementedError(&'static str, u32),
    #[error("io error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("Array Slice error: {0}")]
    TryFromSliceError(#[from] std::array::TryFromSliceError),
    #[error("Utf8 error: {0}")]
    FromUtf8Error(#[from] std::string::FromUtf8Error),
    // #[error("Ole error: {0}")]
    // OleError(#[from] ole::Error),
    #[error("Base64 error: {0}")]
    Base64Error(#[from] base64::DecodeError),
    #[error("Zip error: {0}")]
    ZipError(#[from] zip::result::ZipError),
    #[error("Regex error: {0}")]
    RegexError(#[from] regex::Error),
    #[error("Inflate error: {0}")]
    InflateError(String),
    #[error("undefined quarantine method: {0}")]
    UndefinedQuarantineMethod(String),
}
