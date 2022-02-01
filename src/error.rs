#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Not Inplemented error {0} {1}")]
    NotImplementedError(&'static str, u32),
    #[error("io error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("io error: {0}")]
    TryFromSliceError(#[from] std::array::TryFromSliceError),
    #[error("io error: {0}")]
    FromUtf8Error(#[from] std::string::FromUtf8Error),
    #[error("io error: {0}")]
    OleError(#[from] ole::Error),
    #[error("io error: {0}")]
    Base64Error(#[from] base64::DecodeError),
    #[error("io error: {0}")]
    ZipError(#[from] zip::result::ZipError),
    #[error("io error: {0}")]
    RegexError(#[from] regex::Error),
    #[error("io error: {0}")]
    InflateError(String),
    #[error("undefined quarantine method: {0}")]
    UndefinedQuarantineMethod(String),
}
