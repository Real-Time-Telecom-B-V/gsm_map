/// Errors that can occur during GSM MAP message processing.
#[derive(Debug, thiserror::Error)]
pub enum MapError {
    #[error("BER decode error: {0}")]
    DecodeError(String),

    #[error("BER encode error: {0}")]
    EncodeError(String),

    #[error("TCAP error: {0}")]
    TcapError(#[from] tcap::TcapError),

    #[error("invalid operation code: {0}")]
    InvalidOperationCode(i64),

    #[error("missing field: {0}")]
    MissingField(String),

    #[error("invalid address: {0}")]
    InvalidAddress(String),
}

impl From<rasn::error::DecodeError> for MapError {
    fn from(e: rasn::error::DecodeError) -> Self {
        Self::DecodeError(format!("{e}"))
    }
}

impl From<rasn::error::EncodeError> for MapError {
    fn from(e: rasn::error::EncodeError) -> Self {
        Self::EncodeError(format!("{e}"))
    }
}
