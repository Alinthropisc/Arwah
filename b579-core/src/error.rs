use thiserror::Error;

#[derive(Debug, Error)]
pub enum ArwahError {
    #[error("capture error: {0}")]
    Capture(String),

    #[error("filter syntax error at position {pos}: {msg}")]
    FilterSyntax { pos: usize, msg: String },

    #[error("protocol dissection failed: {0}")]
    Dissection(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("geo lookup failed: {0}")]
    GeoLookup(String),

    #[error("invalid interface: {0}")]
    InvalidInterface(String),

    #[error("permission denied — run as root or grant CAP_NET_RAW")]
    PermissionDenied,
}

pub type ArwahResult<T> = Result<T, ArwahError>;
