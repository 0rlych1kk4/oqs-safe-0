use core::fmt;

#[derive(Debug)]
pub enum OqsError {
    NotImplemented,
    InvalidLength,
    VerifyFail,
    Internal(&'static str),
}

impl fmt::Display for OqsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OqsError::NotImplemented => write!(f, "not implemented (enable `liboqs`)"),
            OqsError::InvalidLength => write!(f, "invalid length"),
            OqsError::VerifyFail => write!(f, "verification failed"),
            OqsError::Internal(m) => write!(f, "internal error: {}", m),
        }
    }
}

impl std::error::Error for OqsError {}
