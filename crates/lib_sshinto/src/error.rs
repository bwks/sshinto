use std::io;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SshintoError {
    #[error("SSH protocol error: {0}")]
    Ssh(#[from] russh::Error),

    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    #[error("Key error: {0}")]
    KeyError(#[from] russh::keys::Error),

    #[error("Authentication failed")]
    AuthFailed,

    #[error("Timed out waiting for prompt")]
    Timeout,

    #[error("Channel closed before prompt matched")]
    ChannelClosed,
}

pub type Result<T> = std::result::Result<T, SshintoError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_failed_display() {
        let err = SshintoError::AuthFailed;
        assert_eq!(err.to_string(), "Authentication failed");
    }

    #[test]
    fn timeout_display() {
        let err = SshintoError::Timeout;
        assert_eq!(err.to_string(), "Timed out waiting for prompt");
    }

    #[test]
    fn channel_closed_display() {
        let err = SshintoError::ChannelClosed;
        assert_eq!(err.to_string(), "Channel closed before prompt matched");
    }

    #[test]
    fn io_error_from() {
        let io_err = io::Error::new(io::ErrorKind::ConnectionRefused, "refused");
        let err = SshintoError::from(io_err);
        assert!(matches!(err, SshintoError::Io(_)));
        assert!(err.to_string().contains("refused"));
    }
}
