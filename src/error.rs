/// Errors produced by QS-Crypto operations.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("authentication failed: invalid ciphertext or tag")]
    AuthenticationFailed,

    #[error("decapsulation failed: ciphertext rejected by FO check")]
    DecapsulationFailed,

    #[error("deserialization failed: {0}")]
    Deserialization(String),

    #[error("invalid parameter: {0}")]
    InvalidParameter(String),

    #[error("PAKE protocol error: {0}")]
    Pake(String),

    #[error("session error: {0}")]
    Session(String),
}
