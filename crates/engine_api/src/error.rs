use silver_common::TapeError;

#[derive(Debug, thiserror::Error)]
pub enum EngineError {
    #[error("http: {0}")]
    Http(String),
    #[error("json-rpc error: {0}")]
    Rpc(String),
    #[error("missing result field in response")]
    MissingResult,
    #[error("serde: {0}")]
    Json(#[from] simd_json::Error),
    #[error("jwt: {0}")]
    Jwt(String),
    #[error("ssz: {0}")]
    Ssz(String),
}

impl From<TapeError> for EngineError {
    fn from(error: TapeError) -> Self {
        match error {
            TapeError::Json(e) => Self::Json(e),
            TapeError::Overflow => Self::Ssz("frame outgrew its response".into()),
            TapeError::Reservation(e) => Self::Ssz(e.to_string()),
        }
    }
}
