#[derive(Debug, thiserror::Error)]
pub enum EngineError {
    #[error("http: {0}")]
    Http(String),
    #[error("json-rpc error: {0}")]
    Rpc(simd_json::OwnedValue),
    #[error("missing result field in response")]
    MissingResult,
    #[error("serde: {0}")]
    Json(#[from] simd_json::Error),
    #[error("jwt: {0}")]
    Jwt(String),
    #[error("ipc: {0}")]
    Ipc(String),
    #[error("ssz: {0}")]
    Ssz(String),
}
