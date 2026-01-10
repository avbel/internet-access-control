use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Allow,
    Deny,
}

#[derive(Debug, Deserialize)]
pub struct RuleRequest {
    pub device: String,
    pub action: Action,
}

#[derive(Debug, Serialize)]
pub struct StatusResponse {
    pub device: String,
    pub mac: String,
    pub allowed: bool,
}

#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: String,
}

#[derive(Debug, Serialize)]
pub struct AliasEntry {
    pub alias: String,
    pub mac: String,
}

#[derive(Debug, Serialize)]
pub struct AliasesResponse {
    pub aliases: Vec<AliasEntry>,
}
