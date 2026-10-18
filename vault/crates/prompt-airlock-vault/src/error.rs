//! Vault 오류. 오류 값에는 원문·token·scope id 를 담지 않는다.

use crate::proto::ErrorCode;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultError {
    ScopeNotFound,
    ScopeExpired,
    TokenNotFound,
    MalformedToken,
    ScopeLimit,
    MappingLimit,
    ValueTooLarge,
    InvalidArgument,
    Overloaded,
    Internal,
    ShuttingDown,
}

impl VaultError {
    pub fn to_proto(self) -> ErrorCode {
        match self {
            Self::ScopeNotFound => ErrorCode::ScopeNotFound,
            Self::ScopeExpired => ErrorCode::ScopeExpired,
            Self::TokenNotFound => ErrorCode::TokenNotFound,
            Self::MalformedToken => ErrorCode::MalformedToken,
            Self::ScopeLimit => ErrorCode::ScopeLimit,
            Self::MappingLimit => ErrorCode::MappingLimit,
            Self::ValueTooLarge => ErrorCode::ValueTooLarge,
            Self::InvalidArgument => ErrorCode::InvalidArgument,
            Self::Overloaded => ErrorCode::Overloaded,
            Self::Internal => ErrorCode::Internal,
            Self::ShuttingDown => ErrorCode::ShuttingDown,
        }
    }
}
