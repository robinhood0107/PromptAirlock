//! Vault 도메인 타입. 원문 값은 `SecretValue` 로만 다루고 Debug 출력에 내용을 싣지 않는다.

use std::fmt;

use zeroize::Zeroizing;

use crate::error::VaultError;

/// CSPRNG 로 채운다. 실패하면 fail closed(Internal).
pub fn csprng_fill(buf: &mut [u8]) -> Result<(), VaultError> {
    getrandom::fill(buf).map_err(|_| VaultError::Internal)
}

/// 16바이트 불투명 scope 식별자. 추측 불가능해야 하므로 CSPRNG 로만 만든다.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ScopeId([u8; 16]);

impl ScopeId {
    pub const LEN: usize = 16;

    pub fn generate() -> Result<Self, VaultError> {
        let mut b = [0u8; 16];
        csprng_fill(&mut b)?;
        Ok(Self(b))
    }

    pub fn from_slice(s: &[u8]) -> Result<Self, VaultError> {
        let arr: [u8; 16] = s.try_into().map_err(|_| VaultError::InvalidArgument)?;
        Ok(Self(arr))
    }

    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl fmt::Debug for ScopeId {
    // scope id 는 capability 이므로 로그·디버그 출력에 전체를 남기지 않는다.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ScopeId({:02x}..)", self.0[0])
    }
}

/// 대문자 엔티티 라벨. 1~24자, `[A-Z][A-Z0-9_]*`.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct EntityLabel(String);

impl EntityLabel {
    pub const MAX_LEN: usize = 24;

    pub fn parse(s: &str) -> Result<Self, VaultError> {
        let b = s.as_bytes();
        let ok = !b.is_empty()
            && b.len() <= Self::MAX_LEN
            && b[0].is_ascii_uppercase()
            && b.iter().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || *c == b'_');
        if ok { Ok(Self(s.to_owned())) } else { Err(VaultError::InvalidArgument) }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// 보호 대상 원문. 복사 불가, drop 시 zeroize. Debug 는 길이만 출력한다.
pub struct SecretValue(Zeroizing<Vec<u8>>);

impl SecretValue {
    /// 이미 받은 버퍼를 그대로 감싼다(추가 복사 없음).
    pub fn from_vec(v: Vec<u8>) -> Self {
        Self(Zeroizing::new(v))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// 응답 전송용 사본. 사본도 Zeroizing 이다.
    pub fn zeroizing_copy(&self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(self.0.to_vec())
    }
}

impl fmt::Debug for SecretValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretValue(<redacted {} bytes>)", self.0.len())
    }
}

/// 32바이트 실행별 인증 비밀값.
pub struct AuthSecret(Zeroizing<[u8; 32]>);

impl AuthSecret {
    pub fn generate() -> Result<Self, VaultError> {
        let mut s = Zeroizing::new([0u8; 32]);
        csprng_fill(&mut s[..])?;
        Ok(Self(s))
    }

    /// 시험과 부모 프로세스가 비밀값을 정해 넘기는 구성을 위한 생성자.
    pub fn from_bytes(b: [u8; 32]) -> Self {
        Self(Zeroizing::new(b))
    }

    /// 길이가 같을 때 내용 비교 시간이 입력에 따라 달라지지 않게 한다.
    pub fn ct_eq(&self, other: &[u8]) -> bool {
        if other.len() != self.0.len() {
            return false;
        }
        let diff = self.0.iter().zip(other).fold(0u8, |acc, (a, b)| acc | (a ^ b));
        std::hint::black_box(diff) == 0
    }

    pub fn to_hex(&self) -> Zeroizing<String> {
        let mut s = Zeroizing::new(String::with_capacity(64));
        for b in self.0.iter() {
            s.push(char::from_digit(u32::from(b >> 4), 16).unwrap_or('0'));
            s.push(char::from_digit(u32::from(b & 0xf), 16).unwrap_or('0'));
        }
        s
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0[..]
    }
}

impl fmt::Debug for AuthSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AuthSecret(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entity_label_validation() {
        assert!(EntityLabel::parse("PERSON").is_ok());
        assert!(EntityLabel::parse("PHONE_KR2").is_ok());
        for bad in ["", "person", "1ABC", "A-B", "가나", "ABCDEFGHIJKLMNOPQRSTUVWXY"] {
            assert_eq!(EntityLabel::parse(bad), Err(VaultError::InvalidArgument), "{bad}");
        }
    }

    #[test]
    fn scope_id_is_random_and_debug_is_redacted() {
        let a = ScopeId::generate().unwrap();
        let b = ScopeId::generate().unwrap();
        assert_ne!(a, b);
        let dbg = format!("{a:?}");
        assert!(dbg.len() < 16, "{dbg}");
        assert_eq!(ScopeId::from_slice(&[0u8; 15]), Err(VaultError::InvalidArgument));
    }

    #[test]
    fn secret_value_debug_hides_content() {
        let v = SecretValue::from_vec(b"synthetic-hong-gildong".to_vec());
        let dbg = format!("{v:?}");
        assert!(!dbg.contains("hong"), "{dbg}");
    }

    #[test]
    fn auth_secret_ct_eq() {
        let s = AuthSecret::from_bytes([7u8; 32]);
        assert!(s.ct_eq(&[7u8; 32]));
        assert!(!s.ct_eq(&[7u8; 31]));
        let mut other = [7u8; 32];
        other[31] = 8;
        assert!(!s.ct_eq(&other));
        assert_eq!(s.to_hex().len(), 64);
    }
}
