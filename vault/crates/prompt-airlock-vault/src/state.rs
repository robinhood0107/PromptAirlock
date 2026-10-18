//! Scope 별 mapping 상태. 동기 코드이며 actor 스레드 하나만 소유한다.
//!
//! 원문은 scope 당 `entries` 에 한 번만 저장한다. 역색인(`by_value`)은 scope 별 무작위 키 SipHash 값만
//! 들고 있으며, 충돌은 저장된 원문과의 정확 비교로 해소한다. scope 가 drop 되면 `SecretValue` 가 zeroize 된다.

use std::collections::HashMap;
use std::collections::hash_map::RandomState;
use std::hash::BuildHasher;
use std::time::Duration;

use zeroize::Zeroizing;

use crate::clock::Clock;
use crate::config::VaultLimits;
use crate::error::VaultError;
use crate::token::{self, Token};
use crate::types::{EntityLabel, ScopeId, SecretValue};

struct Entry {
    label: EntityLabel,
    token: Token,
    value: SecretValue,
}

struct Scope {
    expires_at: Duration,
    entries: Vec<Entry>,
    by_token: HashMap<String, usize>,
    by_value: HashMap<u64, Vec<usize>>,
    hasher: RandomState,
}

impl Scope {
    fn value_hash(&self, label: &EntityLabel, value: &[u8]) -> u64 {
        self.hasher.hash_one((label.as_str(), value))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Stats {
    pub scopes: usize,
    pub mappings: usize,
}

pub struct VaultState<C: Clock> {
    clock: C,
    limits: VaultLimits,
    scopes: HashMap<ScopeId, Scope>,
}

impl<C: Clock> VaultState<C> {
    pub fn new(limits: VaultLimits, clock: C) -> Self {
        Self { clock, limits, scopes: HashMap::new() }
    }

    pub fn limits(&self) -> &VaultLimits {
        &self.limits
    }

    pub fn create_scope(&mut self, ttl: Duration) -> Result<(ScopeId, Duration), VaultError> {
        if ttl.is_zero() || ttl > self.limits.max_ttl {
            return Err(VaultError::InvalidArgument);
        }
        if self.scopes.len() >= self.limits.max_scopes {
            self.sweep();
            if self.scopes.len() >= self.limits.max_scopes {
                return Err(VaultError::ScopeLimit);
            }
        }
        let id = loop {
            let id = ScopeId::generate()?;
            if !self.scopes.contains_key(&id) {
                break id;
            }
        };
        let scope = Scope {
            expires_at: self.clock.now() + ttl,
            entries: Vec::new(),
            by_token: HashMap::new(),
            by_value: HashMap::new(),
            hasher: RandomState::new(),
        };
        self.scopes.insert(id, scope);
        Ok((id, ttl))
    }

    /// 만료 확인을 포함한 조회. 만료면 즉시 제거(zeroize)하고 ScopeExpired.
    fn live_scope(&mut self, id: &ScopeId) -> Result<&mut Scope, VaultError> {
        let now = self.clock.now();
        match self.scopes.get(id) {
            None => return Err(VaultError::ScopeNotFound),
            Some(s) if s.expires_at <= now => {
                self.scopes.remove(id);
                return Err(VaultError::ScopeExpired);
            }
            Some(_) => {}
        }
        self.scopes.get_mut(id).ok_or(VaultError::ScopeNotFound)
    }

    pub fn create_token(
        &mut self,
        id: &ScopeId,
        label: EntityLabel,
        value: SecretValue,
    ) -> Result<Token, VaultError> {
        if value.is_empty() {
            return Err(VaultError::InvalidArgument);
        }
        if value.len() > self.limits.max_value_bytes {
            return Err(VaultError::ValueTooLarge);
        }
        let max_mappings = self.limits.max_mappings_per_scope;
        let scope = self.live_scope(id)?;
        let h = scope.value_hash(&label, value.as_bytes());
        if let Some(idxs) = scope.by_value.get(&h) {
            for &i in idxs {
                let e = &scope.entries[i];
                if e.label == label && e.value.as_bytes() == value.as_bytes() {
                    // 같은 scope + 같은 값 + 같은 타입 → 같은 token. 새로 받은 사본은 여기서 drop(zeroize)된다.
                    return Ok(e.token.clone());
                }
            }
        }
        if scope.entries.len() >= max_mappings {
            return Err(VaultError::MappingLimit);
        }
        let tok = token::generate(&label, value.as_bytes(), |s| scope.by_token.contains_key(s))?;
        let idx = scope.entries.len();
        scope.by_token.insert(tok.as_str().to_owned(), idx);
        scope.by_value.entry(h).or_default().push(idx);
        scope.entries.push(Entry { label, token: tok.clone(), value });
        Ok(tok)
    }

    /// 정확히 일치하는 token 만 복원한다. 변형·미등록 token 은 오류이며 추측하지 않는다.
    pub fn resolve_exact(
        &mut self,
        id: &ScopeId,
        tok: &str,
    ) -> Result<(EntityLabel, Zeroizing<Vec<u8>>), VaultError> {
        token::check_shape(tok)?;
        let scope = self.live_scope(id)?;
        let idx = *scope.by_token.get(tok).ok_or(VaultError::TokenNotFound)?;
        let e = &scope.entries[idx];
        Ok((e.label.clone(), e.value.zeroizing_copy()))
    }

    pub fn drop_scope(&mut self, id: &ScopeId) -> Result<(), VaultError> {
        self.scopes.remove(id).map(drop).ok_or(VaultError::ScopeNotFound)
    }

    /// 만료 scope 를 제거한다. 제거 개수를 돌려준다.
    pub fn sweep(&mut self) -> usize {
        let now = self.clock.now();
        let before = self.scopes.len();
        self.scopes.retain(|_, s| s.expires_at > now);
        before - self.scopes.len()
    }

    pub fn stats(&self) -> Stats {
        Stats {
            scopes: self.scopes.len(),
            mappings: self.scopes.values().map(|s| s.entries.len()).sum(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::ManualClock;

    fn state() -> (VaultState<ManualClock>, ManualClock) {
        let clock = ManualClock::new();
        (VaultState::new(VaultLimits::default(), clock.clone()), clock)
    }

    fn v(s: &str) -> SecretValue {
        SecretValue::from_vec(s.as_bytes().to_vec())
    }

    fn l(s: &str) -> EntityLabel {
        EntityLabel::parse(s).unwrap()
    }

    const MIN: Duration = Duration::from_secs(60);

    #[test]
    fn same_value_same_token_different_value_different_token() {
        let (mut st, _) = state();
        let (s, _) = st.create_scope(MIN).unwrap();
        let a1 = st.create_token(&s, l("PERSON"), v("합성인물A")).unwrap();
        let a2 = st.create_token(&s, l("PERSON"), v("합성인물A")).unwrap();
        let b = st.create_token(&s, l("PERSON"), v("합성인물B")).unwrap();
        let a_other_type = st.create_token(&s, l("ORG"), v("합성인물A")).unwrap();
        assert_eq!(a1, a2);
        assert_ne!(a1, b);
        assert_ne!(a1, a_other_type);
        assert_eq!(st.stats().mappings, 3);
        assert!(!a1.as_str().contains("합성인물A"));
    }

    #[test]
    fn exact_restore_and_no_fuzzy() {
        let (mut st, _) = state();
        let (s, _) = st.create_scope(MIN).unwrap();
        let t = st.create_token(&s, l("PHONE"), v("010-0000-0001")).unwrap();
        let (label, val) = st.resolve_exact(&s, t.as_str()).unwrap();
        assert_eq!(label.as_str(), "PHONE");
        assert_eq!(&val[..], b"010-0000-0001");

        // 마지막 문자를 알파벳 안의 다른 문자로 바꾼 token: 모양은 맞지만 미등록 → TokenNotFound
        let mut chars: Vec<char> = t.as_str().chars().collect();
        let n = chars.len();
        chars[n - 2] = if chars[n - 2] == '0' { '1' } else { '0' };
        let modified: String = chars.into_iter().collect();
        assert_eq!(st.resolve_exact(&s, &modified).unwrap_err(), VaultError::TokenNotFound);
        // 라벨만 바꾼 token
        let relabeled = t.as_str().replacen("PHONE", "EMAIL", 1);
        assert_eq!(st.resolve_exact(&s, &relabeled).unwrap_err(), VaultError::TokenNotFound);
        // 소문자화·공백 → 모양 오류
        assert_eq!(st.resolve_exact(&s, &t.as_str().to_lowercase()).unwrap_err(), VaultError::MalformedToken);
        assert_eq!(st.resolve_exact(&s, &format!(" {}", t.as_str())).unwrap_err(), VaultError::MalformedToken);
    }

    #[test]
    fn scope_isolation() {
        let (mut st, _) = state();
        let (a, _) = st.create_scope(MIN).unwrap();
        let (b, _) = st.create_scope(MIN).unwrap();
        let ta = st.create_token(&a, l("PERSON"), v("합성인물A")).unwrap();
        let tb = st.create_token(&b, l("PERSON"), v("합성인물A")).unwrap();
        // 다른 scope 의 같은 값은 상관관계 없는 token
        assert_ne!(ta, tb);
        // 다른 scope 의 token 은 복원되지 않는다
        assert_eq!(st.resolve_exact(&b, ta.as_str()).unwrap_err(), VaultError::TokenNotFound);
        assert_eq!(st.resolve_exact(&a, tb.as_str()).unwrap_err(), VaultError::TokenNotFound);
        // 존재하지 않는 scope
        let ghost = ScopeId::generate().unwrap();
        assert_eq!(st.resolve_exact(&ghost, ta.as_str()).unwrap_err(), VaultError::ScopeNotFound);
    }

    #[test]
    fn ttl_lazy_expiry() {
        let (mut st, clock) = state();
        let (s, _) = st.create_scope(Duration::from_secs(10)).unwrap();
        let t = st.create_token(&s, l("PERSON"), v("합성인물A")).unwrap();
        clock.advance(Duration::from_millis(9_999));
        assert!(st.resolve_exact(&s, t.as_str()).is_ok());
        clock.advance(Duration::from_millis(1));
        assert_eq!(st.resolve_exact(&s, t.as_str()).unwrap_err(), VaultError::ScopeExpired);
        // 한 번 제거된 뒤에는 존재하지 않는 scope
        assert_eq!(st.resolve_exact(&s, t.as_str()).unwrap_err(), VaultError::ScopeNotFound);
        assert_eq!(st.stats().scopes, 0);
    }

    #[test]
    fn ttl_sweep_removes_expired_only() {
        let (mut st, clock) = state();
        let (short, _) = st.create_scope(Duration::from_secs(1)).unwrap();
        let (long, _) = st.create_scope(Duration::from_secs(100)).unwrap();
        st.create_token(&short, l("P"), v("x1")).unwrap();
        st.create_token(&long, l("P"), v("x2")).unwrap();
        clock.advance(Duration::from_secs(2));
        assert_eq!(st.sweep(), 1);
        assert_eq!(st.stats(), Stats { scopes: 1, mappings: 1 });
        assert_eq!(st.drop_scope(&short).unwrap_err(), VaultError::ScopeNotFound);
        assert!(st.drop_scope(&long).is_ok());
    }

    #[test]
    fn drop_scope_then_resolve_fails() {
        let (mut st, _) = state();
        let (s, _) = st.create_scope(MIN).unwrap();
        let t = st.create_token(&s, l("PERSON"), v("합성인물A")).unwrap();
        st.drop_scope(&s).unwrap();
        assert_eq!(st.resolve_exact(&s, t.as_str()).unwrap_err(), VaultError::ScopeNotFound);
        assert_eq!(st.drop_scope(&s).unwrap_err(), VaultError::ScopeNotFound);
        assert_eq!(st.stats(), Stats { scopes: 0, mappings: 0 });
    }

    #[test]
    fn limits_are_typed_errors() {
        let clock = ManualClock::new();
        let limits = VaultLimits { max_scopes: 2, max_mappings_per_scope: 2, max_value_bytes: 8, max_ttl: MIN };
        let mut st = VaultState::new(limits, clock.clone());
        assert_eq!(st.create_scope(Duration::ZERO).unwrap_err(), VaultError::InvalidArgument);
        assert_eq!(st.create_scope(MIN + Duration::from_secs(1)).unwrap_err(), VaultError::InvalidArgument);
        let (s, _) = st.create_scope(Duration::from_secs(1)).unwrap();
        st.create_scope(MIN).unwrap();
        assert_eq!(st.create_scope(MIN).unwrap_err(), VaultError::ScopeLimit);
        // 만료 scope 가 있으면 생성 시 정리 후 자리를 얻는다
        clock.advance(Duration::from_secs(2));
        let (s2, _) = st.create_scope(MIN).unwrap();
        assert_eq!(st.create_token(&s, l("P"), v("a")).unwrap_err(), VaultError::ScopeNotFound);
        assert_eq!(st.create_token(&s2, l("P"), v("123456789")).unwrap_err(), VaultError::ValueTooLarge);
        assert_eq!(st.create_token(&s2, l("P"), v("")).unwrap_err(), VaultError::InvalidArgument);
        st.create_token(&s2, l("P"), v("a")).unwrap();
        st.create_token(&s2, l("P"), v("b")).unwrap();
        assert_eq!(st.create_token(&s2, l("P"), v("c")).unwrap_err(), VaultError::MappingLimit);
        // 이미 있는 값은 한도와 무관하게 같은 token
        assert!(st.create_token(&s2, l("P"), v("a")).is_ok());
    }

    #[test]
    fn many_values_roundtrip() {
        let (mut st, _) = state();
        let (s, _) = st.create_scope(MIN).unwrap();
        let mut toks = Vec::new();
        for i in 0..2000 {
            toks.push(st.create_token(&s, l("ID"), v(&format!("synthetic-{i}"))).unwrap());
        }
        for (i, t) in toks.iter().enumerate() {
            let (_, val) = st.resolve_exact(&s, t.as_str()).unwrap();
            assert_eq!(&val[..], format!("synthetic-{i}").as_bytes());
        }
    }
}
