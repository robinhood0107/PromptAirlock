//! Pseudonym token 형식과 생성(spec §26).
//!
//! 형식: `⟦<LABEL>_<R>⟧`, R 은 Crockford base32 대문자 10자(50비트, CSPRNG).
//! - 원문에서 유도하지 않는다(전역 결정적 hash 금지). 같은 scope 안의 재사용은 Vault 의 역색인으로만 한다.
//! - 다른 scope 의 token 은 우연히 같을 확률이 무시할 수준이고, 같은 scope 안에서는 생성 시 중복을 거절한다.
//! - R 에 원문의 4자(원문이 더 짧으면 원문 전체) 이상 부분 문자열이 우연히 나타나면 다시 뽑는다.

use crate::error::VaultError;
use crate::types::{EntityLabel, csprng_fill};

pub const OPEN: char = '⟦';
pub const CLOSE: char = '⟧';
pub const RANDOM_LEN: usize = 10;
/// Crockford base32: I, L, O, U 제외(시각 혼동과 LLM 복사 오류를 줄인다).
pub const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
/// 원문 부분 문자열 검사 창 크기.
pub const LEAK_WINDOW: usize = 4;
const MAX_ATTEMPTS: usize = 64;

#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct Token(String);

impl Token {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

fn random_part() -> Result<[u8; RANDOM_LEN], VaultError> {
    let mut raw = [0u8; RANDOM_LEN];
    csprng_fill(&mut raw)?;
    // 32 = 2^5 이므로 하위 5비트 선택은 균등 분포다.
    Ok(raw.map(|b| ALPHABET[usize::from(b & 31)]))
}

/// random 부분에 원문 조각이 들어 있으면 true. ASCII 대소문자를 구분하지 않는다.
pub fn random_part_leaks(random: &[u8], value: &[u8]) -> bool {
    if value.is_empty() {
        return false;
    }
    let w = value.len().min(LEAK_WINDOW);
    value.windows(w).any(|win| {
        random.windows(w).any(|r| r.iter().zip(win).all(|(a, b)| a.eq_ignore_ascii_case(b)))
    })
}

/// 새 token 을 만든다. `is_taken` 은 같은 scope 안의 중복 확인용이다.
pub fn generate(
    label: &EntityLabel,
    value: &[u8],
    mut is_taken: impl FnMut(&str) -> bool,
) -> Result<Token, VaultError> {
    for _ in 0..MAX_ATTEMPTS {
        let r = random_part()?;
        if random_part_leaks(&r, value) {
            continue;
        }
        let mut s = String::with_capacity(label.as_str().len() + RANDOM_LEN + 8);
        s.push(OPEN);
        s.push_str(label.as_str());
        s.push('_');
        // ALPHABET 은 ASCII 이므로 각 바이트가 그대로 문자다.
        s.extend(r.iter().map(|b| char::from(*b)));
        s.push(CLOSE);
        if !is_taken(&s) {
            return Ok(Token(s));
        }
    }
    Err(VaultError::Internal)
}

/// 모양만 검사한다. 조회는 정확한 문자열 일치로만 한다(정규화·유사 일치 없음).
pub fn check_shape(s: &str) -> Result<(), VaultError> {
    let inner = s
        .strip_prefix(OPEN)
        .and_then(|x| x.strip_suffix(CLOSE))
        .ok_or(VaultError::MalformedToken)?;
    let (label, random) = inner.rsplit_once('_').ok_or(VaultError::MalformedToken)?;
    EntityLabel::parse(label).map_err(|_| VaultError::MalformedToken)?;
    if random.len() != RANDOM_LEN || !random.bytes().all(|b| ALPHABET.contains(&b)) {
        return Err(VaultError::MalformedToken);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    fn label(s: &str) -> EntityLabel {
        EntityLabel::parse(s).unwrap()
    }

    #[test]
    fn format_is_stable() {
        let t = generate(&label("PERSON"), "합성홍길동".as_bytes(), |_| false).unwrap();
        check_shape(t.as_str()).unwrap();
        assert!(t.as_str().starts_with("⟦PERSON_"));
        assert!(t.as_str().ends_with('⟧'));
        assert_eq!(t.as_str().chars().count(), 1 + 6 + 1 + RANDOM_LEN + 1);
    }

    #[test]
    fn modified_tokens_are_malformed() {
        let t = generate(&label("EMAIL"), b"a@example.invalid", |_| false).unwrap();
        let s = t.as_str();
        let lower = s.to_lowercase();
        let no_brackets = s.trim_start_matches(OPEN).trim_end_matches(CLOSE).to_owned();
        let ascii_brackets = format!("[{no_brackets}]");
        let extra = format!("{s} ");
        for bad in [lower.as_str(), no_brackets.as_str(), ascii_brackets.as_str(), extra.as_str(), "⟦EMAIL_⟧", "⟦_0123456789⟧"] {
            assert_eq!(check_shape(bad), Err(VaultError::MalformedToken), "{bad}");
        }
    }

    #[test]
    fn random_part_never_contains_value_window() {
        // 합성 ASCII 값으로 성질을 반복 확인한다. 거절 재추첨이 동작하는지 본다.
        let values: [&[u8]; 6] = [b"7", b"AB", b"K7Q", b"0123456789ABCDEFGHJK", b"user99@example.invalid", b"010-0000-0000"];
        for v in values {
            for _ in 0..2000 {
                let t = generate(&label("X"), v, |_| false).unwrap();
                let random = &t.as_str().as_bytes()[t.as_str().len() - 3 - RANDOM_LEN..t.as_str().len() - 3];
                assert!(!random_part_leaks(random, v));
            }
        }
    }

    #[test]
    fn leak_detector_detects() {
        assert!(random_part_leaks(b"XXABCDXXXX", b"zzabcdzz"));
        assert!(!random_part_leaks(b"XXABCXXXXX", b"zzabcdzz"));
        assert!(random_part_leaks(b"XX7XXXXXXX", b"7"));
    }

    #[test]
    fn no_duplicates_in_many_draws_and_taken_is_respected() {
        let mut seen = HashSet::new();
        for _ in 0..20000 {
            let t = generate(&label("P"), b"v", |s| seen.contains(s)).unwrap();
            assert!(seen.insert(t.0));
        }
        // 모두 사용 중이면 무한 반복 없이 Internal 로 실패한다.
        assert_eq!(generate(&label("P"), b"v", |_| true), Err(VaultError::Internal));
    }
}
