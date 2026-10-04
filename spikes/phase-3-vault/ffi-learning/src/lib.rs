//! 학습용 in-process Vault 흉내. C++ 와 같은 주소 공간에서 Rust 가 원문을 들고 있을 때의 위험을 보여 주기 위한 것이다.
//! FFI 경계는 본질적으로 raw pointer 를 다루므로 이 crate 에서만 unsafe 를 허용한다. 운영 경로에 쓰지 않는다.
#![allow(unsafe_code)]

use std::collections::HashMap;
use zeroize::Zeroizing;

pub struct FfiStore {
    next: u64,
    values: HashMap<u64, Zeroizing<Vec<u8>>>,
}

#[unsafe(no_mangle)]
pub extern "C" fn pa_ffi_new() -> *mut FfiStore {
    Box::into_raw(Box::new(FfiStore { next: 1, values: HashMap::new() }))
}

/// # Safety
/// `store` 는 `pa_ffi_new` 결과이고 아직 해제되지 않아야 한다. `ptr..ptr+len` 은 읽기 가능해야 한다.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pa_ffi_put(store: *mut FfiStore, ptr: *const u8, len: usize) -> u64 {
    if store.is_null() || ptr.is_null() {
        return 0;
    }
    // SAFETY: 호출자 계약. Rust 는 C++ 가 넘긴 포인터가 유효한지 검증할 수 없다(같은 주소 공간의 한계).
    let (s, bytes) = unsafe { (&mut *store, std::slice::from_raw_parts(ptr, len)) };
    let id = s.next;
    s.next += 1;
    s.values.insert(id, Zeroizing::new(bytes.to_vec()));
    id
}

/// 값을 out 에 복사하고 길이를 돌려준다. 없거나 버퍼가 작으면 -1.
///
/// # Safety
/// `store` 는 유효해야 하고 `out..out+cap` 은 쓰기 가능해야 한다.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pa_ffi_get(store: *const FfiStore, id: u64, out: *mut u8, cap: usize) -> isize {
    if store.is_null() || out.is_null() {
        return -1;
    }
    // SAFETY: 호출자 계약.
    let s = unsafe { &*store };
    match s.values.get(&id) {
        Some(v) if v.len() <= cap => {
            // SAFETY: out 은 cap 바이트 이상 쓰기 가능(호출자 계약), v.len() <= cap.
            unsafe { std::ptr::copy_nonoverlapping(v.as_ptr(), out, v.len()) };
            v.len() as isize
        }
        _ => -1,
    }
}

/// # Safety
/// `store` 는 `pa_ffi_new` 결과이고 한 번만 해제해야 한다. 이후 사용은 use-after-free 다.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pa_ffi_free(store: *mut FfiStore) {
    if !store.is_null() {
        // SAFETY: 호출자 계약. drop 시 모든 값이 zeroize 된다.
        drop(unsafe { Box::from_raw(store) });
    }
}
