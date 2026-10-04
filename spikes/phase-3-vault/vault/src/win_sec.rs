//! Windows 보안 설명자 처리. Vault 에서 unsafe 를 허용하는 유일한 모듈이다.
//!
//! 하는 일
//! - 현재 프로세스 토큰의 사용자 SID 문자열 얻기
//! - SDDL 로 보안 설명자를 만들어 named pipe 생성에 넘기기
//! - 핸들의 소유자·DACL 을 SDDL 문자열로 읽기(검증·보고용)
//!
//! 모든 OS 할당 메모리는 RAII guard 로 LocalFree, 핸들은 CloseHandle 한다.
#![allow(unsafe_code)]

use std::ffi::c_void;
use std::io;
use std::os::windows::io::{AsRawHandle, RawHandle};
use std::ptr;

use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
use windows_sys::Win32::Foundation::{CloseHandle, ERROR_SUCCESS, HANDLE, LocalFree};
use windows_sys::Win32::Security::Authorization::{
    ConvertSecurityDescriptorToStringSecurityDescriptorW, ConvertSidToStringSidW,
    ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo, SDDL_REVISION_1, SE_KERNEL_OBJECT,
};
use windows_sys::Win32::Security::{
    DACL_SECURITY_INFORMATION, GetTokenInformation, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
    SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER, TokenUser,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

/// LocalAlloc 계열로 OS 가 할당한 포인터를 LocalFree 로 돌려준다.
struct LocalBox(*mut c_void);

impl Drop for LocalBox {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: self.0 은 OS API(Convert*)가 LocalAlloc 으로 할당해 돌려준 포인터이고, 한 번만 해제한다.
            unsafe { LocalFree(self.0) };
        }
    }
}

struct OwnedHandle(HANDLE);

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        // SAFETY: OpenProcessToken 이 성공해 돌려준 유효 핸들이며 한 번만 닫는다.
        unsafe { CloseHandle(self.0) };
    }
}

/// NUL 종료 UTF-16 문자열을 String 으로 복사한다.
///
/// # Safety
/// `p` 는 NUL 로 끝나는 유효한 UTF-16 버퍼를 가리켜야 한다.
unsafe fn wide_to_string(p: *const u16) -> String {
    let mut len = 0usize;
    // SAFETY: 호출자가 NUL 종료를 보장한다. NUL 을 만날 때까지만 읽는다.
    while unsafe { *p.add(len) } != 0 {
        len += 1;
    }
    // SAFETY: [p, p+len) 은 위에서 읽은 유효 범위다.
    String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(p, len) })
}

fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// 현재 프로세스 토큰의 사용자 SID 를 `S-1-5-21-...` 문자열로 돌려준다.
pub fn current_user_sid() -> io::Result<String> {
    let mut token: HANDLE = ptr::null_mut();
    // SAFETY: GetCurrentProcess 는 의사 핸들을 돌려주며 닫을 필요가 없다. token 은 출력 매개변수다.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let token = OwnedHandle(token);
    let mut needed = 0u32;
    // SAFETY: 크기 질의 호출. 버퍼 NULL, 길이 0 이면 필요한 크기만 needed 에 쓴다(실패 반환이 정상).
    unsafe { GetTokenInformation(token.0, TokenUser, ptr::null_mut(), 0, &mut needed) };
    if needed == 0 {
        return Err(io::Error::last_os_error());
    }
    // TOKEN_USER 는 포인터를 담으므로 8바이트 정렬 버퍼를 쓴다.
    let mut buf = vec![0u64; (needed as usize).div_ceil(8)];
    // SAFETY: buf 는 needed 바이트 이상이고 정렬이 맞다.
    if unsafe { GetTokenInformation(token.0, TokenUser, buf.as_mut_ptr().cast(), needed, &mut needed) } == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: GetTokenInformation(TokenUser) 성공 시 버퍼 앞부분은 TOKEN_USER 이며, Sid 는 같은 버퍼 안을 가리킨다.
    let sid = unsafe { (*buf.as_ptr().cast::<TOKEN_USER>()).User.Sid };
    let mut wide: *mut u16 = ptr::null_mut();
    // SAFETY: sid 는 buf 가 살아 있는 동안 유효하다. 결과 문자열은 LocalFree 로 해제한다.
    if unsafe { ConvertSidToStringSidW(sid, &mut wide) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let _free = LocalBox(wide.cast());
    // SAFETY: ConvertSidToStringSidW 가 NUL 종료 문자열을 돌려준다.
    Ok(unsafe { wide_to_string(wide) })
}

/// 현재 사용자에게만 모든 권한을 주는 보호된 DACL. 상속 ACE 를 받지 않는다(P).
pub fn current_user_pipe_sddl() -> io::Result<String> {
    Ok(format!("D:P(A;;GA;;;{})", current_user_sid()?))
}

pub fn create_pipe_with_sddl(opts: &ServerOptions, name: &str, sddl: &str) -> io::Result<NamedPipeServer> {
    let wide = to_wide(sddl);
    let mut sd: PSECURITY_DESCRIPTOR = ptr::null_mut();
    // SAFETY: wide 는 NUL 종료 UTF-16 이다. sd 는 출력 매개변수이며 LocalFree 로 해제한다.
    let ok = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(wide.as_ptr(), SDDL_REVISION_1, &mut sd, ptr::null_mut())
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    let _free = LocalBox(sd);
    let mut sa = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: sd,
        bInheritHandle: 0,
    };
    // SAFETY: sa 는 유효한 SECURITY_ATTRIBUTES 이며 sd 는 이 호출이 끝날 때까지 살아 있다.
    // CreateNamedPipeW 는 보안 설명자를 커널 객체로 복사하므로 호출 뒤 해제해도 된다.
    unsafe { opts.create_with_security_attributes_raw(name, (&mut sa as *mut SECURITY_ATTRIBUTES).cast()) }
}

pub fn create_pipe_current_user(opts: &ServerOptions, name: &str) -> io::Result<NamedPipeServer> {
    create_pipe_with_sddl(opts, name, &current_user_pipe_sddl()?)
}

/// 커널 객체 핸들의 소유자와 DACL 을 SDDL 로 읽는다.
pub fn handle_security_sddl(h: RawHandle) -> io::Result<String> {
    let mut sd: PSECURITY_DESCRIPTOR = ptr::null_mut();
    let info = DACL_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION;
    // SAFETY: h 는 호출자가 빌려준 유효 핸들이다. 나머지 출력 포인터는 NULL 허용이며 sd 는 LocalFree 로 해제한다.
    let rc = unsafe {
        GetSecurityInfo(
            h,
            SE_KERNEL_OBJECT,
            info,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            &mut sd,
        )
    };
    if rc != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(rc as i32));
    }
    let _free_sd = LocalBox(sd);
    let mut wide: *mut u16 = ptr::null_mut();
    // SAFETY: sd 는 GetSecurityInfo 가 돌려준 유효 보안 설명자다. 결과 문자열은 LocalFree 로 해제한다.
    let ok = unsafe {
        ConvertSecurityDescriptorToStringSecurityDescriptorW(sd, SDDL_REVISION_1, info, &mut wide, ptr::null_mut())
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    let _free_str = LocalBox(wide.cast());
    // SAFETY: 변환 함수가 NUL 종료 문자열을 돌려준다.
    Ok(unsafe { wide_to_string(wide) })
}

pub fn pipe_security_sddl(p: &NamedPipeServer) -> io::Result<String> {
    handle_security_sddl(p.as_raw_handle())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sid_looks_valid() {
        let sid = current_user_sid().unwrap();
        assert!(sid.starts_with("S-1-5-"), "{sid}");
    }

    #[test]
    fn wide_roundtrip() {
        let w = to_wide("D:P(A;;GA;;;SY)");
        // SAFETY: to_wide 는 NUL 종료 버퍼를 만든다.
        assert_eq!(unsafe { wide_to_string(w.as_ptr()) }, "D:P(A;;GA;;;SY)");
    }
}
