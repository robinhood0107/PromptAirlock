//! 해제되는 메모리를 0 으로 지우는 전역 할당기(ADR 0019). Vault 에서 unsafe 를 허용하는 두 모듈 가운데 하나다.
//!
//! 통신 라이브러리 내부 버퍼(Windows Named Pipe 와 mio 버퍼), 컬렉션 재할당으로 버려진 옛 영역, 디코더 임시
//! 버퍼처럼 Vault 코드가 직접 지울 수 없는 사본도 해제될 때 지워진다. 재할당은 GlobalAlloc 기본 구현
//! (새로 할당, 복사, 옛 영역 dealloc)을 그대로 쓰므로 옛 영역도 같은 경로로 지워진다.
//! 지우지 못하는 것: 커널 버퍼, 레지스터, 스택, 해제되지 않고 남은 메모리, 강제 종료 시점의 메모리.
#![allow(unsafe_code)]

use std::alloc::{GlobalAlloc, Layout, System};

use zeroize::Zeroize;

/// 안쪽 할당기(기본 System)에 위임하고, 해제 직전에 블록 전체를 0 으로 덮는다.
pub struct WipingAllocator<A = System>(pub A);

// SAFETY: alloc 계열은 안쪽 할당기에 그대로 위임한다. dealloc 은 호출자가 이 할당기로 layout 크기만큼 할당하고
// 아직 해제하지 않은 블록을 넘긴다는 GlobalAlloc 계약에 기대어, 그 블록을 쓰기 가능한 슬라이스로 보고 지운 뒤 위임한다.
unsafe impl<A: GlobalAlloc> GlobalAlloc for WipingAllocator<A> {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: 계약 그대로 위임한다.
        unsafe { self.0.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: 계약 그대로 위임한다.
        unsafe { self.0.alloc_zeroed(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if layout.size() > 0 {
            // SAFETY: ptr 은 이 할당기가 layout 으로 할당했고 아직 유효한 블록이다(GlobalAlloc 계약).
            // zeroize 는 volatile 쓰기라 해제 직전의 쓰기가 최적화로 사라지지 않는다.
            unsafe { std::slice::from_raw_parts_mut(ptr, layout.size()) }.zeroize();
        }
        // SAFETY: 계약 그대로 위임한다.
        unsafe { self.0.dealloc(ptr, layout) }
    }
}
