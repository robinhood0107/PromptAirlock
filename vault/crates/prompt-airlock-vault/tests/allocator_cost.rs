//! 지우는 할당기 비용 측정(Phase 6 측정). 기본 시험에서 빼고 직접 실행한다.
//!   cargo test --release --locked --test allocator_cost -- --ignored --nocapture
//! 같은 크기 블록을 할당하고 내용을 채운 뒤 해제하는 시간을 System 과 WipingAllocator<System> 으로 비교한다.
#![allow(unsafe_code)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::hint::black_box;
use std::time::Instant;

use prompt_airlock_vault::alloc::WipingAllocator;

fn ns_per_cycle<A: GlobalAlloc>(a: &A, size: usize, rounds: usize) -> f64 {
    let layout = Layout::from_size_align(size, 8).unwrap();
    let start = Instant::now();
    for i in 0..rounds {
        // SAFETY: 0 이 아닌 크기의 layout 으로 할당하고, 같은 layout 으로 한 번만 해제한다.
        unsafe {
            let p = a.alloc(layout);
            assert!(!p.is_null());
            std::ptr::write_bytes(p, i as u8, size);
            black_box(p);
            a.dealloc(p, layout);
        }
    }
    start.elapsed().as_nanos() as f64 / rounds as f64
}

#[test]
#[ignore = "측정 전용"]
fn wiping_allocator_cost() {
    let wiping = WipingAllocator(System);
    for (size, rounds) in [(64usize, 200_000usize), (4096, 100_000), (65536, 20_000)] {
        // 한 번 데운 뒤 잰다.
        ns_per_cycle(&System, size, rounds / 10);
        ns_per_cycle(&wiping, size, rounds / 10);
        let plain = ns_per_cycle(&System, size, rounds);
        let wiped = ns_per_cycle(&wiping, size, rounds);
        println!(
            "size {size:>6} B: system {plain:>9.1} ns, wiping {wiped:>9.1} ns, extra {:>9.1} ns ({:>5.2}x)",
            wiped - plain,
            wiped / plain
        );
    }
}
