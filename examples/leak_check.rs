//! Memory-leak check.
//!
//! A counting global allocator tracks **live bytes** (allocated − freed) — RSS is
//! too noisy (the OS/allocator retains freed pages), but live bytes are exact, so
//! a real leak shows up as monotonic growth. Two phases:
//!
//!   1. **codec** — BER encode + decode the core SMS operations (SRI-SM arg/res,
//!      MO/MT-ForwardSM) for many cycles.
//!   2. **full stack** — assemble and tear down a complete MAP ▸ TCAP ▸ SCCP UDT
//!      message end to end, over and over (the integration path).
//!
//! Each phase asserts live bytes return to a flat baseline. Exits non-zero on a
//! leak. Driven by `scripts/mem_leak_test.sh`.
//!
//! All identifiers are synthetic: fictional `+1 555 01xx` addresses and the
//! reserved test PLMN `001/01` IMSI.
//!
//! Run: `cargo run --release --example leak_check`

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicI64, Ordering};

use gsm_map::operations::mo_forward_sm::MoForwardSmArg;
use gsm_map::operations::mt_forward_sm::MtForwardSmArg;
use gsm_map::operations::sri_sm::{RoutingInfoForSmArg, RoutingInfoForSmRes};
use gsm_map::types::{op_codes, LocationInfoWithLmsi, SmRpDa, SmRpOa};

use sccp::{GlobalTitle, SccpAddress, SubsystemNumber, UnitData};
use tcap::{Begin, Component, Invoke, OperationCode, TcapMessage};

// ── Counting allocator ──────────────────────────────────────────────────────
static LIVE: AtomicI64 = AtomicI64::new(0);

struct Counting;
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        let p = System.alloc(l);
        if !p.is_null() {
            LIVE.fetch_add(l.size() as i64, Ordering::Relaxed);
        }
        p
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        System.dealloc(p, l);
        LIVE.fetch_sub(l.size() as i64, Ordering::Relaxed);
    }
    unsafe fn alloc_zeroed(&self, l: Layout) -> *mut u8 {
        let p = System.alloc_zeroed(l);
        if !p.is_null() {
            LIVE.fetch_add(l.size() as i64, Ordering::Relaxed);
        }
        p
    }
    unsafe fn realloc(&self, ptr: *mut u8, l: Layout, new_size: usize) -> *mut u8 {
        let p = System.realloc(ptr, l, new_size);
        if !p.is_null() {
            LIVE.fetch_add(new_size as i64 - l.size() as i64, Ordering::Relaxed);
        }
        p
    }
}

#[global_allocator]
static ALLOC: Counting = Counting;

fn live() -> i64 {
    LIVE.load(Ordering::Relaxed)
}

// ── Fixtures ────────────────────────────────────────────────────────────────
fn sample_msisdn() -> Vec<u8> {
    vec![0x91, 0x51, 0x55, 0x10, 0x00, 0x99, 0xF9]
}
fn sample_sc_addr() -> Vec<u8> {
    vec![0x91, 0x51, 0x55, 0x10, 0x00]
}
fn sample_imsi() -> Vec<u8> {
    vec![0x00, 0x10, 0x10, 0x00, 0x00, 0x00, 0x00, 0x01]
}
fn sample_tpdu() -> Vec<u8> {
    let mut ui = vec![
        0x04, 0x0B, 0x91, 0x51, 0x55, 0x10, 0x00, 0x99, 0xF9, 0x00, 0x00,
    ];
    ui.extend_from_slice(&[0xAB; 19]);
    ui
}

// ── Phase 1: codec workload ─────────────────────────────────────────────────
fn codec_cycle(iters: usize) {
    let sri_arg = RoutingInfoForSmArg::new(sample_msisdn().into(), true, sample_sc_addr().into());
    let sri_res = RoutingInfoForSmRes::new(
        sample_imsi().into(),
        LocationInfoWithLmsi {
            lmsi: Some(vec![0x00, 0x00, 0x00, 0x01].into()),
            ..LocationInfoWithLmsi::new(vec![0x91, 0x51, 0x55, 0x10, 0x12, 0x34, 0x56].into())
        },
    );
    let mo = MoForwardSmArg::new(
        SmRpDa::ServiceCentreAddressDa(sample_sc_addr().into()),
        SmRpOa::MsIsdn(sample_msisdn().into()),
        sample_tpdu().into(),
    );
    let mt = MtForwardSmArg {
        more_messages_to_send: Some(()),
        ..MtForwardSmArg::new(
            SmRpDa::Imsi(sample_imsi().into()),
            SmRpOa::ServiceCentreAddressOa(sample_sc_addr().into()),
            sample_tpdu().into(),
        )
    };

    for _ in 0..iters {
        let a = gsm_map::encode(&sri_arg).unwrap();
        std::hint::black_box(gsm_map::decode::<RoutingInfoForSmArg>(&a).unwrap());
        let r = gsm_map::encode(&sri_res).unwrap();
        std::hint::black_box(gsm_map::decode::<RoutingInfoForSmRes>(&r).unwrap());
        let o = gsm_map::encode(&mo).unwrap();
        std::hint::black_box(gsm_map::decode::<MoForwardSmArg>(&o).unwrap());
        let t = gsm_map::encode(&mt).unwrap();
        std::hint::black_box(gsm_map::decode::<MtForwardSmArg>(&t).unwrap());
    }
}

// ── Phase 2: full-stack churn (MAP → TCAP → SCCP and back) ───────────────────
fn called_hlr() -> SccpAddress {
    SccpAddress::with_gt(
        GlobalTitle::Gt0100 {
            translation_type: 0,
            numbering_plan: 1,
            encoding_scheme: 1,
            nature_of_address: 4,
            digits: "15550100123".to_string(),
        },
        Some(SubsystemNumber::Hlr),
    )
}
fn calling_gmsc() -> SccpAddress {
    SccpAddress::with_gt(
        GlobalTitle::Gt0100 {
            translation_type: 0,
            numbering_plan: 1,
            encoding_scheme: 1,
            nature_of_address: 4,
            digits: "15550100999".to_string(),
        },
        Some(SubsystemNumber::Msc),
    )
}

fn stack_cycle(iters: usize) {
    let arg = RoutingInfoForSmArg::new(sample_msisdn().into(), true, sample_sc_addr().into());
    for _ in 0..iters {
        // encode: MAP → TCAP → SCCP
        let param = gsm_map::encode(&arg).unwrap();
        let invoke = Invoke {
            invoke_id: 1,
            linked_id: None,
            operation_code: OperationCode::Local(op_codes::SEND_ROUTING_INFO_FOR_SM),
            parameter: Some(rasn::types::Any::new(param)),
        };
        let begin = Begin {
            otid: vec![0x00, 0x00, 0x00, 0x01].into(),
            dialogue_portion: None,
            components: Some(vec![Component::Invoke(invoke)]),
        };
        let tcap_bytes = tcap::encode(&TcapMessage::Begin(begin)).unwrap();
        let udt = UnitData::new(called_hlr(), calling_gmsc(), tcap_bytes);
        let wire = udt.encode().unwrap();

        // decode: SCCP → TCAP → MAP
        let udt = UnitData::decode(&wire).unwrap();
        let msg = tcap::decode(&udt.data).unwrap();
        if let TcapMessage::Begin(b) = msg {
            let comps = b.components.unwrap();
            if let Component::Invoke(inv) = &comps[0] {
                let p = inv.parameter.as_ref().unwrap().as_bytes();
                std::hint::black_box(gsm_map::decode::<RoutingInfoForSmArg>(p).unwrap());
            }
        }
    }
}

fn report(phase: &str, base: i64) -> i64 {
    let growth = live() - base;
    println!("  {phase}: live = {} bytes (Δ {:+})", live(), growth);
    growth
}

fn main() {
    const ITERS: usize = 100_000;
    const CYCLES: usize = 10;
    const BUDGET: i64 = 64 * 1024;

    // Phase 1: codec.
    println!("[codec] {CYCLES} x {ITERS} BER encode+decode round-trips (SRI-SM arg/res + MO/MT-ForwardSM)");
    codec_cycle(ITERS); // warm up
    let codec_base = live();
    for c in 1..=CYCLES {
        codec_cycle(ITERS);
        report(&format!("cycle {c:>2}/{CYCLES}"), codec_base);
    }
    let codec_growth = live() - codec_base;

    // Phase 2: full stack.
    println!("\n[full stack] {CYCLES} x {ITERS} MAP → TCAP → SCCP encode + decode round-trips");
    stack_cycle(ITERS); // warm up
    let stack_base = live();
    for c in 1..=CYCLES {
        stack_cycle(ITERS);
        report(&format!("cycle {c:>2}/{CYCLES}"), stack_base);
    }
    let stack_growth = live() - stack_base;

    // Verdict.
    println!();
    let mut ok = true;
    if codec_growth > BUDGET {
        eprintln!("FAIL: codec live bytes grew {codec_growth} (> {BUDGET})");
        ok = false;
    }
    if stack_growth > BUDGET {
        eprintln!("FAIL: full-stack live bytes grew {stack_growth} (> {BUDGET})");
        ok = false;
    }
    if !ok {
        std::process::exit(1);
    }
    println!("PASS: codec Δ {codec_growth} ≤ {BUDGET}; full-stack Δ {stack_growth} ≤ {BUDGET}");
}
