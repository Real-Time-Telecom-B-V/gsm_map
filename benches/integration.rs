//! Full-stack SS7 integration benchmark — MAP ▸ TCAP ▸ SCCP, both directions.
//!
//! This is the "spam a lot of SRI-SM / MO-ForwardSM through the whole stack"
//! benchmark. Each iteration assembles (or tears down) a *complete* connectionless
//! SS7 message exactly as it would ride the wire:
//!
//! ```text
//!   MAP operation arg        (gsm_map — this crate: BER-encode the typed struct)
//!            │
//!   TCAP Invoke in a Begin   (tcap    — Invoke{op, parameter} → Begin{otid, …})
//!            │
//!   SCCP UnitData (UDT)      (sccp    — called/calling GT+SSN, TCAP as user data)
//!            ▼
//!         wire bytes
//! ```
//!
//! * **encode** measures MAP-arg → TCAP → SCCP → `Vec<u8>` (what a GMSC/SMSC emits).
//! * **decode** measures `&[u8]` → SCCP → TCAP → MAP-arg (what the peer parses).
//!
//! `Throughput::Elements(1)` makes criterion report **messages/sec** — the
//! full-stack rate. All addresses/identifiers are synthetic: fictional
//! `+1 555 01xx` global titles and the reserved test PLMN `001/01` IMSI.

use criterion::{criterion_group, criterion_main, BatchSize, Criterion, Throughput};

use gsm_map::operations::mo_forward_sm::MoForwardSmArg;
use gsm_map::operations::sri_sm::RoutingInfoForSmArg;
use gsm_map::types::{op_codes, SmRpDa, SmRpOa};

use sccp::{GlobalTitle, SccpAddress, SubsystemNumber, UnitData};
use tcap::{Begin, Component, Invoke, OperationCode, TcapMessage};

// ── Synthetic MAP fixtures ──────────────────────────────────────────────────

// MSISDN for the fictional +1 555 0100 999 (TBCD: byte 0 = TON/NPI, swapped nibbles).
fn sample_msisdn() -> Vec<u8> {
    vec![0x91, 0x51, 0x55, 0x10, 0x00, 0x99, 0xF9]
}

fn sample_sc_addr() -> Vec<u8> {
    vec![0x91, 0x51, 0x55, 0x10, 0x00]
}

fn sri_sm_arg() -> RoutingInfoForSmArg {
    RoutingInfoForSmArg::new(sample_msisdn().into(), true, sample_sc_addr().into())
}

fn mo_forward_sm_arg() -> MoForwardSmArg {
    let mut ui = vec![
        0x04, 0x0B, 0x91, 0x51, 0x55, 0x10, 0x00, 0x99, 0xF9, 0x00, 0x00,
    ];
    ui.extend_from_slice(&[0xAB; 19]);
    MoForwardSmArg::new(
        SmRpDa::ServiceCentreAddressDa(sample_sc_addr().into()),
        SmRpOa::MsIsdn(sample_msisdn().into()),
        ui.into(),
    )
}

// ── SCCP addressing (synthetic global titles) ───────────────────────────────

fn called_hlr() -> SccpAddress {
    let gt = GlobalTitle::Gt0100 {
        translation_type: 0,
        numbering_plan: 1,  // E.164
        encoding_scheme: 1, // BCD, odd number of digits
        nature_of_address: 4,
        digits: "15550100123".to_string(), // fictional +1 555 0100 123
    };
    SccpAddress::with_gt(gt, Some(SubsystemNumber::Hlr))
}

fn calling_gmsc() -> SccpAddress {
    let gt = GlobalTitle::Gt0100 {
        translation_type: 0,
        numbering_plan: 1,
        encoding_scheme: 1,
        nature_of_address: 4,
        digits: "15550100999".to_string(), // fictional +1 555 0100 999
    };
    SccpAddress::with_gt(gt, Some(SubsystemNumber::Msc))
}

// ── One full end-to-end encode: MAP arg → TCAP Begin/Invoke → SCCP UDT ───────

/// Encode a MAP operation argument into a full SCCP UDT wire buffer, going through
/// a TCAP Begin carrying a single Invoke. `map_param` is the already-BER-encoded
/// MAP argument (the Invoke parameter).
fn build_stack(op_code: i64, map_param: Vec<u8>) -> Vec<u8> {
    // TCAP: an Invoke component wrapping the MAP argument, inside a Begin.
    let invoke = Invoke {
        invoke_id: 1,
        linked_id: None,
        operation_code: OperationCode::Local(op_code),
        parameter: Some(rasn::types::Any::new(map_param)),
    };
    let begin = Begin {
        otid: vec![0x00, 0x00, 0x00, 0x01].into(),
        dialogue_portion: None,
        components: Some(vec![Component::Invoke(invoke)]),
    };
    let tcap_bytes = tcap::encode(&TcapMessage::Begin(begin)).expect("tcap encode");

    // SCCP: a UDT carrying the TCAP message as user data.
    let udt = UnitData::new(called_hlr(), calling_gmsc(), tcap_bytes);
    udt.encode().expect("sccp encode")
}

/// Decode a full SCCP UDT wire buffer back down to the MAP argument bytes,
/// unwrapping SCCP → TCAP → the Invoke parameter.
fn parse_stack(wire: &[u8]) -> Vec<u8> {
    let udt = UnitData::decode(wire).expect("sccp decode");
    let msg = tcap::decode(&udt.data).expect("tcap decode");
    let TcapMessage::Begin(begin) = msg else {
        panic!("expected Begin");
    };
    let components = begin.components.expect("components");
    let Component::Invoke(invoke) = &components[0] else {
        panic!("expected Invoke");
    };
    invoke
        .parameter
        .as_ref()
        .expect("parameter")
        .as_bytes()
        .to_vec()
}

fn bench_integration(c: &mut Criterion) {
    let mut g = c.benchmark_group("integration");
    // Report messages/sec — the full-stack throughput.
    g.throughput(Throughput::Elements(1));

    // ── SRI-SM through the whole stack ──
    let sri_arg = sri_sm_arg();
    let sri_param = rasn::ber::encode(&sri_arg).expect("encode sri arg");
    let sri_wire = build_stack(op_codes::SEND_ROUTING_INFO_FOR_SM, sri_param.clone());

    g.bench_function("sri_sm/encode_full_stack", |b| {
        b.iter_batched(
            || sri_arg.clone(),
            |arg| {
                let param = rasn::ber::encode(&arg).unwrap();
                build_stack(op_codes::SEND_ROUTING_INFO_FOR_SM, param)
            },
            BatchSize::SmallInput,
        )
    });

    g.bench_function("sri_sm/decode_full_stack", |b| {
        b.iter(|| {
            let param = parse_stack(&sri_wire);
            rasn::ber::decode::<RoutingInfoForSmArg>(&param).unwrap()
        })
    });

    // ── MO-ForwardSM through the whole stack ──
    let mo_arg = mo_forward_sm_arg();
    let mo_param = rasn::ber::encode(&mo_arg).expect("encode mo arg");
    let mo_wire = build_stack(op_codes::MO_FORWARD_SM, mo_param.clone());

    g.bench_function("mo_forward_sm/encode_full_stack", |b| {
        b.iter_batched(
            || mo_arg.clone(),
            |arg| {
                let param = rasn::ber::encode(&arg).unwrap();
                build_stack(op_codes::MO_FORWARD_SM, param)
            },
            BatchSize::SmallInput,
        )
    });

    g.bench_function("mo_forward_sm/decode_full_stack", |b| {
        b.iter(|| {
            let param = parse_stack(&mo_wire);
            rasn::ber::decode::<MoForwardSmArg>(&param).unwrap()
        })
    });

    g.finish();
}

criterion_group!(benches, bench_integration);
criterion_main!(benches);
