//! MAP codec micro-benchmarks: BER encode/decode of the core SMS operations.
//!
//! Run with `cargo bench`. Numbers feed the README "Performance" table.
//!
//! Every fixture is built from the public API with **synthetic** identifiers —
//! fictional `+1 555 01xx` MSISDNs and the reserved test PLMN `001/01` for the
//! IMSI — so the benches measure exactly the work this crate does (rasn BER
//! pack/unpack of the typed operation structs) with no I/O in the path.

use criterion::{criterion_group, criterion_main, BatchSize, Criterion, Throughput};

use gsm_map::operations::mo_forward_sm::MoForwardSmArg;
use gsm_map::operations::mt_forward_sm::MtForwardSmArg;
use gsm_map::operations::sri_sm::{RoutingInfoForSmArg, RoutingInfoForSmRes};
use gsm_map::types::{LocationInfoWithLmsi, SmRpDa, SmRpOa};

// Synthetic TBCD addresses (byte 0 = TON/NPI, then swapped-nibble digits).
// MSISDN for the fictional +1 555 0100 999.
fn sample_msisdn() -> Vec<u8> {
    vec![0x91, 0x51, 0x55, 0x10, 0x00, 0x99, 0xF9]
}

// Service-centre AddressString for the fictional +1 555 0100.
fn sample_sc_addr() -> Vec<u8> {
    vec![0x91, 0x51, 0x55, 0x10, 0x00]
}

// Test-PLMN IMSI (001/01 + synthetic MSIN).
fn sample_imsi() -> Vec<u8> {
    vec![0x00, 0x10, 0x10, 0x00, 0x00, 0x00, 0x00, 0x01]
}

// A representative 30-octet SMS TPDU body carried in SM-RP-UI. Length is what
// matters for the copy path, not the contents.
fn sample_tpdu() -> Vec<u8> {
    let mut ui = vec![
        0x04, 0x0B, 0x91, 0x51, 0x55, 0x10, 0x00, 0x99, 0xF9, 0x00, 0x00,
    ];
    ui.extend_from_slice(&[0xAB; 19]);
    ui
}

fn sri_sm_arg() -> RoutingInfoForSmArg {
    RoutingInfoForSmArg::new(sample_msisdn().into(), true, sample_sc_addr().into())
}

fn sri_sm_res() -> RoutingInfoForSmRes {
    RoutingInfoForSmRes::new(
        sample_imsi().into(),
        LocationInfoWithLmsi {
            lmsi: Some(vec![0x00, 0x00, 0x00, 0x01].into()),
            ..LocationInfoWithLmsi::new(vec![0x91, 0x51, 0x55, 0x10, 0x12, 0x34, 0x56].into())
        },
    )
}

fn mo_forward_sm() -> MoForwardSmArg {
    MoForwardSmArg::new(
        SmRpDa::ServiceCentreAddressDa(sample_sc_addr().into()),
        SmRpOa::MsIsdn(sample_msisdn().into()),
        sample_tpdu().into(),
    )
}

fn mt_forward_sm() -> MtForwardSmArg {
    MtForwardSmArg {
        more_messages_to_send: Some(()),
        ..MtForwardSmArg::new(
            SmRpDa::Imsi(sample_imsi().into()),
            SmRpOa::ServiceCentreAddressOa(sample_sc_addr().into()),
            sample_tpdu().into(),
        )
    }
}

fn bench_codec(c: &mut Criterion) {
    let mut g = c.benchmark_group("codec");
    g.throughput(Throughput::Elements(1));

    // sendRoutingInfoForSM-Arg
    let arg = sri_sm_arg();
    let arg_bytes = rasn::ber::encode(&arg).expect("encode sri-sm arg");
    g.bench_function("sri_sm_arg/encode", |b| {
        b.iter_batched(
            || arg.clone(),
            |v| rasn::ber::encode(&v).unwrap(),
            BatchSize::SmallInput,
        )
    });
    g.bench_function("sri_sm_arg/decode", |b| {
        b.iter(|| rasn::ber::decode::<RoutingInfoForSmArg>(&arg_bytes).unwrap())
    });

    // sendRoutingInfoForSM-Res
    let res = sri_sm_res();
    let res_bytes = rasn::ber::encode(&res).expect("encode sri-sm res");
    g.bench_function("sri_sm_res/encode", |b| {
        b.iter_batched(
            || res.clone(),
            |v| rasn::ber::encode(&v).unwrap(),
            BatchSize::SmallInput,
        )
    });
    g.bench_function("sri_sm_res/decode", |b| {
        b.iter(|| rasn::ber::decode::<RoutingInfoForSmRes>(&res_bytes).unwrap())
    });

    // mo-ForwardSM-Arg
    let mo = mo_forward_sm();
    let mo_bytes = rasn::ber::encode(&mo).expect("encode mo-forward-sm");
    g.bench_function("mo_forward_sm/encode", |b| {
        b.iter_batched(
            || mo.clone(),
            |v| rasn::ber::encode(&v).unwrap(),
            BatchSize::SmallInput,
        )
    });
    g.bench_function("mo_forward_sm/decode", |b| {
        b.iter(|| rasn::ber::decode::<MoForwardSmArg>(&mo_bytes).unwrap())
    });

    // mt-ForwardSM-Arg
    let mt = mt_forward_sm();
    let mt_bytes = rasn::ber::encode(&mt).expect("encode mt-forward-sm");
    g.bench_function("mt_forward_sm/encode", |b| {
        b.iter_batched(
            || mt.clone(),
            |v| rasn::ber::encode(&v).unwrap(),
            BatchSize::SmallInput,
        )
    });
    g.bench_function("mt_forward_sm/decode", |b| {
        b.iter(|| rasn::ber::decode::<MtForwardSmArg>(&mt_bytes).unwrap())
    });

    g.finish();
}

criterion_group!(benches, bench_codec);
criterion_main!(benches);
