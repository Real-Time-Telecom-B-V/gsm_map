//! MAP codec micro-benchmarks: BER encode/decode of the core SMS operations.
//!
//! Run with `cargo bench`. Numbers feed the README "Performance" table.
//!
//! Every fixture is built from the public API with **synthetic** identifiers —
//! fictional `+1 555 01xx` MSISDNs and the reserved test PLMN `001/01` for the
//! IMSI — so the benches measure exactly the work this crate does (BER
//! pack/unpack of the typed operation structs) with no I/O in the path.
//!
//! Decoding goes through `gsm_map::decode`, the crate's strict decoder. The
//! `decode_cost` group puts it next to `rasn::ber::decode` on the same octets,
//! for the answer with every serving node and for the largest argument in
//! common use, insertSubscriberData with a subscriber profile.

use criterion::{criterion_group, criterion_main, BatchSize, Criterion, Throughput};

use gsm_map::operations::mo_forward_sm::MoForwardSmArg;
use gsm_map::operations::mt_forward_sm::MtForwardSmArg;
use gsm_map::operations::sri_sm::{IpSmGwGuidance, RoutingInfoForSmArg, RoutingInfoForSmRes};
use gsm_map::operations::subscriber_data::{
    InsertSubscriberDataArg, NetworkAccessMode, OdbData, SubscriberStatus,
};
use gsm_map::types::{
    AdditionalNumber, ExtensionContainer, LocationInfoWithLmsi, NetworkNodeDiameterAddress, Opaque,
    SmRpDa, SmRpOa,
};

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
    let arg_bytes = gsm_map::encode(&arg).expect("encode sri-sm arg");
    g.bench_function("sri_sm_arg/encode", |b| {
        b.iter_batched(
            || arg.clone(),
            |v| gsm_map::encode(&v).unwrap(),
            BatchSize::SmallInput,
        )
    });
    g.bench_function("sri_sm_arg/decode", |b| {
        b.iter(|| gsm_map::decode::<RoutingInfoForSmArg>(&arg_bytes).unwrap())
    });

    // sendRoutingInfoForSM-Res
    let res = sri_sm_res();
    let res_bytes = gsm_map::encode(&res).expect("encode sri-sm res");
    g.bench_function("sri_sm_res/encode", |b| {
        b.iter_batched(
            || res.clone(),
            |v| gsm_map::encode(&v).unwrap(),
            BatchSize::SmallInput,
        )
    });
    g.bench_function("sri_sm_res/decode", |b| {
        b.iter(|| gsm_map::decode::<RoutingInfoForSmRes>(&res_bytes).unwrap())
    });

    // mo-ForwardSM-Arg
    let mo = mo_forward_sm();
    let mo_bytes = gsm_map::encode(&mo).expect("encode mo-forward-sm");
    g.bench_function("mo_forward_sm/encode", |b| {
        b.iter_batched(
            || mo.clone(),
            |v| gsm_map::encode(&v).unwrap(),
            BatchSize::SmallInput,
        )
    });
    g.bench_function("mo_forward_sm/decode", |b| {
        b.iter(|| gsm_map::decode::<MoForwardSmArg>(&mo_bytes).unwrap())
    });

    // mt-ForwardSM-Arg
    let mt = mt_forward_sm();
    let mt_bytes = gsm_map::encode(&mt).expect("encode mt-forward-sm");
    g.bench_function("mt_forward_sm/encode", |b| {
        b.iter_batched(
            || mt.clone(),
            |v| gsm_map::encode(&v).unwrap(),
            BatchSize::SmallInput,
        )
    });
    g.bench_function("mt_forward_sm/decode", |b| {
        b.iter(|| gsm_map::decode::<MtForwardSmArg>(&mt_bytes).unwrap())
    });

    g.finish();
}

/// A routing answer naming three serving nodes with their Diameter
/// addresses, an extension container and delivery guidance.
fn sri_sm_res_full() -> RoutingInfoForSmRes {
    let node = |last: u8| -> Vec<u8> { vec![0x91, 0x51, 0x55, 0x10, 0x00, last, 0xF0] };
    let diameter = |name: &[u8]| NetworkNodeDiameterAddress {
        diameter_name: name.to_vec().into(),
        diameter_realm: b"realm.test".to_vec().into(),
    };
    RoutingInfoForSmRes {
        extension_container: Some(ExtensionContainer::default()),
        ip_sm_gw_guidance: Some(IpSmGwGuidance {
            minimum_delivery_time_value: 30.into(),
            recommended_delivery_time_value: 300.into(),
            extension_container: None,
        }),
        ..RoutingInfoForSmRes::new(
            sample_imsi().into(),
            LocationInfoWithLmsi {
                lmsi: Some(vec![0x00, 0x00, 0x00, 0x01].into()),
                gprs_node_indicator: Some(()),
                additional_number: Some(AdditionalNumber::MscNumber(node(0x10).into())),
                network_node_diameter_address: Some(diameter(b"sgsn01.test")),
                additional_network_node_diameter_address: Some(diameter(b"msc01.test")),
                third_number: Some(AdditionalNumber::MscNumber(node(0x30).into())),
                third_network_node_diameter_address: Some(diameter(b"mme01.test")),
                ims_node_indicator: Some(()),
                ..LocationInfoWithLmsi::new(node(0x20).into())
            },
        )
    }
}

/// insertSubscriberData as an HLR sends it after a location update: identity,
/// services, barring, two PDP contexts carried opaquely, and the flags.
fn insert_subscriber_data() -> InsertSubscriberDataArg {
    // One PDP-Context: pdp-ContextId, pdp-Type [16], qos-Subscribed [18], apn [20].
    let mut pdp_context = vec![0x30, 0x13, 0x02, 0x01, 0x01, 0x90, 0x02, 0xF1, 0x21];
    pdp_context.extend_from_slice(&[0x92, 0x03, 0x23, 0x43, 0x1F]);
    pdp_context.extend_from_slice(&[0x94, 0x05, 0x04, b'i', b'n', b'e', b't']);
    // GPRSSubscriptionData: gprsDataList [1] with the context twice.
    let mut gprs = vec![0xA1, 0x2A];
    gprs.extend_from_slice(&pdp_context);
    gprs.extend_from_slice(&pdp_context);
    let mut odb_general = rasn::types::BitString::new();
    for bit in 0..15 {
        odb_general.push(bit == 0);
    }
    InsertSubscriberDataArg {
        imsi: Some(sample_imsi().into()),
        msisdn: Some(sample_msisdn().into()),
        category: Some(vec![0x0A].into()),
        subscriber_status: Some(SubscriberStatus::ServiceGranted),
        bearer_service_list: Some(vec![vec![0x1F].into(), vec![0x17].into()]),
        teleservice_list: Some(vec![
            vec![0x11].into(),
            vec![0x21].into(),
            vec![0x22].into(),
        ]),
        // Ext-SS-InfoList with one ss-Data [3] entry.
        provisioned_ss: Some(Opaque::new(vec![
            0xA3, 0x09, 0x04, 0x01, 0x41, 0x84, 0x01, 0x05, 0x82, 0x01, 0x10,
        ])),
        odb_data: Some(OdbData::new(odb_general)),
        gprs_subscription_data: Some(Opaque::new(gprs)),
        network_access_mode: Some(NetworkAccessMode::PacketAndCircuit),
        charging_characteristics: Some(vec![0x08, 0x00].into()),
        sms_in_sgsn_allowed: Some(()),
        ue_usage_type: Some(vec![0x00, 0x00, 0x00, 0x01].into()),
        ..InsertSubscriberDataArg::default()
    }
}

/// What the strict decoder costs over `rasn` alone, on the same octets.
fn bench_decode_cost(c: &mut Criterion) {
    let mut g = c.benchmark_group("decode_cost");
    g.throughput(Throughput::Elements(1));

    let res = sri_sm_res_full();
    let res_bytes = gsm_map::encode(&res).expect("encode sri-sm res");
    assert_eq!(
        gsm_map::decode::<RoutingInfoForSmRes>(&res_bytes).unwrap(),
        res
    );
    g.bench_function("sri_sm_res_full/rasn", |b| {
        b.iter(|| rasn::ber::decode::<RoutingInfoForSmRes>(&res_bytes).unwrap())
    });
    g.bench_function("sri_sm_res_full/strict", |b| {
        b.iter(|| gsm_map::decode::<RoutingInfoForSmRes>(&res_bytes).unwrap())
    });

    let isd = insert_subscriber_data();
    let isd_bytes = gsm_map::encode(&isd).expect("encode insertSubscriberData");
    assert_eq!(
        gsm_map::decode::<InsertSubscriberDataArg>(&isd_bytes).unwrap(),
        isd
    );
    g.bench_function("insert_subscriber_data/rasn", |b| {
        b.iter(|| rasn::ber::decode::<InsertSubscriberDataArg>(&isd_bytes).unwrap())
    });
    g.bench_function("insert_subscriber_data/strict", |b| {
        b.iter(|| gsm_map::decode::<InsertSubscriberDataArg>(&isd_bytes).unwrap())
    });

    g.finish();
}

criterion_group!(benches, bench_codec, bench_decode_cost);
criterion_main!(benches);
