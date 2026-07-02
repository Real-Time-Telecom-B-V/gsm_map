//! Integration vectors for the GSM MAP / CAP codec.
//!
//! Every vector here is **synthetic**, built programmatically from the public
//! API. Addresses use the fictional `+1 555 01xx` documentation block; IMSIs use
//! the reserved test MCC/MNC `001/01`. Nothing here is captured traffic.
//!
//! These tests exercise the crate on its own — no sibling transport crates
//! (SCCP / M3UA / MTP3 / SCTP) are needed. They cover:
//!   * BER encode → decode round-trips for every operation group, and
//!   * structural assertions on the emitted wire bytes (tags / lengths), and
//!   * the TCAP dialogue-portion and application-context helpers.

use gsm_map::application_context as ac;
use gsm_map::dialogue;
use gsm_map::operations::auth::{
    AuthenticationSetList, AuthenticationTriplet, SendAuthenticationInfoArg,
    SendAuthenticationInfoRes,
};
use gsm_map::operations::errors;
use gsm_map::operations::location::{UpdateLocationArg, UpdateLocationRes};
use gsm_map::operations::mo_forward_sm::MoForwardSmArg;
use gsm_map::operations::mt_forward_sm::MtForwardSmArg;
use gsm_map::operations::report_sm::{ReportSmDeliveryStatusArg, SmDeliveryOutcome};
use gsm_map::operations::sri_sm::{RoutingInfoForSmArg, RoutingInfoForSmRes};
use gsm_map::types::*;

// ── Synthetic fixtures (fictional `+1 555 01xx`; test IMSI `001/01`) ──

/// MSISDN `+1 555 0100 999`, international / E.164 (TON/NPI = 0x91).
const MSISDN: &[u8] = &[0x91, 0x51, 0x55, 0x10, 0x00, 0x99, 0xF9];
/// Service-centre address `+1 555 0199`.
const SC_ADDR: &[u8] = &[0x91, 0x51, 0x55, 0x10, 0x99];
/// Serving-MSC number `+1 555 0111`.
const MSC_NUM: &[u8] = &[0x91, 0x51, 0x55, 0x10, 0x11];
/// IMSI for test PLMN `001/01`, MSIN `0123456789`.
const IMSI: &[u8] = &[0x00, 0x01, 0x01, 0x21, 0x43, 0x65, 0x87, 0xF9];

/// Round-trip a value through BER and assert equality; return the wire bytes.
fn round_trip<T>(val: &T) -> Vec<u8>
where
    T: rasn::Decode + rasn::Encode + std::fmt::Debug + PartialEq,
{
    let encoded = rasn::ber::encode(val).expect("encode failed");
    let decoded: T = rasn::ber::decode(&encoded).expect("decode failed");
    assert_eq!(&decoded, val, "round-trip mismatch");
    encoded
}

/// Build an `OctetString` fixture from a byte slice (disambiguates `.into()`
/// against the several `PartialEq` impls on `OctetString`).
fn oct(bytes: &[u8]) -> rasn::types::OctetString {
    rasn::types::OctetString::from_slice(bytes)
}

// ── SMS: the SRI-SM → MT-ForwardSM delivery path ──

#[test]
fn sri_sm_request_round_trips_and_is_a_sequence() {
    let arg = RoutingInfoForSmArg {
        msisdn: MSISDN.into(),
        sm_rp_pri: true,
        service_centre_address: SC_ADDR.into(),
        gprs_support_indicator: None,
        sm_rp_mti: None,
        sm_rp_smea: None,
    };
    let wire = round_trip(&arg);
    // BER SEQUENCE tag.
    assert_eq!(wire[0], 0x30, "SRI-SM arg must encode as a SEQUENCE");
}

#[test]
fn sri_sm_response_carries_imsi_and_serving_node() {
    let res = RoutingInfoForSmRes {
        imsi: IMSI.into(),
        location_info_with_lmsi: LocationInfoWithLmsi {
            network_node_number: MSC_NUM.into(),
            lmsi: Some(vec![0x00, 0x00, 0x00, 0x2A].into()),
            gprs_node_indicator: None,
            additional_number: None,
        },
    };
    let decoded: RoutingInfoForSmRes = rasn::ber::decode(&round_trip(&res)).unwrap();
    assert_eq!(decoded.imsi, res.imsi);
    assert_eq!(
        decoded.location_info_with_lmsi.network_node_number,
        oct(MSC_NUM)
    );
}

#[test]
fn mo_forward_sm_carries_a_submit_tpdu() {
    // A minimal spec-shaped SMS-SUBMIT TPDU addressed to the synthetic MSISDN.
    let submit_tpdu = vec![
        0x11, // MTI = SUBMIT, VPF = relative
        0x00, // TP-MR
        0x0B, // TP-DA length: 11 digits
        0x91, // TP-DA TON/NPI: international E.164
        0x51, 0x55, 0x10, 0x00, 0x99, 0xF9, // +1 555 0100 999
        0x00, // TP-PID
        0x00, // TP-DCS: GSM 7-bit default
        0x05, // TP-VP: relative
        0x05, // TP-UDL: 5 septets
        0xE8, 0x32, 0x9B, 0xFD, 0x06, // "Hello" packed GSM 7-bit
    ];
    let arg = MoForwardSmArg {
        sm_rp_da: SmRpDa::ServiceCentreAddressDa(SC_ADDR.into()),
        sm_rp_oa: SmRpOa::MsIsdn(MSISDN.into()),
        sm_rp_ui: submit_tpdu.clone().into(),
        imsi: None,
    };
    let decoded: MoForwardSmArg = rasn::ber::decode(&round_trip(&arg)).unwrap();
    assert_eq!(decoded.sm_rp_ui, oct(&submit_tpdu));
    match decoded.sm_rp_oa {
        SmRpOa::MsIsdn(m) => assert_eq!(m, oct(MSISDN)),
        other => panic!("expected MsIsdn originator, got {other}"),
    }
}

#[test]
fn mt_forward_sm_addresses_the_imsi() {
    let arg = MtForwardSmArg {
        sm_rp_da: SmRpDa::Imsi(IMSI.into()),
        sm_rp_oa: SmRpOa::ServiceCentreAddressOa(SC_ADDR.into()),
        sm_rp_ui: vec![0x04, 0x0B, 0x91, 0x51, 0x55, 0x10, 0x00, 0x99, 0xF9].into(),
        more_messages_to_send: None,
    };
    let decoded: MtForwardSmArg = rasn::ber::decode(&round_trip(&arg)).unwrap();
    match decoded.sm_rp_da {
        SmRpDa::Imsi(i) => assert_eq!(i, oct(IMSI)),
        other => panic!("expected IMSI destination, got {other}"),
    }
}

#[test]
fn report_sm_delivery_status_outcomes() {
    for outcome in [
        SmDeliveryOutcome::SuccessfulTransfer,
        SmDeliveryOutcome::AbsentSubscriber,
        SmDeliveryOutcome::SuccessfulTransfer,
    ] {
        let arg = ReportSmDeliveryStatusArg {
            msisdn: MSISDN.into(),
            service_centre_address: SC_ADDR.into(),
            sm_delivery_outcome: outcome,
        };
        let decoded: ReportSmDeliveryStatusArg = rasn::ber::decode(&round_trip(&arg)).unwrap();
        assert_eq!(decoded.sm_delivery_outcome, outcome);
    }
}

// ── Mobility: updateLocation + authentication ──

#[test]
fn update_location_round_trips() {
    let arg = UpdateLocationArg {
        imsi: IMSI.into(),
        msc_number: MSC_NUM.into(),
        vlr_number: MSC_NUM.into(),
        lmsi: Some(vec![0x00, 0x00, 0x00, 0x01].into()),
        vlr_capability: None,
    };
    let decoded: UpdateLocationArg = rasn::ber::decode(&round_trip(&arg)).unwrap();
    assert_eq!(decoded.imsi, oct(IMSI));

    let res = UpdateLocationRes {
        hlr_number: SC_ADDR.into(),
    };
    let decoded: UpdateLocationRes = rasn::ber::decode(&round_trip(&res)).unwrap();
    assert_eq!(decoded.hlr_number, oct(SC_ADDR));
}

#[test]
fn send_authentication_info_triplet_vectors() {
    let arg = SendAuthenticationInfoArg {
        imsi: IMSI.into(),
        number_of_requested_vectors: 3.into(),
        re_synchronisation_info: None,
        requesting_node_type: None,
    };
    round_trip(&arg);

    // Synthetic auth triplets (all-zero material — no real key data).
    let triplets: Vec<AuthenticationTriplet> = (0..3)
        .map(|i| AuthenticationTriplet {
            rand: vec![i; 16].into(),
            sres: vec![i; 4].into(),
            kc: vec![i; 8].into(),
        })
        .collect();
    let res = SendAuthenticationInfoRes {
        authentication_set_list: Some(AuthenticationSetList::TripletList(triplets)),
    };
    let decoded: SendAuthenticationInfoRes = rasn::ber::decode(&round_trip(&res)).unwrap();
    match decoded.authentication_set_list.unwrap() {
        AuthenticationSetList::TripletList(t) => assert_eq!(t.len(), 3),
        other => panic!("expected triplet list, got {other:?}"),
    }
}

// ── Application contexts + TCAP dialogue portion ──

#[test]
fn application_contexts_are_distinct_per_version() {
    let v1 = ac::short_msg_gateway_context(ac::V1);
    let v2 = ac::short_msg_gateway_context(ac::V2);
    let v3 = ac::short_msg_gateway_context(ac::V3);
    assert_ne!(v1, v2);
    assert_ne!(v2, v3);
    // v3 ends in ...20.3
    assert_eq!(v3.iter().copied().last(), Some(3));
}

#[test]
fn dialogue_portion_wraps_the_application_context() {
    let oid = ac::short_msg_gateway_context(ac::V3);
    let begin = dialogue::build_begin_dialogue(&oid);
    let end = dialogue::build_end_dialogue(&oid);
    // Both must be non-empty EXTERNAL-encoded dialogue portions.
    assert!(!begin.is_empty());
    assert!(!end.is_empty());
    // A dialogue-request (AARQ, [APPLICATION 0]) vs dialogue-response differ.
    assert_ne!(begin, end);
}

// ── MAP error registry ──

#[test]
fn map_error_names_resolve() {
    assert_eq!(
        errors::error_name(errors::error_codes::ABSENT_SUBSCRIBER),
        "absentSubscriber"
    );
    assert_eq!(
        errors::error_name(errors::error_codes::SYSTEM_FAILURE),
        "systemFailure"
    );
    assert_eq!(
        errors::error_name(errors::error_codes::UNKNOWN_SUBSCRIBER),
        "unknownSubscriber"
    );
    assert_eq!(errors::error_name(9999), "unknown");
}

// ── Operation-code registry ──

#[test]
fn operation_names_resolve() {
    assert_eq!(
        operation_name(op_codes::SEND_ROUTING_INFO_FOR_SM),
        "sendRoutingInfoForSM"
    );
    assert_eq!(operation_name(op_codes::MT_FORWARD_SM), "mt-ForwardSM");
    assert_eq!(operation_name(op_codes::MO_FORWARD_SM), "mo-ForwardSM");
    assert_eq!(operation_name(op_codes::UPDATE_LOCATION), "updateLocation");
    assert_eq!(operation_name(0xFF), "unknown");
}
