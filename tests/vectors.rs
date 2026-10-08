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
use gsm_map::operations::fault_recovery::{ResetArg, SendingNodeNumber};
use gsm_map::operations::inform_sc::InformServiceCentreArg;
use gsm_map::operations::location::{UpdateLocationArg, UpdateLocationRes};
use gsm_map::operations::mo_forward_sm::MoForwardSmArg;
use gsm_map::operations::mt_forward_sm::MtForwardSmArg;
use gsm_map::operations::ready_for_sm::{AlertReason, ReadyForSmArg};
use gsm_map::operations::report_sm::{ReportSmDeliveryStatusArg, SmDeliveryOutcome};
use gsm_map::operations::sri_sm::{IpSmGwGuidance, RoutingInfoForSmArg, RoutingInfoForSmRes};
use gsm_map::operations::subscriber_info::{
    AnyTimeModificationArg, ModificationInstruction, ModificationRequestForIpSmGwData,
    SubscriberIdentity,
};
use gsm_map::operations::supplementary::RegisterSsArg;
use gsm_map::types::MwStatusFlags;
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
    let encoded = gsm_map::encode(val).expect("encode failed");
    let decoded = gsm_map::decode_with_extensions::<T>(&encoded).expect("decode failed");
    assert_eq!(&decoded.value, val, "round-trip mismatch");
    assert_eq!(decoded.unknown_extensions, []);
    // rasn's own decoder has to agree on everything this crate encodes.
    let lenient: T = rasn::ber::decode(&encoded).expect("rasn decode failed");
    assert_eq!(&lenient, val, "rasn disagrees with the crate's decoder");
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
    let arg = RoutingInfoForSmArg::new(MSISDN.into(), true, SC_ADDR.into());
    let wire = round_trip(&arg);
    // BER SEQUENCE tag.
    assert_eq!(wire[0], 0x30, "SRI-SM arg must encode as a SEQUENCE");
}

#[test]
fn sri_sm_response_carries_imsi_and_serving_node() {
    let res = RoutingInfoForSmRes::new(
        IMSI.into(),
        LocationInfoWithLmsi {
            lmsi: Some(vec![0x00, 0x00, 0x00, 0x2A].into()),
            ..LocationInfoWithLmsi::new(MSC_NUM.into())
        },
    );
    let decoded: RoutingInfoForSmRes = gsm_map::decode(&round_trip(&res)).unwrap();
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
    let arg = MoForwardSmArg::new(
        SmRpDa::ServiceCentreAddressDa(SC_ADDR.into()),
        SmRpOa::MsIsdn(MSISDN.into()),
        submit_tpdu.clone().into(),
    );
    let decoded: MoForwardSmArg = gsm_map::decode(&round_trip(&arg)).unwrap();
    assert_eq!(decoded.sm_rp_ui, oct(&submit_tpdu));
    match decoded.sm_rp_oa {
        SmRpOa::MsIsdn(m) => assert_eq!(m, oct(MSISDN)),
        other => panic!("expected MsIsdn originator, got {other}"),
    }
}

#[test]
fn mt_forward_sm_addresses_the_imsi() {
    let arg = MtForwardSmArg::new(
        SmRpDa::Imsi(IMSI.into()),
        SmRpOa::ServiceCentreAddressOa(SC_ADDR.into()),
        vec![0x04, 0x0B, 0x91, 0x51, 0x55, 0x10, 0x00, 0x99, 0xF9].into(),
    );
    let decoded: MtForwardSmArg = gsm_map::decode(&round_trip(&arg)).unwrap();
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
        let arg = ReportSmDeliveryStatusArg::new(MSISDN.into(), SC_ADDR.into(), outcome);
        let decoded: ReportSmDeliveryStatusArg = gsm_map::decode(&round_trip(&arg)).unwrap();
        assert_eq!(decoded.sm_delivery_outcome, outcome);
    }
}

// ── Mobility: updateLocation + authentication ──

#[test]
fn update_location_round_trips() {
    let arg = UpdateLocationArg {
        lmsi: Some(vec![0x00, 0x00, 0x00, 0x01].into()),
        ..UpdateLocationArg::new(IMSI.into(), MSC_NUM.into(), MSC_NUM.into())
    };
    let decoded: UpdateLocationArg = gsm_map::decode(&round_trip(&arg)).unwrap();
    assert_eq!(decoded.imsi, oct(IMSI));

    let res = UpdateLocationRes::new(SC_ADDR.into());
    let decoded: UpdateLocationRes = gsm_map::decode(&round_trip(&res)).unwrap();
    assert_eq!(decoded.hlr_number, oct(SC_ADDR));
}

#[test]
fn send_authentication_info_triplet_vectors() {
    let arg = SendAuthenticationInfoArg::new(IMSI.into(), 3.into());
    round_trip(&arg);

    // Synthetic auth triplets (all-zero material — no real key data).
    let triplets: Vec<AuthenticationTriplet> = (0..3)
        .map(|i| AuthenticationTriplet {
            rand: vec![i; 16].into(),
            sres: vec![i; 4].into(),
            kc: vec![i; 8].into(),
        })
        .collect();
    let mut res = SendAuthenticationInfoRes::default();
    res.set_authentication_set_list(AuthenticationSetList::TripletList(triplets));
    let decoded: SendAuthenticationInfoRes = gsm_map::decode(&round_trip(&res)).unwrap();
    match decoded.authentication_set_list().unwrap() {
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
fn dialogue_portion_carries_and_returns_the_application_context() {
    let oid = ac::short_msg_gateway_context(ac::V3);
    let begin = dialogue::begin(&oid);
    let end = dialogue::end_accept(&oid);
    assert_ne!(begin, end);
    // Both name the context, and both parse back into a typed PDU.
    assert_eq!(dialogue::application_context(&begin), Some(oid.clone()));
    assert_eq!(dialogue::application_context(&end), Some(oid));
    assert!(matches!(
        dialogue::parse(&begin),
        Some(dialogue::DialoguePdu::Aarq { .. })
    ));
    assert!(matches!(
        dialogue::parse(&end),
        Some(dialogue::DialoguePdu::Aare { .. })
    ));

    // An abort names no context but still parses.
    let abrt = dialogue::abort(dialogue::AbortSource::DialogueServiceProvider);
    assert_eq!(dialogue::application_context(&abrt), None);
    assert!(matches!(
        dialogue::parse(&abrt),
        Some(dialogue::DialoguePdu::Abrt { .. })
    ));
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
    assert_eq!(operation_name(op_codes::MT_FORWARD_SM), "mt-forwardSM");
    assert_eq!(operation_name(op_codes::MO_FORWARD_SM), "mo-forwardSM");
    assert_eq!(operation_name(op_codes::UPDATE_LOCATION), "updateLocation");
    assert_eq!(operation_name(0xFF), "unknown");
}

// ── anyTimeModification carrying the IP-SM-GW registration ──────────────────

/// The IP-SM-GW's own address in the gsmSCF role, `+1 555 0142`.
const IP_SM_GW_ADDR: &[u8] = &[0x91, 0x51, 0x55, 0x10, 0x24];

fn atm(ip_sm_gw: Option<ModificationRequestForIpSmGwData>) -> AnyTimeModificationArg {
    AnyTimeModificationArg {
        modification_request_for_ip_sm_gw_data: ip_sm_gw,
        ..AnyTimeModificationArg::new(
            SubscriberIdentity::Msisdn(MSISDN.into()),
            IP_SM_GW_ADDR.into(),
        )
    }
}

fn registration(instruction: ModificationInstruction) -> ModificationRequestForIpSmGwData {
    ModificationRequestForIpSmGwData {
        modify_registration_status: Some(instruction),
        ..Default::default()
    }
}

#[test]
fn any_time_modification_registers_and_deregisters_an_ip_sm_gw() {
    for instruction in [
        ModificationInstruction::Activate,
        ModificationInstruction::Deactivate,
    ] {
        let arg = atm(Some(registration(instruction)));
        let decoded: AnyTimeModificationArg = gsm_map::decode(&round_trip(&arg)).unwrap();
        let data = decoded
            .modification_request_for_ip_sm_gw_data
            .expect("registration survives the round trip");
        assert_eq!(data.modify_registration_status, Some(instruction));
        assert_eq!(data.ip_sm_gw_diameter_address, None);
    }
}

#[test]
fn ip_sm_gw_registration_encodes_at_tag_8() {
    for (instruction, value) in [
        (ModificationInstruction::Activate, 0x01),
        (ModificationInstruction::Deactivate, 0x00),
    ] {
        let wire = round_trip(&atm(Some(registration(instruction))));
        // modificationRequestFor-IP-SM-GW-Data [8], constructed, holding
        // modifyRegistrationStatus [0], primitive, one byte.
        let expected: &[u8] = &[0xA8, 0x03, 0x80, 0x01, value];
        assert!(
            wire.windows(expected.len()).any(|w| w == expected),
            "expected {expected:02x?} in {wire:02x?}"
        );
    }
}

#[test]
fn ip_sm_gw_registration_carries_a_diameter_address() {
    let arg = atm(Some(ModificationRequestForIpSmGwData {
        modify_registration_status: Some(ModificationInstruction::Activate),
        ip_sm_gw_diameter_address: Some(NetworkNodeDiameterAddress {
            diameter_name: b"ipsmgw.example.net".to_vec().into(),
            diameter_realm: b"example.net".to_vec().into(),
        }),
        ..Default::default()
    }));
    let decoded: AnyTimeModificationArg = gsm_map::decode(&round_trip(&arg)).unwrap();
    let address = decoded
        .modification_request_for_ip_sm_gw_data
        .and_then(|d| d.ip_sm_gw_diameter_address)
        .expect("ip-sm-gw-DiameterAddress survives the round trip");
    assert_eq!(address.diameter_realm, oct(b"example.net"));
}

#[test]
fn the_new_any_time_modification_members_cost_nothing_when_absent() {
    // The added members are optional and absent by default, so an argument that
    // leaves them `None` must encode to exactly the bytes the type produced
    // before they existed: subscriberIdentity [0] wrapping the msisdn [1]
    // alternative, then gsmSCF-Address [1].
    let mut expected = vec![0x30, 0x00, 0xA0, 0x09, 0x81, 0x07];
    expected.extend_from_slice(MSISDN);
    expected.extend_from_slice(&[0x81, 0x05]);
    expected.extend_from_slice(IP_SM_GW_ADDR);
    expected[1] = (expected.len() - 2) as u8;

    assert_eq!(round_trip(&atm(None)), expected);
}

#[test]
fn subscriber_identity_is_an_explicitly_tagged_choice() {
    // subscriberIdentity is a CHOICE, so TS 29.002's IMPLICIT TAGS does not
    // apply and [0] is explicit: A0 wrapping the alternative's own tag. An
    // implicit [0] would overwrite the msisdn alternative's [1] and the
    // identity would be unreadable to a peer.
    let wire = round_trip(&atm(None));
    assert_eq!(&wire[2..6], &[0xA0, 0x09, 0x81, 0x07]);
}

#[test]
fn any_time_info_handling_context_is_arc_43() {
    let oid = ac::any_time_info_handling_context(ac::V3);
    let components: Vec<u32> = oid.iter().copied().collect();
    assert_eq!(components, vec![0, 4, 0, 0, 1, 0, 43, 3]);
}

#[test]
fn subscriber_info_operation_names_resolve() {
    assert_eq!(
        operation_name(op_codes::ANY_TIME_MODIFICATION),
        "anyTimeModification"
    );
    assert_eq!(
        operation_name(op_codes::PROVIDE_SUBSCRIBER_INFO),
        "provideSubscriberInfo"
    );
    assert_eq!(
        operation_name(op_codes::ANY_TIME_INTERROGATION),
        "anyTimeInterrogation"
    );
}

// ── readyForSM ──────────────────────────────────────────────────────────────

#[test]
fn ready_for_sm_tags_the_imsi_as_context_0() {
    let arg = ReadyForSmArg::new(IMSI.into(), AlertReason::MsPresent);
    let wire = round_trip(&arg);
    // SEQUENCE, then imsi [0] primitive — not a universal OCTET STRING (0x04).
    assert_eq!(wire[0], 0x30);
    assert_eq!(wire[2], 0x80, "imsi must carry context tag [0]");
    assert_eq!(wire[3] as usize, IMSI.len());

    // The shape gsm_map 1.x emitted — a universal OCTET STRING — is what a
    // conformant HLR rejects, and it must not decode as a ReadyForSM-Arg here
    // either.
    let mut legacy = wire.clone();
    legacy[2] = 0x04;
    assert!(
        gsm_map::decode::<ReadyForSmArg>(&legacy).is_err(),
        "the 1.x universal-tag encoding must no longer round-trip"
    );
}

// ── decode tolerance: members a real HLR sends ──────────────────────────────

/// Splice `extra` in at the end of a definite-length, short-form SEQUENCE and
/// fix up the length octet.
fn append_member(encoded: &[u8], extra: &[u8]) -> Vec<u8> {
    assert_eq!(encoded[0], 0x30, "expected a universal SEQUENCE");
    let len = encoded[1] as usize;
    assert!(len < 0x80, "fixture must use the short length form");
    let mut out = vec![0x30, (len + extra.len()) as u8];
    out.extend_from_slice(&encoded[2..2 + len]);
    out.extend_from_slice(extra);
    out
}

#[test]
fn sri_sm_response_decodes_with_an_extension_container() {
    let res = RoutingInfoForSmRes::new(IMSI.into(), LocationInfoWithLmsi::new(MSC_NUM.into()));
    let wire = round_trip(&res);

    // [4] extensionContainer holding a privateExtensionList [0] with one
    // PrivateExtension: a bare extId OBJECT IDENTIFIER.
    let extension_container: &[u8] = &[
        0xA4, 0x0C, 0xA0, 0x0A, 0x30, 0x08, 0x06, 0x06, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D,
    ];
    let decoded: RoutingInfoForSmRes = gsm_map::decode(&append_member(&wire, extension_container))
        .expect("an extensionContainer from a real HLR must decode");
    assert!(decoded.extension_container.is_some());
    assert_eq!(decoded.imsi, oct(IMSI));
}

#[test]
fn sri_sm_response_decodes_with_ip_sm_gw_guidance() {
    let res = RoutingInfoForSmRes {
        ip_sm_gw_guidance: Some(IpSmGwGuidance {
            minimum_delivery_time_value: 30.into(),
            recommended_delivery_time_value: 300.into(),
            extension_container: None,
        }),
        ..RoutingInfoForSmRes::new(IMSI.into(), LocationInfoWithLmsi::new(MSC_NUM.into()))
    };
    let decoded: RoutingInfoForSmRes = gsm_map::decode(&round_trip(&res)).unwrap();
    let guidance = decoded.ip_sm_gw_guidance.expect("ip-sm-gwGuidance");
    assert_eq!(guidance.minimum_delivery_time_value, 30.into());
    assert_eq!(guidance.recommended_delivery_time_value, 300.into());
}

#[test]
fn sri_sm_response_decodes_a_serving_node_diameter_address() {
    let res = RoutingInfoForSmRes::new(
        IMSI.into(),
        LocationInfoWithLmsi {
            additional_number: Some(AdditionalNumber::SgsnNumber(MSC_NUM.into())),
            network_node_diameter_address: Some(NetworkNodeDiameterAddress {
                diameter_name: b"msc.example.net".to_vec().into(),
                diameter_realm: b"example.net".to_vec().into(),
            }),
            ..LocationInfoWithLmsi::new(MSC_NUM.into())
        },
    );
    let decoded: RoutingInfoForSmRes = gsm_map::decode(&round_trip(&res)).unwrap();
    let info = decoded.location_info_with_lmsi;
    assert_eq!(
        info.additional_number,
        Some(AdditionalNumber::SgsnNumber(oct(MSC_NUM)))
    );
    assert_eq!(
        info.network_node_diameter_address.map(|a| a.diameter_realm),
        Some(oct(b"example.net"))
    );
}

#[test]
fn location_info_extension_container_does_not_eat_the_members_after_it() {
    // extensionContainer sits at an *untagged* position between `lmsi` and the
    // post-extension members, so a wrong model here silently swallows whatever
    // follows instead of failing.
    let info = LocationInfoWithLmsi {
        lmsi: Some(vec![0x00, 0x00, 0x00, 0x2A].into()),
        extension_container: Some(ExtensionContainer {
            private_extension_list: Some(rasn::types::Any::new(vec![
                0x30, 0x08, 0x06, 0x06, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D,
            ])),
            pcs_extensions: None,
        }),
        gprs_node_indicator: Some(()),
        additional_number: Some(AdditionalNumber::MscNumber(MSC_NUM.into())),
        smsf_3gpp_address_indicator: Some(()),
        ..LocationInfoWithLmsi::new(MSC_NUM.into())
    };
    let res = RoutingInfoForSmRes::new(IMSI.into(), info);
    let decoded: RoutingInfoForSmRes = gsm_map::decode(&round_trip(&res)).unwrap();
    let info = decoded.location_info_with_lmsi;
    assert!(info.extension_container.is_some());
    assert_eq!(info.gprs_node_indicator, Some(()));
    assert_eq!(
        info.additional_number,
        Some(AdditionalNumber::MscNumber(oct(MSC_NUM)))
    );
    assert_eq!(info.smsf_3gpp_address_indicator, Some(()));
}

#[test]
fn an_unmodelled_trailing_member_is_skipped_not_fatal() {
    // rasn 0.28 does not skip members a type does not model: it fails the
    // whole decode with UnexpectedExtraData. TS 29.002 17.1.4 obliges a
    // receiver to accept them after the extension marker, and the crate's
    // decoder does. tests/extensibility.rs has the cases.
    let wire = round_trip(&RoutingInfoForSmArg::new(
        MSISDN.into(),
        true,
        SC_ADDR.into(),
    ));
    // A context [20] member: past everything Rel-18 defines.
    let extended = append_member(&wire, &[0x94, 0x00]);
    assert!(rasn::ber::decode::<RoutingInfoForSmArg>(&extended).is_err());
    let decoded = gsm_map::decode_with_extensions::<RoutingInfoForSmArg>(&extended).unwrap();
    assert!(decoded.value.sm_rp_pri);
    assert_eq!(decoded.unknown_extensions.len(), 1);
}

// ── Encoder shapes that a round-trip alone would not catch ──────────────────

#[test]
fn mw_status_is_a_bit_string_not_a_packed_byte() {
    // MW-Status is a BIT STRING numbered from the most significant bit, and it
    // is untagged. Packing the flags into an OCTET STRING (as gsm_map 1.x did)
    // put them in the wrong member entirely and in the wrong bit order.
    let arg = InformServiceCentreArg {
        mw_status: Some(
            MwStatusFlags {
                sc_address_not_included: true,
                mnrf_set: true,
                mcef_set: true,
                mnrg_set: true,
                ..Default::default()
            }
            .to_bits(),
        ),
        ..Default::default()
    };
    let wire = round_trip(&arg);
    // SEQUENCE, then BIT STRING (0x03), two unused bits, value 0xF0.
    assert_eq!(&wire[..], &[0x30, 0x04, 0x03, 0x02, 0x02, 0xF0]);
}

#[test]
fn reset_sending_node_number_is_an_untagged_choice_alternative() {
    // SendingNode-Number's hlr-Number alternative carries no tag of its own, so
    // it goes on the wire as a universal OCTET STRING. Only css-Number is [1].
    let hlr = round_trip(&ResetArg::new(SendingNodeNumber::HlrNumber(SC_ADDR.into())));
    assert_eq!(hlr[2], 0x04, "hlr-Number is untagged");
    let css = round_trip(&ResetArg::new(SendingNodeNumber::CssNumber(SC_ADDR.into())));
    assert_eq!(css[2], 0x81, "css-Number carries context tag [1]");
}

#[test]
fn register_ss_emits_tag_6_before_tag_5() {
    // TS 29.002 declares forwardedToSubaddress [6] ahead of noReplyConditionTime
    // [5], and BER encodes in declaration order. Ascending-by-tag would put the
    // subaddress where no peer looks for it.
    let wire = round_trip(&RegisterSsArg {
        forwarded_to_subaddress: Some(oct(&[0x01])),
        no_reply_condition_time: Some(20.into()),
        ..RegisterSsArg::new(oct(&[0x21]))
    });
    let six = wire.iter().position(|&b| b == 0x86).expect("[6] present");
    let five = wire.iter().position(|&b| b == 0x85).expect("[5] present");
    assert!(six < five, "[6] must precede [5], got {wire:02x?}");
}

#[test]
fn requested_info_emits_tag_6_before_tag_5_and_11_before_8() {
    use gsm_map::operations::subscriber_info::RequestedInfo;
    let wire = round_trip(&RequestedInfo {
        ms_classmark: Some(()),
        imei: Some(()),
        t_ads_data: Some(()),
        location_information_eps_supported: Some(()),
        ..Default::default()
    });
    let at = |tag: u8| wire.iter().position(|&b| b == tag).expect("member present");
    assert!(at(0x86) < at(0x85), "imei [6] precedes ms-classmark [5]");
    assert!(
        at(0x8B) < at(0x88),
        "locationInformationEPS-Supported [11] precedes t-adsData [8]"
    );
}

#[test]
fn location_information_tags_match_the_asn1() {
    use gsm_map::operations::subscriber_info::LocationInformation;
    // ageOfLocationInformation is untagged; geographicalInformation is [0], not
    // [1]; every member after it shifts down by one from what 1.x emitted.
    let wire = round_trip(&LocationInformation {
        age_of_location_information: Some(5.into()),
        geographical_information: Some(oct(&[0x10; 8])),
        vlr_number: Some(MSC_NUM.into()),
        sai_present: Some(()),
        ..Default::default()
    });
    assert_eq!(
        wire[2], 0x02,
        "ageOfLocationInformation is an untagged INTEGER"
    );
    assert!(
        wire.windows(2).any(|w| w == [0x80, 0x08]),
        "geographicalInformation [0]"
    );
    assert!(
        wire.windows(2).any(|w| w == [0x89, 0x00]),
        "sai-Present [9]"
    );
}

#[test]
fn subscriber_state_is_a_choice_at_an_explicit_tag() {
    use gsm_map::operations::subscriber_info::{
        NotReachableReason, SubscriberInfo, SubscriberState,
    };
    let wire = round_trip(&SubscriberInfo {
        subscriber_state: Some(SubscriberState::CamelBusy(())),
        ..Default::default()
    });
    // [1] explicit, wrapping the camelBusy [1] alternative.
    assert_eq!(&wire[2..6], &[0xA1, 0x02, 0x81, 0x00]);

    let wire = round_trip(&SubscriberInfo {
        subscriber_state: Some(SubscriberState::NetDetNotReachable(
            NotReachableReason::RestrictedArea,
        )),
        ..Default::default()
    });
    // netDetNotReachable is the untagged alternative: a universal ENUMERATED.
    assert_eq!(&wire[2..7], &[0xA1, 0x03, 0x0A, 0x01, 0x02]);
}
