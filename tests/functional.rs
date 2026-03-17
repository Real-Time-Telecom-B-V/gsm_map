//! Functional tests — end-to-end protocol stack tests with mock network elements.
//!
//! These tests verify that a complete MAP operation can be built up through
//! all protocol layers (MAP → TCAP → SCCP → M3UA) and decoded back.

use gsm_map::operations::sri_sm::{RoutingInfoForSmArg, RoutingInfoForSmRes};
use gsm_map::operations::mt_forward_sm::MtForwardSmArg;
use gsm_map::operations::location::{UpdateLocationArg, UpdateLocationRes};
use gsm_map::operations::auth::{SendAuthenticationInfoArg, SendAuthenticationInfoRes, AuthenticationSetList, AuthenticationTriplet};
use gsm_map::operations::subscriber_info::{AnyTimeInterrogationArg, RequestedInfo, SubscriberIdentity, SubscriberInfo};
use gsm_map::operations::cap::{InitialDpArg, EventTypeBcsm, ConnectArg};
use gsm_map::types::*;
use gsm_map::application_context;

use tcap::{TcapMessage, Begin, End, Component, Invoke, ReturnResult, ReturnResultValue, OperationCode};
use sccp::{SccpAddress, GlobalTitle, SubsystemNumber, UnitData};
use m3ua::{M3uaMessage, ProtocolData};

// ─── Helpers ───────────────────────────────────────────────────

/// Build a TCAP Begin with a MAP Invoke, wrap in SCCP UDT, then M3UA DATA.
/// Returns the M3UA encoded bytes.
fn build_map_request(
    op_code: i64,
    map_arg_bytes: &[u8],
    otid: &[u8],
    called_gt_digits: &str,
    calling_gt_digits: &str,
    called_ssn: SubsystemNumber,
    calling_ssn: SubsystemNumber,
    opc: u32,
    dpc: u32,
) -> Vec<u8> {
    // 1. Build TCAP Begin with Invoke
    let invoke = Invoke {
        invoke_id: 1,
        linked_id: None,
        operation_code: OperationCode::Local(op_code),
        parameter: if map_arg_bytes.is_empty() {
            None
        } else {
            Some(rasn::types::Any::new(rasn::ber::encode(&rasn::types::OctetString::from(map_arg_bytes.to_vec())).unwrap()))
        },
    };

    let begin = Begin {
        otid: otid.to_vec().into(),
        dialogue_portion: None,
        components: Some(vec![Component::Invoke(invoke)]),
    };

    let tcap_msg = TcapMessage::Begin(begin);
    let tcap_bytes = tcap::encode(&tcap_msg).unwrap();

    // 2. Wrap in SCCP UDT
    let called_gt = GlobalTitle::Gt0100 {
        translation_type: 0,
        numbering_plan: 1,
        encoding_scheme: 1,
        nature_of_address: 4,
        digits: called_gt_digits.to_string(),
    };
    let calling_gt = GlobalTitle::Gt0100 {
        translation_type: 0,
        numbering_plan: 1,
        encoding_scheme: 1,
        nature_of_address: 4,
        digits: calling_gt_digits.to_string(),
    };

    let called = SccpAddress::with_gt(called_gt, Some(called_ssn));
    let calling = SccpAddress::with_gt(calling_gt, Some(calling_ssn));

    let udt = UnitData::new(called, calling, tcap_bytes);
    let sccp_bytes = udt.encode().unwrap();

    // 3. Wrap in M3UA DATA
    let pd = ProtocolData::new(
        opc, dpc,
        3,  // SI = SCCP
        2,  // NI = National
        0,  // MP
        0,  // SLS
        sccp_bytes,
    );
    let m3ua_msg = M3uaMessage::data(None, Some(1), pd, None);
    m3ua_msg.encode()
}

/// Decode M3UA → SCCP → extract TCAP bytes.
fn decode_to_tcap(m3ua_bytes: &[u8]) -> (ProtocolData, UnitData, Vec<u8>) {
    let m3ua_msg = M3uaMessage::decode(m3ua_bytes).unwrap();
    let pd = m3ua_msg.protocol_data().unwrap();
    assert_eq!(pd.si, 3); // SCCP

    let udt = UnitData::decode(&pd.user_data).unwrap();
    let tcap_bytes = udt.data.clone();

    (pd, udt, tcap_bytes)
}

// ─── Test: Full SRI-SM Flow ────────────────────────────────────

/// Simulate: SMS-SC sends SRI-SM to HLR via STP.
/// SMS-SC (OPC=100) → STP → HLR (DPC=200)
#[test]
fn full_sri_sm_request_through_stack() {
    let sri_sm_arg = RoutingInfoForSmArg {
        msisdn: vec![0x91, 0x13, 0x16, 0x32, 0x54, 0x76, 0xF8].into(),
        sm_rp_pri: true,
        service_centre_address: vec![0x91, 0x44, 0x77, 0x89, 0x01, 0x23].into(),
        gprs_support_indicator: None,
        sm_rp_mti: None,
        sm_rp_smea: None,
    };
    let map_bytes = rasn::ber::encode(&sri_sm_arg).unwrap();

    let m3ua_bytes = build_map_request(
        op_codes::SEND_ROUTING_INFO_FOR_SM,
        &map_bytes,
        &[0x00, 0x00, 0x00, 0x01],
        "31612345678",  // Called GT (HLR)
        "31699887766",  // Calling GT (SMS-SC)
        SubsystemNumber::Hlr,
        SubsystemNumber::Msc,
        100, // OPC (SMS-SC)
        200, // DPC (HLR)
    );

    // Decode back through the full stack
    let (pd, udt, tcap_bytes) = decode_to_tcap(&m3ua_bytes);

    // Verify M3UA layer
    assert_eq!(pd.opc, 100);
    assert_eq!(pd.dpc, 200);
    assert_eq!(pd.si, 3); // SCCP

    // Verify SCCP layer
    assert!(udt.called_party.global_title.digits().unwrap().contains("31612345678"));
    assert_eq!(udt.called_party.ssn, Some(SubsystemNumber::Hlr));

    // Verify TCAP layer
    let tcap_msg = tcap::decode(&tcap_bytes).unwrap();
    match tcap_msg {
        TcapMessage::Begin(b) => {
            assert_eq!(b.otid.as_ref(), &[0, 0, 0, 1]);
        }
        _ => panic!("Expected TCAP Begin"),
    }
}

/// Simulate: HLR responds to SRI-SM with IMSI + serving MSC.
#[test]
fn full_sri_sm_response_through_stack() {
    let sri_sm_res = RoutingInfoForSmRes {
        imsi: vec![0x09, 0x10, 0x10, 0x00, 0x00, 0x00, 0x00, 0x01].into(),
        location_info_with_lmsi: LocationInfoWithLmsi {
            network_node_number: vec![0x91, 0x44, 0x77, 0x12, 0x34, 0x56].into(),
            lmsi: Some(vec![0x00, 0x00, 0x00, 0x42].into()),
            gprs_node_indicator: None,
            additional_number: None,
        },
    };
    let map_bytes = rasn::ber::encode(&sri_sm_res).unwrap();

    // Build TCAP End with ReturnResult
    let rr = ReturnResult {
        invoke_id: 1,
        result: Some(ReturnResultValue {
            operation_code: OperationCode::Local(op_codes::SEND_ROUTING_INFO_FOR_SM),
            parameter: Some(rasn::types::Any::new(map_bytes)),
        }),
    };

    let end = End {
        dtid: vec![0x00, 0x00, 0x00, 0x01].into(),
        dialogue_portion: None,
        components: Some(vec![Component::ReturnResultLast(rr)]),
    };

    let tcap_bytes = tcap::encode(&TcapMessage::End(end)).unwrap();

    // Wrap in SCCP UDT
    let called = SccpAddress::with_ssn(SubsystemNumber::Msc, None);
    let calling = SccpAddress::with_ssn(SubsystemNumber::Hlr, None);
    let udt = UnitData::new(called, calling, tcap_bytes);
    let sccp_bytes = udt.encode().unwrap();

    // Wrap in M3UA
    let pd = ProtocolData::new(200, 100, 3, 2, 0, 0, sccp_bytes);
    let m3ua_bytes = M3uaMessage::data(None, Some(1), pd, None).encode();

    // Decode back
    let (pd, udt, tcap_bytes) = decode_to_tcap(&m3ua_bytes);
    assert_eq!(pd.opc, 200); // HLR
    assert_eq!(pd.dpc, 100); // SMS-SC
    assert_eq!(udt.called_party.ssn, Some(SubsystemNumber::Msc));

    let tcap_msg = tcap::decode(&tcap_bytes).unwrap();
    match tcap_msg {
        TcapMessage::End(e) => {
            assert_eq!(e.dtid.as_ref(), &[0, 0, 0, 1]);
        }
        _ => panic!("Expected TCAP End"),
    }
}

// ─── Test: MT-SMS Delivery ─────────────────────────────────────

/// Simulate: SMS-SC sends MT-ForwardSM to serving MSC.
#[test]
fn full_mt_forward_sm_through_stack() {
    let mt_arg = MtForwardSmArg {
        sm_rp_da: SmRpDa::Imsi(vec![0x09, 0x10, 0x10, 0x00, 0x00, 0x00, 0x00, 0x01].into()),
        sm_rp_oa: SmRpOa::ServiceCentreAddressOa(vec![0x91, 0x44, 0x77, 0x89, 0x01, 0x23].into()),
        sm_rp_ui: vec![
            0x04, 0x0B, 0x91, 0x13, 0x16, 0x32, 0x54, 0x76, 0xF8,
            0x00, 0x00, 0x21, 0x30, 0x11, 0x50, 0x00, 0x00, 0x0A,
            0xC8, 0x32, 0x9B, 0xFD, 0x06, 0xDD, 0xDF, 0x72, 0x36, 0x19,
        ].into(), // SMS-DELIVER TPDU with "Hello World"
        more_messages_to_send: None,
    };
    let map_bytes = rasn::ber::encode(&mt_arg).unwrap();

    let m3ua_bytes = build_map_request(
        op_codes::MT_FORWARD_SM,
        &map_bytes,
        &[0x00, 0x00, 0x00, 0x02],
        "31644332211",
        "31699887766",
        SubsystemNumber::Msc,
        SubsystemNumber::Msc,
        100, // SMS-SC
        300, // Serving MSC
    );

    let (pd, udt, _) = decode_to_tcap(&m3ua_bytes);
    assert_eq!(pd.dpc, 300); // MSC
    assert_eq!(udt.called_party.ssn, Some(SubsystemNumber::Msc));
}

// ─── Test: SCCP GT Translation (Mock STP) ──────────────────────

/// Simulate STP GT translation: incoming UDT with GT, translate to PC+SSN.
#[test]
fn mock_stp_gt_translation() {
    // Incoming: route on GT, digits = 31612345678, SSN = HLR
    let called_gt = GlobalTitle::Gt0100 {
        translation_type: 0,
        numbering_plan: 1,
        encoding_scheme: 1,
        nature_of_address: 4,
        digits: "31612345678".to_string(),
    };
    let called = SccpAddress::with_gt(called_gt, Some(SubsystemNumber::Hlr));
    let calling = SccpAddress::with_ssn(SubsystemNumber::Msc, None);

    let udt = UnitData::new(called, calling, vec![0x62, 0x00]); // dummy TCAP
    let sccp_bytes = udt.encode().unwrap();

    // STP decodes the SCCP message
    let decoded_udt = UnitData::decode(&sccp_bytes).unwrap();

    // STP performs GT translation:
    // Look up "31612345678" → DPC=200 (HLR), SSN=6
    let gt_digits = decoded_udt.called_party.global_title.digits().unwrap();
    assert_eq!(gt_digits, "31612345678");

    // Mock translation table
    struct GtTranslationEntry {
        prefix: &'static str,
        dpc: u32,
        ssn: SubsystemNumber,
    }

    let translation_table = vec![
        GtTranslationEntry { prefix: "3161", dpc: 200, ssn: SubsystemNumber::Hlr },
        GtTranslationEntry { prefix: "3168", dpc: 300, ssn: SubsystemNumber::Vlr },
    ];

    let matched = translation_table
        .iter()
        .find(|e| gt_digits.starts_with(e.prefix))
        .expect("No GT translation match");

    assert_eq!(matched.dpc, 200);
    assert_eq!(matched.ssn, SubsystemNumber::Hlr);

    // STP would now re-address and forward with route-on-SSN to DPC 200
    let translated = SccpAddress::with_ssn(matched.ssn, Some(matched.dpc as u16));
    assert!(translated.route_on_ssn);
    assert_eq!(translated.point_code, Some(200));
}

// ─── Test: M3UA ASP Lifecycle ──────────────────────────────────

/// Simulate full ASP lifecycle: ASPUP → ACK → ASPAC → ACK → DATA.
#[test]
fn m3ua_asp_lifecycle() {
    // 1. ASP sends ASPUP
    let aspup = M3uaMessage::asp_up(Some(42), Some("test-asp"));
    let aspup_bytes = aspup.encode();
    let decoded = M3uaMessage::decode(&aspup_bytes).unwrap();
    assert_eq!(decoded.message_type, m3ua::MessageType::AspUp);

    // 2. SGP responds with ASPUP ACK
    let aspup_ack = M3uaMessage::asp_up_ack(None);
    let ack_bytes = aspup_ack.encode();
    let decoded = M3uaMessage::decode(&ack_bytes).unwrap();
    assert_eq!(decoded.message_type, m3ua::MessageType::AspUpAck);

    // 3. ASP sends ASPAC (override mode, routing context 1)
    let aspac = M3uaMessage::asp_active(Some(1), Some(1));
    let aspac_bytes = aspac.encode();
    let decoded = M3uaMessage::decode(&aspac_bytes).unwrap();
    assert_eq!(decoded.message_type, m3ua::MessageType::AspActive);
    assert_eq!(decoded.routing_context(), Some(1));

    // 4. SGP responds with ASPAC ACK
    let aspac_ack = M3uaMessage::asp_active_ack(Some(1), Some(1));
    let ack_bytes = aspac_ack.encode();
    let decoded = M3uaMessage::decode(&ack_bytes).unwrap();
    assert_eq!(decoded.message_type, m3ua::MessageType::AspActiveAck);

    // 5. ASP sends DATA
    let pd = ProtocolData::new(100, 200, 3, 2, 0, 5, vec![0x09, 0x01, 0x03]);
    let data = M3uaMessage::data(None, Some(1), pd.clone(), None);
    let data_bytes = data.encode();
    let decoded = M3uaMessage::decode(&data_bytes).unwrap();
    assert_eq!(decoded.message_type, m3ua::MessageType::Data);
    let decoded_pd = decoded.protocol_data().unwrap();
    assert_eq!(decoded_pd.opc, 100);
    assert_eq!(decoded_pd.dpc, 200);
    assert_eq!(decoded_pd.user_data, vec![0x09, 0x01, 0x03]);

    // 6. Heartbeat exchange
    let beat = M3uaMessage::heartbeat(Some(vec![0xDE, 0xAD, 0xBE, 0xEF]));
    let beat_bytes = beat.encode();
    let decoded = M3uaMessage::decode(&beat_bytes).unwrap();
    assert_eq!(decoded.message_type, m3ua::MessageType::Heartbeat);

    let beat_ack = M3uaMessage::heartbeat_ack(Some(vec![0xDE, 0xAD, 0xBE, 0xEF]));
    let ack_bytes = beat_ack.encode();
    let decoded = M3uaMessage::decode(&ack_bytes).unwrap();
    assert_eq!(decoded.message_type, m3ua::MessageType::HeartbeatAck);
}

// ─── Test: Error Paths ─────────────────────────────────────────

/// M3UA DUNA — destination unavailable notification.
#[test]
fn m3ua_duna_notification() {
    let duna = M3uaMessage::duna(Some(1), vec![200, 300]);
    let bytes = duna.encode();
    let decoded = M3uaMessage::decode(&bytes).unwrap();
    assert_eq!(decoded.message_type, m3ua::MessageType::Duna);

    let apc = m3ua::parameter::find_parameter(
        &decoded.parameters,
        m3ua::tags::AFFECTED_POINT_CODE,
    ).unwrap();
    assert_eq!(apc.value.len(), 8); // 2 point codes × 4 bytes
}

/// TCAP Abort — transaction abort.
#[test]
fn tcap_abort() {
    let abort = tcap::Abort {
        dtid: vec![0x00, 0x00, 0x00, 0x01].into(),
        reason: None,
    };
    let msg = TcapMessage::Abort(abort);
    let bytes = tcap::encode(&msg).unwrap();
    let decoded = tcap::decode(&bytes).unwrap();
    match decoded {
        TcapMessage::Abort(a) => assert_eq!(a.dtid.as_ref(), &[0, 0, 0, 1]),
        _ => panic!("Expected Abort"),
    }
}

/// MAP error in TCAP ReturnError component.
#[test]
fn map_error_through_tcap() {
    let return_error = tcap::ReturnError {
        invoke_id: 1,
        error_code: tcap::ErrorCode::Local(
            gsm_map::operations::errors::error_codes::ABSENT_SUBSCRIBER as i64,
        ),
        parameter: None,
    };

    let end = End {
        dtid: vec![0x00, 0x00, 0x00, 0x01].into(),
        dialogue_portion: None,
        components: Some(vec![Component::ReturnError(return_error)]),
    };

    let bytes = tcap::encode(&TcapMessage::End(end)).unwrap();
    let decoded = tcap::decode(&bytes).unwrap();
    match decoded {
        TcapMessage::End(e) => {
            let comps = e.components.unwrap();
            match &comps[0] {
                Component::ReturnError(re) => {
                    assert_eq!(re.error_code, tcap::ErrorCode::Local(27));
                    assert_eq!(
                        gsm_map::operations::errors::error_name(27),
                        "absentSubscriber"
                    );
                }
                _ => panic!("Expected ReturnError"),
            }
        }
        _ => panic!("Expected End"),
    }
}

/// SCCP UDTS — return on error.
#[test]
fn sccp_return_on_error() {
    // Build a UDT that would fail at the destination
    let called = SccpAddress::with_ssn(SubsystemNumber::Hlr, None);
    let calling = SccpAddress::with_ssn(SubsystemNumber::Msc, None);
    let udt = UnitData::new(called, calling, vec![0x62, 0x00]);

    // Encode and decode to verify it survives the round trip
    let bytes = udt.encode().unwrap();
    let decoded = UnitData::decode(&bytes).unwrap();
    assert_eq!(decoded.protocol_class, 0);
}

// ─── Test: Mock HLR responds to UpdateLocation ────────────────

#[test]
fn mock_hlr_update_location() {
    // VLR sends updateLocation to HLR
    let ul_arg = UpdateLocationArg {
        imsi: vec![0x09, 0x10, 0x10, 0x00, 0x00, 0x00, 0x00, 0x01].into(),
        msc_number: vec![0x91, 0x44, 0x77, 0x12, 0x34, 0x56].into(),
        vlr_number: vec![0x91, 0x44, 0x77, 0x12, 0x34, 0x57].into(),
        lmsi: Some(vec![0x00, 0x00, 0x00, 0x01].into()),
        vlr_capability: None,
    };
    let map_bytes = rasn::ber::encode(&ul_arg).unwrap();

    // Mock HLR: decode the request
    let decoded_arg: UpdateLocationArg = rasn::ber::decode(&map_bytes).unwrap();
    assert_eq!(decoded_arg.imsi, ul_arg.imsi);

    // Mock HLR: send response
    let ul_res = UpdateLocationRes {
        hlr_number: vec![0x91, 0x44, 0x77, 0x89, 0x01, 0x23].into(),
    };
    let res_bytes = rasn::ber::encode(&ul_res).unwrap();
    let decoded_res: UpdateLocationRes = rasn::ber::decode(&res_bytes).unwrap();
    assert_eq!(decoded_res.hlr_number, ul_res.hlr_number);
}

// ─── Test: Mock HLR responds to SendAuthenticationInfo ─────────

#[test]
fn mock_hlr_send_auth_info() {
    let sai_arg = SendAuthenticationInfoArg {
        imsi: vec![0x09, 0x10, 0x10, 0x00, 0x00, 0x00, 0x00, 0x01].into(),
        number_of_requested_vectors: 3.into(),
        re_synchronisation_info: None,
        requesting_node_type: None,
    };
    let arg_bytes = rasn::ber::encode(&sai_arg).unwrap();
    let decoded: SendAuthenticationInfoArg = rasn::ber::decode(&arg_bytes).unwrap();
    assert_eq!(decoded.imsi, sai_arg.imsi);

    // Mock HLR generates 3 triplets
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
    let res_bytes = rasn::ber::encode(&res).unwrap();
    let decoded_res: SendAuthenticationInfoRes = rasn::ber::decode(&res_bytes).unwrap();
    match decoded_res.authentication_set_list.unwrap() {
        AuthenticationSetList::TripletList(t) => assert_eq!(t.len(), 3),
        _ => panic!("Expected TripletList"),
    }
}

// ─── Test: Mock gsmSCF handles CAP InitialDP ──────────────────

#[test]
fn mock_scf_initial_dp() {
    // gsmSSF sends initialDP to gsmSCF
    let idp = InitialDpArg {
        service_key: 100.into(),
        called_party_number: Some(vec![0x84, 0x13, 0x16, 0x32, 0x54, 0x76, 0xF8].into()),
        calling_party_number: Some(vec![0x84, 0x31, 0x61, 0x23, 0x45].into()),
        calling_partys_category: None,
        original_called_party_id: None,
        event_type_bcsm: Some(EventTypeBcsm::CollectedInfo),
        redirecting_party_id: None,
        imsi: Some(vec![0x09, 0x10, 0x10, 0x00, 0x00, 0x00, 0x00, 0x01].into()),
        location_information: None,
        call_reference_number: None,
        msc_address: Some(vec![0x91, 0x44, 0x77].into()),
        called_party_bcd_number: None,
        time_and_timezone: None,
    };
    let encoded = rasn::ber::encode(&idp).unwrap();
    let decoded: InitialDpArg = rasn::ber::decode(&encoded).unwrap();

    // Mock gsmSCF decision: connect to different number
    assert_eq!(decoded.event_type_bcsm, Some(EventTypeBcsm::CollectedInfo));

    let connect = ConnectArg {
        destination_routing_address: vec![
            vec![0x84, 0x44, 0x77, 0x89, 0x01, 0x23].into(),
        ],
        original_called_party_id: decoded.called_party_number.clone(),
        calling_partys_category: None,
        redirecting_party_id: None,
        generic_numbers: None,
    };
    let connect_bytes = rasn::ber::encode(&connect).unwrap();
    let decoded_connect: ConnectArg = rasn::ber::decode(&connect_bytes).unwrap();
    assert_eq!(decoded_connect.destination_routing_address.len(), 1);
}

// ─── Test: Application Context versioning ──────────────────────

#[test]
fn application_context_versioning() {
    let v1 = application_context::short_msg_gateway_context(application_context::V1);
    let v2 = application_context::short_msg_gateway_context(application_context::V2);
    let v3 = application_context::short_msg_gateway_context(application_context::V3);

    // All different
    assert_ne!(v1, v2);
    assert_ne!(v2, v3);
    assert_ne!(v1, v3);

    // v3 should end with ...20.3
    let v3_parts: Vec<u32> = v3.iter().copied().collect();
    assert_eq!(v3_parts.last(), Some(&3));

    // CAP contexts
    let cap_v3 = application_context::cap_gsmssf_scf_generic(application_context::CAP_V3);
    let cap_v4 = application_context::cap_gsmssf_scf_generic(application_context::CAP_V4);
    assert_ne!(cap_v3, cap_v4);
}

// ─── Test: Mock ATI (AnyTimeInterrogation) ─────────────────────

#[test]
fn mock_hlr_any_time_interrogation() {
    let ati_arg = AnyTimeInterrogationArg {
        subscriber_identity: SubscriberIdentity::Msisdn(
            vec![0x91, 0x13, 0x16, 0x32, 0x54, 0x76, 0xF8].into(),
        ),
        requested_info: RequestedInfo {
            location_information: Some(()),
            subscriber_state: Some(()),
            current_location: Some(()),
            imei: None,
            ms_classmark: None,
            mn_p_requested_info: None,
        },
        gsm_scf_address: vec![0x91, 0x44, 0x77, 0x89].into(),
    };
    let bytes = rasn::ber::encode(&ati_arg).unwrap();
    let decoded: AnyTimeInterrogationArg = rasn::ber::decode(&bytes).unwrap();

    // Mock HLR response
    let ati_res = gsm_map::operations::subscriber_info::AnyTimeInterrogationRes {
        subscriber_info: SubscriberInfo {
            location_information: None,
            subscriber_state: Some(
                gsm_map::operations::subscriber_info::SubscriberState::AssumedIdle,
            ),
            imei: None,
            ms_classmark2: None,
            gprs_ms_class: None,
            mn_p_info_res: None,
        },
    };
    let res_bytes = rasn::ber::encode(&ati_res).unwrap();
    let decoded_res: gsm_map::operations::subscriber_info::AnyTimeInterrogationRes =
        rasn::ber::decode(&res_bytes).unwrap();
    assert_eq!(
        decoded_res.subscriber_info.subscriber_state,
        Some(gsm_map::operations::subscriber_info::SubscriberState::AssumedIdle)
    );
}
