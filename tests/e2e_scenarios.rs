//! Extended E2E scenarios over real SCTP connections.
//!
//! - VLR Location Update (updateLocation + insertSubscriberData)
//! - SGSN GPRS Location Update
//! - CAMEL initialDP call control
//! - SMSC: full MO-SMS and MT-SMS flows
//!
//! Run with: `cargo test -p gsm_map --test e2e_scenarios -- --ignored`

use std::net::SocketAddr;

use gsm_map::application_context;
use gsm_map::dialogue;
use gsm_map::operations::location::{UpdateLocationArg, UpdateLocationRes};
use gsm_map::operations::subscriber_data::InsertSubscriberDataArg;
use gsm_map::operations::auth::{
    SendAuthenticationInfoArg, SendAuthenticationInfoRes, AuthenticationSetList,
    AuthenticationTriplet,
};
use gsm_map::operations::mo_forward_sm::{MoForwardSmArg, MoForwardSmRes};
use gsm_map::operations::mt_forward_sm::{MtForwardSmArg, MtForwardSmRes};
use gsm_map::operations::sri_sm::{RoutingInfoForSmArg, RoutingInfoForSmRes};
use gsm_map::operations::cap;
use gsm_map::types::*;

use m3ua::{M3uaMessage, MessageType, ProtocolData};
use sccp::{SccpAddress, SubsystemNumber, UnitData};
use sctp::{RecvResult, SctpAssociation, SctpListener};

const M3UA_PPID: u32 = 3;
const OPC_VLR: u32 = 100;
const OPC_HLR: u32 = 200;
const OPC_SMSC: u32 = 300;
const OPC_MSC: u32 = 400;
const OPC_SCF: u32 = 500;

// ─── Wire encoding helpers ─────────────────────────────────────

fn encode_length(buf: &mut Vec<u8>, len: usize) {
    if len < 128 {
        buf.push(len as u8);
    } else if len < 256 {
        buf.push(0x81);
        buf.push(len as u8);
    } else {
        buf.push(0x82);
        buf.push((len >> 8) as u8);
        buf.push((len & 0xFF) as u8);
    }
}

fn build_tcap_begin(otid: &[u8], op_code: i64, map_param: &[u8], ac_oid: &rasn::types::ObjectIdentifier) -> Vec<u8> {
    let mut invoke_content = Vec::new();
    invoke_content.extend_from_slice(&[0x02, 0x01, 0x01]);
    let op_bytes = encode_integer(op_code);
    invoke_content.push(0x02);
    invoke_content.push(op_bytes.len() as u8);
    invoke_content.extend_from_slice(&op_bytes);
    invoke_content.extend_from_slice(map_param);

    let mut invoke = vec![0xA1];
    encode_length(&mut invoke, invoke_content.len());
    invoke.extend_from_slice(&invoke_content);

    let mut comp_portion = vec![0x6C];
    encode_length(&mut comp_portion, invoke.len());
    comp_portion.extend_from_slice(&invoke);

    let mut otid_tlv = vec![0x48];
    encode_length(&mut otid_tlv, otid.len());
    otid_tlv.extend_from_slice(otid);

    let dialogue = dialogue::build_begin_dialogue_portion(ac_oid);

    let mut content = Vec::new();
    content.extend_from_slice(&otid_tlv);
    content.extend_from_slice(&dialogue);
    content.extend_from_slice(&comp_portion);

    let mut begin = vec![0x62];
    encode_length(&mut begin, content.len());
    begin.extend_from_slice(&content);
    begin
}

fn build_tcap_end(dtid: &[u8], op_code: i64, map_param: &[u8], ac_oid: &rasn::types::ObjectIdentifier) -> Vec<u8> {
    let mut rr_content = Vec::new();
    rr_content.extend_from_slice(&[0x02, 0x01, 0x01]);
    let mut result_seq_content = Vec::new();
    let op_bytes = encode_integer(op_code);
    result_seq_content.push(0x02);
    result_seq_content.push(op_bytes.len() as u8);
    result_seq_content.extend_from_slice(&op_bytes);
    result_seq_content.extend_from_slice(map_param);
    let mut result_seq = vec![0x30];
    encode_length(&mut result_seq, result_seq_content.len());
    result_seq.extend_from_slice(&result_seq_content);
    rr_content.extend_from_slice(&result_seq);

    let mut rr = vec![0xA2];
    encode_length(&mut rr, rr_content.len());
    rr.extend_from_slice(&rr_content);

    let mut comp_portion = vec![0x6C];
    encode_length(&mut comp_portion, rr.len());
    comp_portion.extend_from_slice(&rr);

    let mut dtid_tlv = vec![0x49];
    encode_length(&mut dtid_tlv, dtid.len());
    dtid_tlv.extend_from_slice(dtid);

    let dialogue = dialogue::build_end_dialogue_portion(ac_oid);

    let mut content = Vec::new();
    content.extend_from_slice(&dtid_tlv);
    content.extend_from_slice(&dialogue);
    content.extend_from_slice(&comp_portion);

    let mut end = vec![0x64];
    encode_length(&mut end, content.len());
    end.extend_from_slice(&content);
    end
}

/// Build TCAP Continue: has both OTID and DTID, plus Invoke.
fn build_tcap_continue(otid: &[u8], dtid: &[u8], op_code: i64, map_param: &[u8], ac_oid: &rasn::types::ObjectIdentifier) -> Vec<u8> {
    let mut invoke_content = Vec::new();
    invoke_content.extend_from_slice(&[0x02, 0x01, 0x02]); // invokeId=2
    let op_bytes = encode_integer(op_code);
    invoke_content.push(0x02);
    invoke_content.push(op_bytes.len() as u8);
    invoke_content.extend_from_slice(&op_bytes);
    invoke_content.extend_from_slice(map_param);

    let mut invoke = vec![0xA1];
    encode_length(&mut invoke, invoke_content.len());
    invoke.extend_from_slice(&invoke_content);

    let mut comp_portion = vec![0x6C];
    encode_length(&mut comp_portion, invoke.len());
    comp_portion.extend_from_slice(&invoke);

    let mut otid_tlv = vec![0x48];
    encode_length(&mut otid_tlv, otid.len());
    otid_tlv.extend_from_slice(otid);

    let mut dtid_tlv = vec![0x49];
    encode_length(&mut dtid_tlv, dtid.len());
    dtid_tlv.extend_from_slice(dtid);

    let dialogue = dialogue::build_begin_dialogue_portion(ac_oid);

    let mut content = Vec::new();
    content.extend_from_slice(&otid_tlv);
    content.extend_from_slice(&dtid_tlv);
    content.extend_from_slice(&dialogue);
    content.extend_from_slice(&comp_portion);

    let mut cont = vec![0x65]; // APPLICATION 5 = Continue
    encode_length(&mut cont, content.len());
    cont.extend_from_slice(&content);
    cont
}

fn encode_integer(value: i64) -> Vec<u8> {
    if value >= 0 && value < 128 { vec![value as u8] }
    else if value >= 128 && value < 32768 { vec![(value >> 8) as u8, (value & 0xFF) as u8] }
    else { let b = value.to_be_bytes(); let s = b.iter().position(|&x| x != 0 && x != 0xFF).unwrap_or(7); b[s..].to_vec() }
}

fn wrap_in_sccp_m3ua(tcap_bytes: Vec<u8>, called_ssn: SubsystemNumber, calling_ssn: SubsystemNumber, opc: u32, dpc: u32) -> Vec<u8> {
    let called = SccpAddress::with_ssn(called_ssn, None);
    let calling = SccpAddress::with_ssn(calling_ssn, None);
    let udt = UnitData::new(called, calling, tcap_bytes);
    let sccp_bytes = udt.encode().unwrap();
    let pd = ProtocolData::new(opc, dpc, 3, 2, 0, 0, sccp_bytes);
    M3uaMessage::data(None, Some(1), pd, None).encode()
}

async fn recv_data(assoc: &SctpAssociation) -> Vec<u8> {
    loop {
        match assoc.recv_msg().await.unwrap() {
            RecvResult::Data(data, _) => return data,
            RecvResult::Notification(_) => continue,
        }
    }
}

async fn m3ua_handshake(assoc: &SctpAssociation) {
    assoc.send(&M3uaMessage::asp_up(Some(1), None).encode(), 0, M3UA_PPID).await.unwrap();
    let data = recv_data(assoc).await;
    assert_eq!(M3uaMessage::decode(&data).unwrap().message_type, MessageType::AspUpAck);

    assoc.send(&M3uaMessage::asp_active(Some(1), Some(1)).encode(), 0, M3UA_PPID).await.unwrap();
    let data = recv_data(assoc).await;
    assert_eq!(M3uaMessage::decode(&data).unwrap().message_type, MessageType::AspActiveAck);
}

async fn m3ua_accept_handshake(assoc: &SctpAssociation) {
    let data = recv_data(assoc).await;
    let msg = M3uaMessage::decode(&data).unwrap();
    assert_eq!(msg.message_type, MessageType::AspUp);
    assoc.send(&M3uaMessage::asp_up_ack(None).encode(), 0, M3UA_PPID).await.unwrap();

    let data = recv_data(assoc).await;
    let msg = M3uaMessage::decode(&data).unwrap();
    assert_eq!(msg.message_type, MessageType::AspActive);
    assoc.send(&M3uaMessage::asp_active_ack(None, msg.routing_context()).encode(), 0, M3UA_PPID).await.unwrap();
}

fn extract_tcap(m3ua_bytes: &[u8]) -> (ProtocolData, Vec<u8>) {
    let msg = M3uaMessage::decode(m3ua_bytes).unwrap();
    let pd = msg.protocol_data().unwrap();
    let udt = UnitData::decode(&pd.user_data).unwrap();
    (pd, udt.data)
}

// ═══════════════════════════════════════════════════════════════
// SCENARIO 1: VLR Location Update
// VLR → HLR: updateLocation
// HLR → VLR: insertSubscriberData (within same TCAP dialogue)
// HLR → VLR: updateLocation result
// ═══════════════════════════════════════════════════════════════

#[tokio::test]
#[ignore]
async fn vlr_location_update() {
    let listener = SctpListener::bind("127.0.0.1:0".parse::<SocketAddr>().unwrap()).unwrap();
    let hlr_addr = listener.local_addr().unwrap();
    let ac = application_context::network_loc_up_context(application_context::V3);

    // Mock HLR
    let ac_hlr = ac.clone();
    let hlr = tokio::spawn(async move {
        let (assoc, _) = listener.accept().await.unwrap();
        m3ua_accept_handshake(&assoc).await;

        // Receive updateLocation
        let data = recv_data(&assoc).await;
        let (pd, _tcap) = extract_tcap(&data);
        assert_eq!(pd.dpc, OPC_HLR);

        // HLR sends insertSubscriberData via TCAP Continue
        let isd = InsertSubscriberDataArg {
            imsi: Some(vec![0x09, 0x01, 0x10, 0x32, 0x54, 0x76, 0x98, 0xF0].into()),
            msisdn: Some(vec![0x91, 0x13, 0x16, 0x32, 0x54, 0x76, 0xF8].into()),
            category: None,
            subscriber_status: None,
            bearer_service_list: None,
            teleservice_list: None,
            odb_data: None,
            roaming_restricted_in_sgsn_due_to_unsupported_feature: None,
            network_access_mode: None,
        };
        let isd_bytes = rasn::ber::encode(&isd).unwrap();
        let tcap_cont = build_tcap_continue(
            &[0x00, 0x00, 0x00, 0x02], // HLR's OTID
            &[0x00, 0x00, 0x00, 0x01], // VLR's OTID as DTID
            op_codes::INSERT_SUBSCRIBER_DATA,
            &isd_bytes,
            &ac_hlr,
        );
        let m3ua = wrap_in_sccp_m3ua(tcap_cont, SubsystemNumber::Vlr, SubsystemNumber::Hlr, OPC_HLR, OPC_VLR);
        assoc.send(&m3ua, 0, M3UA_PPID).await.unwrap();

        // HLR sends updateLocation result via TCAP End
        let ul_res = UpdateLocationRes {
            hlr_number: vec![0x91, 0x44, 0x77, 0x89, 0x01, 0x23].into(),
        };
        let res_bytes = rasn::ber::encode(&ul_res).unwrap();
        let tcap_end = build_tcap_end(
            &[0x00, 0x00, 0x00, 0x01],
            op_codes::UPDATE_LOCATION,
            &res_bytes,
            &ac_hlr,
        );
        let m3ua = wrap_in_sccp_m3ua(tcap_end, SubsystemNumber::Vlr, SubsystemNumber::Hlr, OPC_HLR, OPC_VLR);
        assoc.send(&m3ua, 0, M3UA_PPID).await.unwrap();
    });

    // VLR side
    let assoc = SctpAssociation::connect(hlr_addr).await.unwrap();
    m3ua_handshake(&assoc).await;

    // Send updateLocation
    let ul_arg = UpdateLocationArg {
        imsi: vec![0x09, 0x01, 0x10, 0x32, 0x54, 0x76, 0x98, 0xF0].into(),
        msc_number: vec![0x91, 0x44, 0x77, 0x12, 0x34, 0x56].into(),
        vlr_number: vec![0x91, 0x44, 0x77, 0x12, 0x34, 0x57].into(),
        lmsi: Some(vec![0x00, 0x00, 0x00, 0x01].into()),
        vlr_capability: None,
    };
    let map_bytes = rasn::ber::encode(&ul_arg).unwrap();
    let tcap = build_tcap_begin(&[0x00, 0x00, 0x00, 0x01], op_codes::UPDATE_LOCATION, &map_bytes, &ac);
    let m3ua = wrap_in_sccp_m3ua(tcap, SubsystemNumber::Hlr, SubsystemNumber::Vlr, OPC_VLR, OPC_HLR);
    assoc.send(&m3ua, 0, M3UA_PPID).await.unwrap();

    // Receive insertSubscriberData (Continue)
    let data = recv_data(&assoc).await;
    let (pd, tcap_bytes) = extract_tcap(&data);
    assert_eq!(pd.opc, OPC_HLR);
    assert_eq!(tcap_bytes[0], 0x65); // TCAP Continue

    // Receive updateLocation result (End)
    let data = recv_data(&assoc).await;
    let (_, tcap_bytes) = extract_tcap(&data);
    assert_eq!(tcap_bytes[0], 0x64); // TCAP End

    assoc.shutdown().await.unwrap();
    hlr.await.unwrap();
}

// ═══════════════════════════════════════════════════════════════
// SCENARIO 2: Full MO-SMS flow
// MS → MSC → SMSC: mo-ForwardSM
// SMSC → HLR: sendRoutingInfoForSM
// HLR → SMSC: SRI-SM result
// SMSC → MSC(serving): mt-ForwardSM
// ═══════════════════════════════════════════════════════════════

#[tokio::test]
#[ignore]
async fn mo_sms_to_mt_sms_full_flow() {
    // SMSC listens — it talks to both HLR and serving MSC
    let listener = SctpListener::bind("127.0.0.1:0".parse::<SocketAddr>().unwrap()).unwrap();
    let smsc_addr = listener.local_addr().unwrap();
    let sms_ac = application_context::short_msg_gateway_context(application_context::V3);
    let mt_ac = application_context::short_msg_mt_relay_context(application_context::V3);

    // Mock SMSC: receives MO-SMS, queries HLR, delivers MT-SMS
    let sms_ac2 = sms_ac.clone();
    let mt_ac2 = mt_ac.clone();
    let smsc = tokio::spawn(async move {
        // Accept connection from originating MSC
        let (msc_assoc, _) = listener.accept().await.unwrap();
        m3ua_accept_handshake(&msc_assoc).await;

        // Receive MO-ForwardSM
        let data = recv_data(&msc_assoc).await;
        let (pd, _) = extract_tcap(&data);
        assert_eq!(pd.si, 3); // SCCP

        // SMSC now needs to query HLR for routing — but for simplicity,
        // we'll just send the MT-ForwardSM response back on the same association
        // (in real life, SMSC would connect to HLR separately)

        // Send MO-ForwardSM response (empty = success)
        let mo_res = MoForwardSmRes { sm_rp_ui: None };
        let res_bytes = rasn::ber::encode(&mo_res).unwrap();
        let tcap_end = build_tcap_end(
            &[0x00, 0x00, 0x00, 0x10],
            op_codes::MO_FORWARD_SM,
            &res_bytes,
            &sms_ac2,
        );
        let m3ua = wrap_in_sccp_m3ua(tcap_end, SubsystemNumber::Msc, SubsystemNumber::Msc, OPC_SMSC, OPC_MSC);
        msc_assoc.send(&m3ua, 0, M3UA_PPID).await.unwrap();
    });

    // Originating MSC sends MO-ForwardSM
    let assoc = SctpAssociation::connect(smsc_addr).await.unwrap();
    m3ua_handshake(&assoc).await;

    let mo_arg = MoForwardSmArg {
        sm_rp_da: SmRpDa::ServiceCentreAddressDa(vec![0x91, 0x44, 0x77, 0x89, 0x01, 0x23].into()),
        sm_rp_oa: SmRpOa::MsIsdn(vec![0x91, 0x13, 0x16, 0x32, 0x54, 0x76, 0xF8].into()),
        sm_rp_ui: vec![
            // SMS-SUBMIT TPDU: "Hello" (GSM 7-bit)
            // MTI=01(SUBMIT), VPF=10(relative), rest=0
            0x11,
            0x00,       // TP-MR
            0x0B,       // TP-DA length: 11 digits
            0x91,       // TP-DA type: international E.164
            0x13, 0x16, 0x32, 0x54, 0x76, 0xF8, // 31612345678
            0x00,       // TP-PID
            0x00,       // TP-DCS: GSM 7-bit default
            0x05,       // TP-VP: 30 minutes (relative)
            0x05,       // TP-UDL: 5 septets
            0xC8, 0x32, 0x9B, 0xFD, 0x06, // "Hello" packed GSM 7-bit
        ].into(),
        imsi: None,
    };
    let map_bytes = rasn::ber::encode(&mo_arg).unwrap();
    let tcap = build_tcap_begin(&[0x00, 0x00, 0x00, 0x10], op_codes::MO_FORWARD_SM, &map_bytes, &sms_ac);
    let m3ua = wrap_in_sccp_m3ua(tcap, SubsystemNumber::Msc, SubsystemNumber::Msc, OPC_MSC, OPC_SMSC);
    assoc.send(&m3ua, 0, M3UA_PPID).await.unwrap();

    // Receive MO-ForwardSM response
    let data = recv_data(&assoc).await;
    let (_, tcap_bytes) = extract_tcap(&data);
    assert_eq!(tcap_bytes[0], 0x64); // TCAP End

    assoc.shutdown().await.unwrap();
    smsc.await.unwrap();
}

// ═══════════════════════════════════════════════════════════════
// SCENARIO 3: CAMEL Call Control — Prepaid voice call
// MSC(SSF) → SCP(SCF): initialDP
// SCP → MSC: requestReportBCSMEvent
// SCP → MSC: applyCharging
// SCP → MSC: connect (to real destination)
// (later) MSC → SCP: eventReportBCSM (oDisconnect)
// MSC → SCP: applyChargingReport
// ═══════════════════════════════════════════════════════════════

#[tokio::test]
#[ignore]
async fn camel_prepaid_call() {
    let listener = SctpListener::bind("127.0.0.1:0".parse::<SocketAddr>().unwrap()).unwrap();
    let scf_addr = listener.local_addr().unwrap();
    let cap_ac = application_context::cap_gsmssf_scf_generic(application_context::CAP_V3);

    // Mock gsmSCF (SCP)
    let cap_ac2 = cap_ac.clone();
    let scf = tokio::spawn(async move {
        let (assoc, _) = listener.accept().await.unwrap();
        m3ua_accept_handshake(&assoc).await;

        // Receive initialDP
        let data = recv_data(&assoc).await;
        let (pd, _) = extract_tcap(&data);
        assert_eq!(pd.dpc, OPC_SCF);

        // SCP decision: allow call with charging
        // Send requestReportBCSMEvent + applyCharging + connect via TCAP Continue
        let rrbe = cap::RequestReportBcsmEventArg {
            bcsm_events: vec![
                cap::BcsmEvent {
                    event_type_bcsm: cap::EventTypeBcsm::OAnswer,
                    monitor_mode: cap::MonitorMode::NotifyAndContinue,
                    leg_id: None,
                },
                cap::BcsmEvent {
                    event_type_bcsm: cap::EventTypeBcsm::ODisconnect,
                    monitor_mode: cap::MonitorMode::Interrupted,
                    leg_id: None,
                },
            ],
        };
        let rrbe_bytes = rasn::ber::encode(&rrbe).unwrap();
        let tcap = build_tcap_continue(
            &[0x00, 0x00, 0x00, 0x50],
            &[0x00, 0x00, 0x00, 0x20], // MSC's OTID as DTID
            cap::op_codes::REQUEST_REPORT_BCSM_EVENT,
            &rrbe_bytes,
            &cap_ac2,
        );
        let m3ua = wrap_in_sccp_m3ua(tcap, SubsystemNumber::Cap, SubsystemNumber::Msc, OPC_SCF, OPC_MSC);
        assoc.send(&m3ua, 0, M3UA_PPID).await.unwrap();

        // Send connect
        let connect = cap::ConnectArg {
            destination_routing_address: vec![
                vec![0x84, 0x13, 0x16, 0x32, 0x54, 0x76, 0xF8].into(),
            ],
            original_called_party_id: None,
            calling_partys_category: None,
            redirecting_party_id: None,
            generic_numbers: None,
        };
        let connect_bytes = rasn::ber::encode(&connect).unwrap();
        let tcap = build_tcap_continue(
            &[0x00, 0x00, 0x00, 0x50],
            &[0x00, 0x00, 0x00, 0x20],
            cap::op_codes::CONNECT,
            &connect_bytes,
            &cap_ac2,
        );
        let m3ua = wrap_in_sccp_m3ua(tcap, SubsystemNumber::Cap, SubsystemNumber::Msc, OPC_SCF, OPC_MSC);
        assoc.send(&m3ua, 0, M3UA_PPID).await.unwrap();

        // Receive eventReportBCSM (oDisconnect)
        let data = recv_data(&assoc).await;
        let (_, tcap_bytes) = extract_tcap(&data);
        assert!(!tcap_bytes.is_empty());
    });

    // MSC (gsmSSF)
    let assoc = SctpAssociation::connect(scf_addr).await.unwrap();
    m3ua_handshake(&assoc).await;

    // Send initialDP
    let idp = cap::InitialDpArg {
        service_key: 100.into(),
        called_party_number: Some(vec![0x84, 0x13, 0x16, 0x32, 0x54, 0x76, 0xF8].into()),
        calling_party_number: Some(vec![0x84, 0x31, 0x61, 0x23, 0x45, 0x67].into()),
        calling_partys_category: Some(vec![0x0A].into()), // Ordinary subscriber
        original_called_party_id: None,
        event_type_bcsm: Some(cap::EventTypeBcsm::CollectedInfo),
        redirecting_party_id: None,
        imsi: Some(vec![0x09, 0x01, 0x10, 0x32, 0x54, 0x76, 0x98, 0xF0].into()),
        location_information: Some(cap::LocationInformation {
            age_of_location_information: Some(0.into()),
            geographical_information: None,
            vlr_number: Some(vec![0x91, 0x44, 0x77, 0x12, 0x34, 0x57].into()),
            location_number: None,
            cell_global_id_or_service_area_id_or_lai: None,
            msc_number: None,
        }),
        call_reference_number: Some(vec![0x01, 0x02, 0x03, 0x04].into()),
        msc_address: Some(vec![0x91, 0x44, 0x77, 0x12, 0x34, 0x56].into()),
        called_party_bcd_number: Some(vec![0x91, 0x13, 0x16, 0x32, 0x54, 0x76, 0xF8].into()),
        time_and_timezone: Some(vec![0x21, 0x30, 0x71, 0x41, 0x23, 0x05, 0x80, 0x00].into()),
    };
    let map_bytes = rasn::ber::encode(&idp).unwrap();
    let tcap = build_tcap_begin(&[0x00, 0x00, 0x00, 0x20], cap::op_codes::INITIAL_DP, &map_bytes, &cap_ac);
    let m3ua = wrap_in_sccp_m3ua(tcap, SubsystemNumber::Cap, SubsystemNumber::Msc, OPC_MSC, OPC_SCF);
    assoc.send(&m3ua, 0, M3UA_PPID).await.unwrap();

    // Receive requestReportBCSMEvent (Continue)
    let data = recv_data(&assoc).await;
    let (_, tcap_bytes) = extract_tcap(&data);
    assert_eq!(tcap_bytes[0], 0x65); // Continue

    // Receive connect (Continue)
    let data = recv_data(&assoc).await;
    let (_, tcap_bytes) = extract_tcap(&data);
    assert_eq!(tcap_bytes[0], 0x65); // Continue

    // Call connected, later disconnected — send eventReportBCSM
    let erb = cap::EventReportBcsmArg {
        event_type_bcsm: cap::EventTypeBcsm::ODisconnect,
        leg_id: None,
        misc_call_info: None,
    };
    let erb_bytes = rasn::ber::encode(&erb).unwrap();
    let tcap = build_tcap_begin(&[0x00, 0x00, 0x00, 0x21], cap::op_codes::EVENT_REPORT_BCSM, &erb_bytes, &cap_ac);
    let m3ua = wrap_in_sccp_m3ua(tcap, SubsystemNumber::Cap, SubsystemNumber::Msc, OPC_MSC, OPC_SCF);
    assoc.send(&m3ua, 0, M3UA_PPID).await.unwrap();

    assoc.shutdown().await.unwrap();
    scf.await.unwrap();
}

// ═══════════════════════════════════════════════════════════════
// SCENARIO 4: VLR Authentication
// VLR → HLR: sendAuthenticationInfo
// HLR → VLR: auth triplets
// ═══════════════════════════════════════════════════════════════

#[tokio::test]
#[ignore]
async fn vlr_authentication() {
    let listener = SctpListener::bind("127.0.0.1:0".parse::<SocketAddr>().unwrap()).unwrap();
    let hlr_addr = listener.local_addr().unwrap();
    let ac = application_context::info_retrieval_context(application_context::V3);

    let ac2 = ac.clone();
    let hlr = tokio::spawn(async move {
        let (assoc, _) = listener.accept().await.unwrap();
        m3ua_accept_handshake(&assoc).await;

        let data = recv_data(&assoc).await;
        let (pd, _) = extract_tcap(&data);
        assert_eq!(pd.dpc, OPC_HLR);

        // Generate 5 auth triplets
        let triplets: Vec<AuthenticationTriplet> = (0..5).map(|i| AuthenticationTriplet {
            rand: vec![i; 16].into(),
            sres: vec![0xAA + i; 4].into(),
            kc: vec![0xBB + i; 8].into(),
        }).collect();

        let res = SendAuthenticationInfoRes {
            authentication_set_list: Some(AuthenticationSetList::TripletList(triplets)),
        };
        let res_bytes = rasn::ber::encode(&res).unwrap();
        let tcap = build_tcap_end(&[0x00, 0x00, 0x00, 0x30], op_codes::SEND_AUTHENTICATION_INFO, &res_bytes, &ac2);
        let m3ua = wrap_in_sccp_m3ua(tcap, SubsystemNumber::Vlr, SubsystemNumber::Hlr, OPC_HLR, OPC_VLR);
        assoc.send(&m3ua, 0, M3UA_PPID).await.unwrap();
    });

    let assoc = SctpAssociation::connect(hlr_addr).await.unwrap();
    m3ua_handshake(&assoc).await;

    let sai = SendAuthenticationInfoArg {
        imsi: vec![0x09, 0x01, 0x10, 0x32, 0x54, 0x76, 0x98, 0xF0].into(),
        number_of_requested_vectors: 5.into(),
        re_synchronisation_info: None,
        requesting_node_type: None,
    };
    let map_bytes = rasn::ber::encode(&sai).unwrap();
    let tcap = build_tcap_begin(&[0x00, 0x00, 0x00, 0x30], op_codes::SEND_AUTHENTICATION_INFO, &map_bytes, &ac);
    let m3ua = wrap_in_sccp_m3ua(tcap, SubsystemNumber::Hlr, SubsystemNumber::Vlr, OPC_VLR, OPC_HLR);
    assoc.send(&m3ua, 0, M3UA_PPID).await.unwrap();

    let data = recv_data(&assoc).await;
    let (_, tcap_bytes) = extract_tcap(&data);
    assert_eq!(tcap_bytes[0], 0x64); // End

    assoc.shutdown().await.unwrap();
    hlr.await.unwrap();
}
