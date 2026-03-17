//! End-to-end test: two SCTP endpoints exchange real MAP messages
//! through the full protocol stack.
//!
//! SMS-SC ←→ HLR over SCTP/M3UA/SCCP/TCAP/MAP
//!
//! Requires kernel SCTP support (`modprobe sctp`).
//! Run with: `cargo test -p gsm_map --test e2e -- --ignored`

use std::net::SocketAddr;

use gsm_map::application_context;
use gsm_map::dialogue;
use gsm_map::operations::sri_sm::{RoutingInfoForSmArg, RoutingInfoForSmRes};
use gsm_map::types::*;

use m3ua::{M3uaMessage, MessageType, ProtocolData};
use sccp::{GlobalTitle, SccpAddress, SubsystemNumber, UnitData};
use sctp::{RecvResult, SctpAssociation, SctpListener};

const M3UA_PPID: u32 = 3;

/// Build a TCAP Begin with dialogue portion and invoke, manually.
/// This produces wire-correct bytes that Wireshark can fully decode.
fn build_tcap_begin(otid: &[u8], op_code: i64, map_param: &[u8], ac_oid: &rasn::types::ObjectIdentifier) -> Vec<u8> {
    // Invoke component: [CONTEXT 1 CONSTRUCTED]
    let mut invoke_content = Vec::new();
    // InvokeID: INTEGER
    invoke_content.extend_from_slice(&[0x02, 0x01, 0x01]); // invokeId = 1
    // OperationCode: [0] IMPLICIT INTEGER (local)
    let op_bytes = encode_integer(op_code);
    invoke_content.push(0x02); // INTEGER tag
    invoke_content.push(op_bytes.len() as u8);
    invoke_content.extend_from_slice(&op_bytes);
    // MAP parameter (already a SEQUENCE)
    invoke_content.extend_from_slice(map_param);

    let mut invoke = vec![0xA1]; // CONTEXT 1 CONSTRUCTED
    encode_length(&mut invoke, invoke_content.len());
    invoke.extend_from_slice(&invoke_content);

    // Component portion: [APPLICATION 12 CONSTRUCTED] = 0x6C
    let mut comp_portion = vec![0x6C];
    encode_length(&mut comp_portion, invoke.len());
    comp_portion.extend_from_slice(&invoke);

    // OTID: [APPLICATION 8 PRIMITIVE] = 0x48
    let mut otid_tlv = vec![0x48];
    encode_length(&mut otid_tlv, otid.len());
    otid_tlv.extend_from_slice(otid);

    // Dialogue portion
    let dialogue = dialogue::build_begin_dialogue_portion(ac_oid);

    // Begin: [APPLICATION 2 CONSTRUCTED] = 0x62
    let mut begin_content = Vec::new();
    begin_content.extend_from_slice(&otid_tlv);
    begin_content.extend_from_slice(&dialogue);
    begin_content.extend_from_slice(&comp_portion);

    let mut begin = vec![0x62];
    encode_length(&mut begin, begin_content.len());
    begin.extend_from_slice(&begin_content);

    begin
}

/// Build a TCAP End with dialogue portion and return result, manually.
fn build_tcap_end(dtid: &[u8], op_code: i64, map_param: &[u8], ac_oid: &rasn::types::ObjectIdentifier) -> Vec<u8> {
    // ReturnResult: [CONTEXT 2 CONSTRUCTED] = 0xA2
    let mut rr_content = Vec::new();
    // InvokeID
    rr_content.extend_from_slice(&[0x02, 0x01, 0x01]);
    // SEQUENCE { operationCode, parameter }
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

    let mut rr = vec![0xA2]; // ReturnResultLast
    encode_length(&mut rr, rr_content.len());
    rr.extend_from_slice(&rr_content);

    // Component portion
    let mut comp_portion = vec![0x6C];
    encode_length(&mut comp_portion, rr.len());
    comp_portion.extend_from_slice(&rr);

    // DTID: [APPLICATION 9 PRIMITIVE] = 0x49
    let mut dtid_tlv = vec![0x49];
    encode_length(&mut dtid_tlv, dtid.len());
    dtid_tlv.extend_from_slice(dtid);

    // Dialogue portion
    let dialogue = dialogue::build_end_dialogue_portion(ac_oid);

    // End: [APPLICATION 4 CONSTRUCTED] = 0x64
    let mut end_content = Vec::new();
    end_content.extend_from_slice(&dtid_tlv);
    end_content.extend_from_slice(&dialogue);
    end_content.extend_from_slice(&comp_portion);

    let mut end = vec![0x64];
    encode_length(&mut end, end_content.len());
    end.extend_from_slice(&end_content);

    end
}

fn encode_integer(value: i64) -> Vec<u8> {
    if value >= 0 && value < 128 {
        vec![value as u8]
    } else if value >= 0 && value < 32768 {
        vec![(value >> 8) as u8, (value & 0xFF) as u8]
    } else {
        let bytes = value.to_be_bytes();
        let start = bytes.iter().position(|&b| b != 0 && b != 0xFF).unwrap_or(7);
        bytes[start..].to_vec()
    }
}

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

/// Full end-to-end: SMS-SC sends MAP SRI-SM to mock HLR over SCTP.
#[tokio::test]
#[ignore]
async fn smsc_to_hlr_sri_sm_over_sctp() {
    let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let listener = SctpListener::bind(addr).unwrap();
    let hlr_addr = listener.local_addr().unwrap();
    let ac = application_context::short_msg_gateway_context(application_context::V3);

    // ─── Mock HLR ──────────────────────────────────────────
    let ac_hlr = ac.clone();
    let hlr = tokio::spawn(async move {
        let (assoc, _peer) = listener.accept().await.unwrap();

        // Receive ASPUP, send ACK
        let data = recv_data(&assoc).await;
        let msg = M3uaMessage::decode(&data).unwrap();
        assert_eq!(msg.message_type, MessageType::AspUp);
        assoc.send(&M3uaMessage::asp_up_ack(None).encode(), 0, M3UA_PPID).await.unwrap();

        // Receive ASPAC, send ACK
        let data = recv_data(&assoc).await;
        let msg = M3uaMessage::decode(&data).unwrap();
        assert_eq!(msg.message_type, MessageType::AspActive);
        assoc.send(&M3uaMessage::asp_active_ack(None, msg.routing_context()).encode(), 0, M3UA_PPID).await.unwrap();

        // Receive DATA (MAP SRI-SM request)
        let data = recv_data(&assoc).await;
        let msg = M3uaMessage::decode(&data).unwrap();
        assert_eq!(msg.message_type, MessageType::Data);
        let pd = msg.protocol_data().unwrap();
        let request_opc = pd.opc;
        let request_dpc = pd.dpc;

        // Decode SCCP
        let udt = UnitData::decode(&pd.user_data).unwrap();
        assert_eq!(udt.called_party.ssn, Some(SubsystemNumber::Hlr));

        // Build MAP SRI-SM response
        let sri_res = RoutingInfoForSmRes {
            imsi: vec![0x09, 0x01, 0x10, 0x32, 0x54, 0x76, 0x98, 0xF0].into(),
            location_info_with_lmsi: LocationInfoWithLmsi {
                network_node_number: vec![0x91, 0x44, 0x77, 0x12, 0x34, 0x56].into(),
                lmsi: Some(vec![0x00, 0x00, 0x00, 0x42].into()),
                gprs_node_indicator: None,
                additional_number: None,
            },
        };
        let map_bytes = rasn::ber::encode(&sri_res).unwrap();

        // Build wire-correct TCAP End
        let tcap_bytes = build_tcap_end(
            &[0x00, 0x00, 0x00, 0x01], // DTID = requester's OTID
            op_codes::SEND_ROUTING_INFO_FOR_SM,
            &map_bytes,
            &ac_hlr,
        );

        // Wrap in SCCP (swap called/calling)
        let called = SccpAddress::with_ssn(SubsystemNumber::Msc, None);
        let calling = SccpAddress::with_ssn(SubsystemNumber::Hlr, None);
        let udt = UnitData::new(called, calling, tcap_bytes);
        let sccp_bytes = udt.encode().unwrap();

        // Wrap in M3UA DATA (swap OPC/DPC)
        let resp_pd = ProtocolData::new(request_dpc, request_opc, 3, 2, 0, 0, sccp_bytes);
        let resp = M3uaMessage::data(None, None, resp_pd, None);
        assoc.send(&resp.encode(), 0, M3UA_PPID).await.unwrap();
    });

    // ─── SMS-SC (client side) ──────────────────────────────
    tokio::task::yield_now().await;

    let assoc = SctpAssociation::connect(hlr_addr).await.unwrap();

    // M3UA handshake
    assoc.send(&M3uaMessage::asp_up(Some(1), None).encode(), 0, M3UA_PPID).await.unwrap();
    let data = recv_data(&assoc).await;
    assert_eq!(M3uaMessage::decode(&data).unwrap().message_type, MessageType::AspUpAck);

    assoc.send(&M3uaMessage::asp_active(Some(1), Some(1)).encode(), 0, M3UA_PPID).await.unwrap();
    let data = recv_data(&assoc).await;
    assert_eq!(M3uaMessage::decode(&data).unwrap().message_type, MessageType::AspActiveAck);

    // Build MAP SRI-SM request
    let sri_arg = RoutingInfoForSmArg {
        msisdn: vec![0x91, 0x13, 0x16, 0x32, 0x54, 0x76, 0xF8].into(),
        sm_rp_pri: true,
        service_centre_address: vec![0x91, 0x44, 0x77, 0x89, 0x01, 0x23].into(),
        gprs_support_indicator: None,
        sm_rp_mti: None,
        sm_rp_smea: None,
    };
    let map_bytes = rasn::ber::encode(&sri_arg).unwrap();

    // Build wire-correct TCAP Begin with dialogue portion
    let tcap_bytes = build_tcap_begin(
        &[0x00, 0x00, 0x00, 0x01],
        op_codes::SEND_ROUTING_INFO_FOR_SM,
        &map_bytes,
        &ac,
    );

    // Wrap in SCCP UDT
    let called_gt = GlobalTitle::Gt0100 {
        translation_type: 0,
        numbering_plan: 1,
        encoding_scheme: 1,
        nature_of_address: 4,
        digits: "31612345678".to_string(),
    };
    let called = SccpAddress::with_gt(called_gt, Some(SubsystemNumber::Hlr));
    let calling = SccpAddress::with_ssn(SubsystemNumber::Msc, None);
    let udt = UnitData::new(called, calling, tcap_bytes);
    let sccp_bytes = udt.encode().unwrap();

    // Wrap in M3UA DATA
    let pd = ProtocolData::new(100, 200, 3, 2, 0, 0, sccp_bytes);
    assoc.send(&M3uaMessage::data(None, Some(1), pd, None).encode(), 0, M3UA_PPID).await.unwrap();

    // Receive and verify response
    let resp_bytes = recv_data(&assoc).await;
    let resp = M3uaMessage::decode(&resp_bytes).unwrap();
    assert_eq!(resp.message_type, MessageType::Data);

    let resp_pd = resp.protocol_data().unwrap();
    assert_eq!(resp_pd.opc, 200); // HLR
    assert_eq!(resp_pd.dpc, 100); // SMS-SC
    assert_eq!(resp_pd.si, 3);    // SCCP

    let resp_udt = UnitData::decode(&resp_pd.user_data).unwrap();
    assert_eq!(resp_udt.called_party.ssn, Some(SubsystemNumber::Msc));
    assert_eq!(resp_udt.calling_party.ssn, Some(SubsystemNumber::Hlr));

    // Verify TCAP End tag
    assert_eq!(resp_udt.data[0], 0x64, "Expected TCAP End tag");

    assoc.shutdown().await.unwrap();
    hlr.await.unwrap();
}

/// Helper: receive data from SCTP, skipping notifications.
async fn recv_data(assoc: &SctpAssociation) -> Vec<u8> {
    loop {
        match assoc.recv_msg().await.unwrap() {
            RecvResult::Data(data, _info) => return data,
            RecvResult::Notification(_) => continue,
        }
    }
}
