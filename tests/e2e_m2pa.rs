//! End-to-end test: M2PA link alignment + MTP3 MSU exchange over SCTP.
//!
//! Two nodes establish an M2PA link (alignment → proving → ready → in service),
//! then exchange MTP3 MSUs carrying SCCP/TCAP/MAP.
//!
//! Run with: `cargo test -p gsm_map --test e2e_m2pa -- --ignored`

use std::net::SocketAddr;

use gsm_map::application_context;
use gsm_map::dialogue;
use gsm_map::operations::sri_sm::RoutingInfoForSmArg;
use gsm_map::types::*;

use m2pa::*;
use mtp3::*;
use sccp::{SccpAddress, SubsystemNumber, UnitData};
use sctp::{RecvResult, SctpAssociation, SctpListener};

const M2PA_PPID: u32 = 5;

fn wrap_dialogue_portion(external: &[u8]) -> Vec<u8> {
    let mut dp = vec![0x6B];
    encode_length(&mut dp, external.len());
    dp.extend_from_slice(external);
    dp
}

fn encode_length(buf: &mut Vec<u8>, len: usize) {
    if len < 128 { buf.push(len as u8); }
    else if len < 256 { buf.push(0x81); buf.push(len as u8); }
    else { buf.push(0x82); buf.push((len >> 8) as u8); buf.push((len & 0xFF) as u8); }
}

fn build_tcap_begin(otid: &[u8], op_code: i64, map_param: &[u8], ac_oid: &rasn::types::ObjectIdentifier) -> Vec<u8> {
    let mut invoke_content = Vec::new();
    invoke_content.extend_from_slice(&[0x02, 0x01, 0x01]);
    invoke_content.push(0x02);
    invoke_content.push(0x01);
    invoke_content.push(op_code as u8);
    invoke_content.extend_from_slice(map_param);
    let mut invoke = vec![0xA1];
    encode_length(&mut invoke, invoke_content.len());
    invoke.extend_from_slice(&invoke_content);
    let mut comp = vec![0x6C];
    encode_length(&mut comp, invoke.len());
    comp.extend_from_slice(&invoke);
    let mut otid_tlv = vec![0x48];
    encode_length(&mut otid_tlv, otid.len());
    otid_tlv.extend_from_slice(otid);
    let dialogue = wrap_dialogue_portion(&dialogue::build_begin_dialogue(ac_oid));
    let mut content = Vec::new();
    content.extend_from_slice(&otid_tlv);
    content.extend_from_slice(&dialogue);
    content.extend_from_slice(&comp);
    let mut begin = vec![0x62];
    encode_length(&mut begin, content.len());
    begin.extend_from_slice(&content);
    begin
}

async fn recv_m2pa(assoc: &SctpAssociation) -> Vec<u8> {
    loop {
        match assoc.recv_msg().await.unwrap() {
            RecvResult::Data(data, _) => return data,
            RecvResult::Notification(_) => continue,
        }
    }
}

/// Send an M2PA Link Status message over SCTP stream 0.
async fn send_link_status(assoc: &SctpAssociation, state: LinkState, bsn: u32, fsn: u32) {
    let msg = M2paMessage::LinkStatus {
        bsn,
        fsn,
        message: LinkStatusMessage::new(state),
    };
    let bytes = msg.encode().unwrap();
    assoc.send(&bytes, LinkStatusMessage::SCTP_STREAM, M2PA_PPID).await.unwrap();
}

/// Send an M2PA User Data message (carrying an MTP3 MSU) over SCTP stream 1.
async fn send_user_data(assoc: &SctpAssociation, msu_bytes: &[u8], bsn: u32, fsn: u32) {
    let msg = M2paMessage::UserData {
        bsn,
        fsn,
        message: UserDataMessage::new(0, msu_bytes.to_vec()),
    };
    let bytes = msg.encode().unwrap();
    assoc.send(&bytes, UserDataMessage::SCTP_STREAM, M2PA_PPID).await.unwrap();
}

/// Full M2PA link alignment sequence.
/// Returns when both sides reach In Service.
async fn do_alignment(assoc: &SctpAssociation, initiator: bool) {
    let initial_bsn = 0xFFFFFF;
    let initial_fsn = 0xFFFFFF;

    if initiator {
        // Send Alignment
        send_link_status(assoc, LinkState::Alignment, initial_bsn, initial_fsn).await;
    }

    // Wait for peer's Alignment
    let data = recv_m2pa(assoc).await;
    let msg = M2paMessage::decode(&data).unwrap();
    match &msg {
        M2paMessage::LinkStatus { message, .. } => {
            assert_eq!(message.state, LinkState::Alignment);
        }
        _ => panic!("Expected Link Status Alignment"),
    }

    if !initiator {
        // Respond with Alignment
        send_link_status(assoc, LinkState::Alignment, initial_bsn, initial_fsn).await;
    }

    // Send Proving Normal
    send_link_status(assoc, LinkState::ProvingNormal, initial_bsn, initial_fsn).await;

    // Receive peer's Proving
    let data = recv_m2pa(assoc).await;
    let msg = M2paMessage::decode(&data).unwrap();
    match &msg {
        M2paMessage::LinkStatus { message, .. } => {
            assert!(
                message.state == LinkState::ProvingNormal
                    || message.state == LinkState::ProvingEmergency
            );
        }
        _ => panic!("Expected Link Status Proving"),
    }

    // Send Ready
    send_link_status(assoc, LinkState::Ready, initial_bsn, initial_fsn).await;

    // Receive peer's Ready
    let data = recv_m2pa(assoc).await;
    let msg = M2paMessage::decode(&data).unwrap();
    match &msg {
        M2paMessage::LinkStatus { message, .. } => {
            assert_eq!(message.state, LinkState::Ready);
        }
        _ => panic!("Expected Link Status Ready"),
    }
}

/// Full end-to-end: M2PA alignment + MTP3 MSU with MAP SRI-SM.
///
/// Node A (SMS-SC, PC=100) ←M2PA/SCTP→ Node B (STP/HLR, PC=200)
///
/// 1. SCTP association established
/// 2. M2PA link alignment: Alignment → Proving Normal → Ready
/// 3. Node A sends MTP3 MSU with SCCP UDT containing MAP SRI-SM
/// 4. Node B receives and decodes the full stack
#[tokio::test]
#[ignore]
async fn m2pa_alignment_and_msu_exchange() {
    let listener = SctpListener::bind("127.0.0.1:0".parse::<SocketAddr>().unwrap()).unwrap();
    let peer_addr = listener.local_addr().unwrap();
    let ac = application_context::short_msg_gateway_context(application_context::V3);

    // ─── Node B (HLR side) ─────────────────────────────────
    let ac2 = ac.clone();
    let node_b = tokio::spawn(async move {
        let (assoc, _) = listener.accept().await.unwrap();

        // M2PA alignment (responder)
        do_alignment(&assoc, false).await;

        // Receive MTP3 MSU via M2PA User Data
        let data = recv_m2pa(&assoc).await;
        let m2pa_msg = M2paMessage::decode(&data).unwrap();

        let msu_bytes = match m2pa_msg {
            M2paMessage::UserData { fsn, message, .. } => {
                assert_eq!(fsn, 0); // First user data message
                assert_eq!(message.priority, 0);
                message.msu
            }
            _ => panic!("Expected User Data"),
        };

        // Decode MTP3 MSU
        let msu = Msu::decode(&msu_bytes, PointCodeVariant::Itu).unwrap();
        assert_eq!(msu.sio.network_indicator, NetworkIndicator::National);
        assert_eq!(msu.sio.service_indicator, ServiceIndicator::Sccp);

        let dpc = msu.routing_label.dpc;
        let opc = msu.routing_label.opc;
        // DPC should be our PC (200), OPC should be sender (100)
        assert_eq!(dpc, PointCode::itu(0, 25, 0).unwrap()); // 200
        assert_eq!(opc, PointCode::itu(0, 12, 4).unwrap()); // 100

        // Decode SCCP
        let udt = UnitData::decode(&msu.payload).unwrap();
        assert_eq!(udt.called_party.ssn, Some(SubsystemNumber::Hlr));

        // Verify TCAP Begin tag
        assert_eq!(udt.data[0], 0x62); // TCAP Begin

        // Send back a TRA (Traffic Restart Allowed) via MTP3 SNM
        let tra = SnmMessage::Tra;
        let snm_bytes = tra.encode();
        let reply_sio = Sio::new(NetworkIndicator::National, ServiceIndicator::Snm);
        let reply_rl = RoutingLabel::new(
            PointCode::itu(0, 12, 4).unwrap(), // back to Node A
            PointCode::itu(0, 25, 0).unwrap(), // from Node B
            0,
        );
        let reply_msu = Msu::new(reply_sio, reply_rl, snm_bytes);
        let reply_msu_bytes = reply_msu.encode().unwrap();

        send_user_data(&assoc, &reply_msu_bytes, 0xFFFFFF, 0).await;
    });

    // ─── Node A (SMS-SC side) ──────────────────────────────
    tokio::task::yield_now().await;
    let assoc = SctpAssociation::connect(peer_addr).await.unwrap();

    // M2PA alignment (initiator)
    do_alignment(&assoc, true).await;

    // Build MAP SRI-SM → TCAP → SCCP
    let sri_arg = RoutingInfoForSmArg {
        msisdn: vec![0x91, 0x13, 0x16, 0x32, 0x54, 0x76, 0xF8].into(),
        sm_rp_pri: true,
        service_centre_address: vec![0x91, 0x44, 0x77, 0x89, 0x01, 0x23].into(),
        gprs_support_indicator: None,
        sm_rp_mti: None,
        sm_rp_smea: None,
    };
    let map_bytes = rasn::ber::encode(&sri_arg).unwrap();
    let tcap_bytes = build_tcap_begin(
        &[0x00, 0x00, 0x00, 0x01],
        op_codes::SEND_ROUTING_INFO_FOR_SM,
        &map_bytes,
        &ac,
    );

    let called = SccpAddress::with_ssn(SubsystemNumber::Hlr, None);
    let calling = SccpAddress::with_ssn(SubsystemNumber::Msc, None);
    let udt = UnitData::new(called, calling, tcap_bytes);
    let sccp_bytes = udt.encode().unwrap();

    // Wrap in MTP3 MSU (ITU format)
    let sio = Sio::new(NetworkIndicator::National, ServiceIndicator::Sccp);
    let rl = RoutingLabel::new(
        PointCode::itu(0, 25, 0).unwrap(), // DPC=200 (HLR)
        PointCode::itu(0, 12, 4).unwrap(), // OPC=100 (SMS-SC)
        0,
    );
    let msu = Msu::new(sio, rl, sccp_bytes);
    let msu_bytes = msu.encode().unwrap();

    // Send via M2PA User Data (stream 1, FSN=0)
    send_user_data(&assoc, &msu_bytes, 0xFFFFFF, 0).await;

    // Receive TRA from Node B
    let data = recv_m2pa(&assoc).await;
    let m2pa_msg = M2paMessage::decode(&data).unwrap();
    match m2pa_msg {
        M2paMessage::UserData { message, .. } => {
            let reply_msu = Msu::decode(&message.msu, PointCodeVariant::Itu).unwrap();
            assert_eq!(reply_msu.sio.service_indicator, ServiceIndicator::Snm);
            let snm = SnmMessage::decode(&reply_msu.payload).unwrap();
            assert_eq!(snm, SnmMessage::Tra);
        }
        _ => panic!("Expected User Data with TRA"),
    }

    assoc.shutdown().await.unwrap();
    node_b.await.unwrap();
}
