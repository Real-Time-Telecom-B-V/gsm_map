//! Emit one maximal instance of **every** operation this crate models, as a
//! `text2pcap` hex dump of SCCP UDT frames, so an *independent* decoder can read
//! them back.
//!
//! A BER round-trip cannot catch a shared encode/decode bug: if a tag is wrong in
//! both directions the test still passes, and a member encoded out of order is
//! silently dropped rather than rejected. Wireshark's `gsm_map` dissector carries
//! the TS 29.002 ASN.1 and does not share our bugs, so what it makes of these
//! bytes is real evidence about the tags, the order and the structure we emit.
//!
//! Each vector is a full MAP → TCAP → SCCP frame, printed starting at offset
//! `000000` (which is how `text2pcap` knows a new packet begins). Run it through
//! [`scripts/wireshark_check.sh`](../scripts/wireshark_check.sh), which pipes it
//! into `text2pcap -l 142` (SS7 SCCP link type) and asserts that the dissector
//! names back **every** member of every frame.
//!
//! Each frame's label, direction and member count go to stderr, one line per
//! frame, for the checker to compare against.

use gsm_map::address;
use gsm_map::application_context as ac;
use gsm_map::dialogue;
use gsm_map::operations::alert_sc::{AlertServiceCentreArg, SmsGmscAlertEvent};
use gsm_map::operations::auth::{
    AuthenticationTriplet, ReSynchronisationInfo, SendAuthenticationInfoArg,
    SendAuthenticationInfoRes,
};
use gsm_map::operations::call_handling::{
    InterrogationType, ProvideRoamingNumberArg, ProvideRoamingNumberRes, SendRoutingInfoArg,
};
use gsm_map::operations::fault_recovery::{
    ResetArg, RestoreDataArg, RestoreDataRes, SendingNodeNumber,
};
use gsm_map::operations::gprs_location::{
    FailureReportArg, NoteMsPresentForGprsArg, SendRoutingInfoForGprsArg,
    SendRoutingInfoForGprsRes, UpdateGprsLocationArg, UpdateGprsLocationRes,
};
use gsm_map::operations::handover::{
    ExternalSignalInfo, PrepareHandoverArg, PrepareSubsequentHandoverArg,
};
use gsm_map::operations::imei::{CheckImeiArg, CheckImeiRes, EquipmentStatus, UesbiIu};
use gsm_map::operations::inform_sc::InformServiceCentreArg;
use gsm_map::operations::lcs::{
    op_codes as lcs_op_codes, LcsClientId, LcsEvent, ProvideSubscriberLocationArg,
    SendRoutingInfoForLcsArg, SubscriberIdentityLcs, SubscriberLocationReportArg,
};
use gsm_map::operations::location::{
    CancelLocationArg, CancellationType, Identity, PurgeMsArg, PurgeMsRes, SendIdentificationArg,
    UpdateLocationArg, UpdateLocationRes,
};
use gsm_map::operations::mo_forward_sm::MoForwardSmArg;
use gsm_map::operations::mt_forward_sm::MtForwardSmArg;
use gsm_map::operations::oam::{ActivateTraceModeArg, DeactivateTraceModeArg};
use gsm_map::operations::ready_for_sm::{AlertReason, ReadyForSmArg};
use gsm_map::operations::report_sm::{
    ReportSmDeliveryStatusArg, ReportSmDeliveryStatusRes, SmDeliveryOutcome,
};
use gsm_map::operations::sri_sm::{
    CorrelationId, IpSmGwGuidance, RoutingInfoForSmArg, RoutingInfoForSmRes, SmDeliveryNotIntended,
};
use gsm_map::operations::subscriber_data::{
    DeleteSubscriberDataArg, InsertSubscriberDataArg, InsertSubscriberDataRes, NetworkAccessMode,
    OdbData, SubscriberStatus,
};
use gsm_map::operations::subscriber_info::{
    AnyTimeInterrogationArg, AnyTimeModificationArg, AnyTimeModificationRes,
    CellGlobalIdOrServiceAreaIdOrLai, LocationInformation, ModificationInstruction,
    ModificationRequestForIpSmGwData, NotReachableReason, ProvideSubscriberInfoArg,
    ProvideSubscriberInfoRes, RequestedInfo, SubscriberIdentity, SubscriberInfo, SubscriberState,
};
use gsm_map::operations::supplementary::{RegisterSsArg, SsForBsCode};
use gsm_map::operations::ussd::ProcessUnstructuredSsRequestArg;
use gsm_map::types::{
    op_codes, AdditionalNumber, ExtensionContainer, LocationInfoWithLmsi, MwStatusFlags,
    NetworkNodeDiameterAddress, Opaque, SmRpDa, SmRpOa,
};

use rasn::types::{BitString, ObjectIdentifier, OctetString};
use sccp::{GlobalTitle, SccpAddress, SubsystemNumber, UnitData};
use tcap::{
    Begin, Component, End, ErrorCode, Invoke, OperationCode, ReturnError, ReturnResult,
    ReturnResultValue, TcapMessage,
};

// ── Fixtures: fictional +1 555 01xx numbers and the reserved test PLMN 001/01 ──

const MSISDN_DIGITS: &str = "15550100999";
const IP_SM_GW_DIGITS: &str = "15550142";
const MSC_DIGITS: &str = "15550111";
const SC_DIGITS: &str = "15550199";
const IMSI_DIGITS: &str = "001010123456789";

fn e164(digits: &str) -> OctetString {
    address::international_e164(digits)
        .expect("fictional digits are valid")
        .into()
}

fn imsi() -> OctetString {
    address::imsi(IMSI_DIGITS)
        .expect("test-PLMN IMSI is valid")
        .into()
}

fn oct(bytes: &[u8]) -> OctetString {
    OctetString::from_slice(bytes)
}

fn bits(values: &[bool]) -> BitString {
    let mut out = BitString::new();
    for v in values {
        out.push(*v);
    }
    out
}

/// A one-member opaque SEQUENCE, standing in for a sub-structure this crate
/// carries but does not interpret. At a **context-tagged** position the opaque
/// value holds the member's *content*, so this is one inner `[0]` element. The
/// eight bytes give the dissector something plausible to chew on whatever the
/// real inner type is; the point here is the outer tag and position, not the
/// payload.
fn opaque() -> Opaque {
    // Context tag [30]: no real inner member uses it, so the dissector notes it
    // as unrecognised and moves on instead of trying to parse a synthetic
    // payload as a real sub-structure and throwing.
    Opaque::new(vec![0xBE, 0x00])
}

/// The same, for an **untagged** position: there the opaque value holds the
/// whole TLV, tag included.
fn opaque_tlv() -> Opaque {
    Opaque::new(vec![0x30, 0x02, 0xBE, 0x00])
}

/// An explicitly tagged CHOICE we carry opaquely: the wrapper's content is the
/// alternative's own TLV.
fn opaque_choice() -> Opaque {
    Opaque::new(vec![0xA0, 0x00])
}

fn extension_container() -> ExtensionContainer {
    ExtensionContainer {
        private_extension_list: Some(Opaque::new(vec![
            0x30, 0x08, 0x06, 0x06, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D,
        ])),
        pcs_extensions: None,
    }
}

/// `DiameterIdentity ::= OCTET STRING (SIZE (9..255))`, so nine bytes is the
/// shortest legal value — and these frames have to fit SCCP UDT's one-octet
/// data length.
fn diameter(name: &str) -> NetworkNodeDiameterAddress {
    NetworkNodeDiameterAddress {
        diameter_name: oct(name.as_bytes()),
        diameter_realm: oct(b"ex.net.nl"),
    }
}

// ── Framing ─────────────────────────────────────────────────────────────────

fn addr(digits: &str, ssn: SubsystemNumber) -> SccpAddress {
    SccpAddress::with_gt(
        GlobalTitle::Gt0100 {
            translation_type: 0,
            numbering_plan: 1,  // E.164
            encoding_scheme: 1, // BCD, odd number of digits
            nature_of_address: 4,
            digits: digits.to_string(),
        },
        Some(ssn),
    )
}

/// Every frame gets its own TCAP transaction id: the dissector keeps per-
/// transaction state, and reusing one id would make a later frame inherit an
/// earlier frame's outstanding invoke.
fn next_transaction_id() -> Vec<u8> {
    use std::sync::atomic::{AtomicU32, Ordering};
    static NEXT: AtomicU32 = AtomicU32::new(1);
    NEXT.fetch_add(1, Ordering::Relaxed).to_be_bytes().to_vec()
}

/// Hex-dump one SCCP UDT frame carrying `tcap_bytes`, and record what the
/// dissector should make of it.
fn emit_frame(label: &str, direction: &str, members: usize, tcap_bytes: Vec<u8>) {
    let udt = UnitData::new(
        addr("15550100123", SubsystemNumber::Hlr),
        addr("15550100888", SubsystemNumber::Msc),
        tcap_bytes,
    );
    let wire = udt.encode().expect("sccp encode");

    eprintln!("{label}\t{direction}\t{members}");
    for (i, chunk) in wire.chunks(16).enumerate() {
        let hex: Vec<String> = chunk.iter().map(|b| format!("{b:02x}")).collect();
        println!("{:06x}  {}", i * 16, hex.join(" "));
    }
}

/// An operation **argument**: TCAP `Invoke` in a `Begin`. `members` is how many
/// top-level members of the argument were set.
fn emit(label: &str, op_code: i64, acn: Option<ObjectIdentifier>, members: usize, param: Vec<u8>) {
    let begin = Begin {
        otid: next_transaction_id().into(),
        dialogue_portion: acn.as_ref().map(dialogue::begin),
        components: Some(vec![Component::Invoke(Invoke {
            invoke_id: 1,
            linked_id: None,
            operation_code: OperationCode::Local(op_code),
            parameter: Some(rasn::types::Any::new(param)),
        })]),
    };
    emit_frame(
        label,
        "invoke",
        members,
        tcap::encode(&TcapMessage::Begin(begin)).expect("tcap encode"),
    );
}

/// An operation **result**: TCAP `ReturnResultLast` in an `End`. A result has to
/// travel this way for the dissector to decode it as the result type — inside an
/// `Invoke` it would be read as the argument type and come back malformed.
fn emit_result(
    label: &str,
    op_code: i64,
    acn: Option<ObjectIdentifier>,
    members: usize,
    param: Vec<u8>,
) {
    let end = End {
        dtid: next_transaction_id().into(),
        dialogue_portion: acn.as_ref().map(dialogue::end_accept),
        components: Some(vec![Component::ReturnResultLast(ReturnResult {
            invoke_id: 1,
            result: Some(ReturnResultValue {
                operation_code: OperationCode::Local(op_code),
                parameter: Some(rasn::types::Any::new(param)),
            }),
        })]),
    };
    emit_frame(
        label,
        "result",
        members,
        tcap::encode(&TcapMessage::End(end)).expect("tcap encode"),
    );
}

fn ber(value: &impl rasn::Encode) -> Vec<u8> {
    rasn::ber::encode(value).expect("BER encode")
}

/// An application context, carried on a `Begin` with a trivial invoke: the
/// checker asserts the dissector resolves the OID to `expected_name`.
fn emit_context(expected_name: &str, acn: ObjectIdentifier) {
    let param = ber(&RoutingInfoForSmArg::new(
        e164(MSISDN_DIGITS),
        true,
        e164(SC_DIGITS),
    ));
    let begin = Begin {
        otid: next_transaction_id().into(),
        dialogue_portion: Some(dialogue::begin(&acn)),
        components: Some(vec![Component::Invoke(Invoke {
            invoke_id: 1,
            linked_id: None,
            operation_code: OperationCode::Local(op_codes::SEND_ROUTING_INFO_FOR_SM),
            parameter: Some(rasn::types::Any::new(param)),
        })]),
    };
    emit_frame(
        expected_name,
        "acn",
        0,
        tcap::encode(&TcapMessage::Begin(begin)).expect("tcap encode"),
    );
}

/// A MAP error, carried on an `End` as a `ReturnError`: the checker asserts the
/// dissector resolves the code to `expected_name`.
fn emit_error(code: i64, expected_name: &str) {
    let end = End {
        dtid: next_transaction_id().into(),
        dialogue_portion: None,
        components: Some(vec![Component::ReturnError(ReturnError {
            invoke_id: 1,
            error_code: ErrorCode::Local(code),
            parameter: None,
        })]),
    };
    emit_frame(
        expected_name,
        "error",
        0,
        tcap::encode(&TcapMessage::End(end)).expect("tcap encode"),
    );
}

/// Every application context the crate exposes, at a version TS 29.002 defines
/// it for.
fn context_vectors() {
    let contexts: &[(&str, ObjectIdentifier)] = &[
        ("networkLocUpContext-v3", ac::network_loc_up_context(ac::V3)),
        (
            "locationCancellationContext-v3",
            ac::location_cancellation_context(ac::V3),
        ),
        (
            "roamingNumberEnquiryContext-v3",
            ac::roaming_number_enquiry_context(ac::V3),
        ),
        ("istAlertingContext-v3", ac::ist_alerting_context(ac::V3)),
        (
            "locationInfoRetrievalContext-v3",
            ac::location_info_retrieval_context(ac::V3),
        ),
        (
            "callControlTransferContext-v3",
            ac::call_control_transfer_context(ac::V3),
        ),
        ("reportingContext-v3", ac::reporting_context(ac::V3)),
        (
            "callCompletionContext-v3",
            ac::call_completion_context(ac::V3),
        ),
        (
            "serviceTerminationContext-v3",
            ac::service_termination_context(ac::V3),
        ),
        ("resetContext-v3", ac::reset_context(ac::V3)),
        (
            "handoverControlContext-v3",
            ac::handover_control_context(ac::V3),
        ),
        (
            "sIWFSAllocationContext-v3",
            ac::siwfs_allocation_context(ac::V3),
        ),
        (
            "equipmentMngtContext-v3",
            ac::equipment_mngt_context(ac::V3),
        ),
        (
            "infoRetrievalContext-v3",
            ac::info_retrieval_context(ac::V3),
        ),
        (
            "interVlrInfoRetrievalContext-v3",
            ac::inter_vlr_info_retrieval_context(ac::V3),
        ),
        (
            "subscriberDataMngtContext-v3",
            ac::subscriber_data_mngt_context(ac::V3),
        ),
        ("tracingContext-v3", ac::tracing_context(ac::V3)),
        (
            "networkFunctionalSsContext-v2",
            ac::network_functional_ss_context(ac::V2),
        ),
        (
            "networkUnstructuredSsContext-v2",
            ac::network_unstructured_ss_context(ac::V2),
        ),
        (
            "shortMsgGatewayContext-v3",
            ac::short_msg_gateway_context(ac::V3),
        ),
        (
            "shortMsgMO-RelayContext-v3",
            ac::short_msg_mo_relay_context(ac::V3),
        ),
        (
            "subscriberDataModificationNotificationContext-v3",
            ac::subscriber_data_modification_notification_context(ac::V3),
        ),
        (
            "shortMsgAlertContext-v2",
            ac::short_msg_alert_context(ac::V2),
        ),
        ("mwdMngtContext-v3", ac::mwd_mngt_context(ac::V3)),
        (
            "shortMsgMT-RelayContext-v3",
            ac::short_msg_mt_relay_context(ac::V3),
        ),
        (
            "imsiRetrievalContext-v2",
            ac::imsi_retrieval_context(ac::V2),
        ),
        ("msPurgingContext-v3", ac::ms_purging_context(ac::V3)),
        (
            "subscriberInfoEnquiryContext-v3",
            ac::subscriber_info_enquiry_context(ac::V3),
        ),
        (
            "anyTimeInfoEnquiryContext-v3",
            ac::any_time_info_enquiry_context(ac::V3),
        ),
        (
            "groupCallControlContext-v3",
            ac::group_call_control_context(ac::V3),
        ),
        (
            "gprsLocationUpdateContext-v3",
            ac::gprs_location_update_context(ac::V3),
        ),
        (
            "gprsLocationInfoRetrievalContext-v3",
            ac::gprs_location_info_retrieval_context(ac::V3),
        ),
        (
            "failureReportContext-v3",
            ac::failure_report_context(ac::V3),
        ),
        ("gprsNotifyContext-v3", ac::gprs_notify_context(ac::V3)),
        (
            "ss-InvocationNotificationContext-v3",
            ac::ss_invocation_notification_context(ac::V3),
        ),
        (
            "locationSvcGatewayContext-v3",
            ac::location_svc_gateway_context(ac::V3),
        ),
        (
            "locationSvcEnquiryContext-v3",
            ac::location_svc_enquiry_context(ac::V3),
        ),
        (
            "authenticationFailureReportContext-v3",
            ac::authentication_failure_report_context(ac::V3),
        ),
        (
            "secureTransportHandlingContext-v3",
            ac::secure_transport_handling_context(ac::V3),
        ),
        (
            "shortMsgMT-Relay-VGCS-Context-v3",
            ac::short_msg_mt_relay_vgcs_context(ac::V3),
        ),
        (
            "mm-EventReportingContext-v3",
            ac::mm_event_reporting_context(ac::V3),
        ),
        (
            "anyTimeInfoHandlingContext-v3",
            ac::any_time_info_handling_context(ac::V3),
        ),
        (
            "resourceManagementContext-v3",
            ac::resource_management_context(ac::V3),
        ),
        (
            "groupCallInfoRetrievalContext-v3",
            ac::group_call_info_retrieval_context(ac::V3),
        ),
    ];
    for (name, oid) in contexts {
        emit_context(name, oid.clone());
    }
}

/// A MAP error *with* its parameter: the checker asserts the dissector names
/// back every member, the same way it does for an operation.
fn emit_error_param(label: &str, code: i64, members: usize, param: Vec<u8>) {
    let end = End {
        dtid: next_transaction_id().into(),
        dialogue_portion: None,
        components: Some(vec![Component::ReturnError(ReturnError {
            invoke_id: 1,
            error_code: ErrorCode::Local(code),
            parameter: Some(rasn::types::Any::new(param)),
        })]),
    };
    emit_frame(
        label,
        "error_param",
        members,
        tcap::encode(&TcapMessage::End(end)).expect("tcap encode"),
    );
}

/// The same, for a parameter whose ASN.1 type is a CHOICE: the dissector names
/// the alternative at the error's own level and its members one deeper.
fn emit_error_param_choice(label: &str, code: i64, members: usize, param: Vec<u8>) {
    let end = End {
        dtid: next_transaction_id().into(),
        dialogue_portion: None,
        components: Some(vec![Component::ReturnError(ReturnError {
            invoke_id: 1,
            error_code: ErrorCode::Local(code),
            parameter: Some(rasn::types::Any::new(param)),
        })]),
    };
    emit_frame(
        label,
        "error_param_choice",
        members,
        tcap::encode(&TcapMessage::End(end)).expect("tcap encode"),
    );
}

/// Every operation code the crate names — the same check the error codes get,
/// so the registry cannot drift from the spec's own spelling.
fn operation_name_vectors() {
    for (code, name) in gsm_map::OPERATION_REGISTRY {
        let begin = Begin {
            otid: next_transaction_id().into(),
            dialogue_portion: None,
            components: Some(vec![Component::Invoke(Invoke {
                invoke_id: 1,
                linked_id: None,
                operation_code: OperationCode::Local(*code),
                parameter: None,
            })]),
        };
        emit_frame(
            name,
            "opname",
            0,
            tcap::encode(&TcapMessage::Begin(begin)).expect("tcap encode"),
        );
    }
}

/// Every MAP error code the crate names, then every error parameter it models.
fn error_vectors() {
    use gsm_map::operations::errors::*;

    for (code, name) in ERROR_REGISTRY {
        emit_error(*code, name);
    }

    emit_error_param(
        "unknownSubscriberParam",
        error_codes::UNKNOWN_SUBSCRIBER,
        2,
        ber(&UnknownSubscriberParam {
            extension_container: Some(extension_container()),
            unknown_subscriber_diagnostic: Some(1.into()),
        }),
    );
    emit_error_param(
        "absentSubscriberSmParam",
        error_codes::ABSENT_SUBSCRIBER_SM,
        5,
        ber(&AbsentSubscriberSmParam {
            absent_subscriber_diagnostic_sm: Some(5.into()),
            extension_container: Some(extension_container()),
            additional_absent_subscriber_diagnostic_sm: Some(6.into()),
            imsi: Some(imsi()),
            requested_retransmission_time: Some(oct(&[0x22, 0x01, 0x01, 0x00])),
        }),
    );
    emit_error_param(
        "absentSubscriberParam",
        error_codes::ABSENT_SUBSCRIBER,
        2,
        ber(&AbsentSubscriberParam {
            extension_container: Some(extension_container()),
            absent_subscriber_reason: Some(2.into()),
        }),
    );
    emit_error_param(
        "subBusyForMtSmsParam",
        error_codes::SUBSCRIBER_BUSY_FOR_MT_SMS,
        2,
        ber(&SubBusyForMtSmsParam {
            extension_container: Some(extension_container()),
            gprs_connection_suspended: Some(()),
        }),
    );
    emit_error_param(
        "smDeliveryFailureCause",
        error_codes::SM_DELIVERY_FAILURE,
        3,
        ber(&SmDeliveryFailureCause {
            diagnostic_info: Some(oct(&[0x01, 0x02])),
            extension_container: Some(extension_container()),
            ..SmDeliveryFailureCause::new(SmEnumeratedDeliveryFailureCause::ScCongestion)
        }),
    );
    emit_error_param(
        "roamingNotAllowedParam",
        error_codes::ROAMING_NOT_ALLOWED,
        3,
        ber(&RoamingNotAllowedParam {
            roaming_not_allowed_cause: 0.into(),
            extension_container: Some(extension_container()),
            additional_roaming_not_allowed_cause: Some(0.into()),
        }),
    );
    emit_error_param_choice(
        "extensibleCallBarredParam",
        error_codes::CALL_BARRED,
        4,
        ber(&ExtensibleCallBarredParam {
            call_barring_cause: Some(0.into()),
            extension_container: Some(extension_container()),
            unauthorised_message_originator: Some(()),
            anonymous_call_rejection: Some(()),
        }),
    );
    emit_error_param_choice(
        "extensibleSystemFailureParam",
        error_codes::SYSTEM_FAILURE,
        4,
        ber(&ExtensibleSystemFailureParam {
            network_resource: Some(1.into()),
            extension_container: Some(extension_container()),
            additional_network_resource: Some(0.into()),
            failure_cause_param: Some(0.into()),
        }),
    );
    emit_error_param(
        "unexpectedDataParam",
        error_codes::UNEXPECTED_DATA_VALUE,
        2,
        ber(&UnexpectedDataParam {
            extension_container: Some(extension_container()),
            unexpected_subscriber: Some(()),
        }),
    );
    emit_error_param(
        "busySubscriberParam",
        error_codes::BUSY_SUBSCRIBER,
        3,
        ber(&BusySubscriberParam {
            extension_container: Some(extension_container()),
            ccbs_possible: Some(()),
            ccbs_busy: Some(()),
        }),
    );
    emit_error_param(
        "facilityNotSupParam",
        error_codes::FACILITY_NOT_SUPPORTED,
        3,
        ber(&FacilityNotSupParam {
            extension_container: Some(extension_container()),
            shape_of_location_estimate_not_supported: Some(()),
            needed_lcs_capability_not_supported_in_serving_node: Some(()),
        }),
    );
    emit_error_param(
        "positionMethodFailureParam",
        error_codes::POSITION_METHOD_FAILURE,
        2,
        ber(&PositionMethodFailureParam {
            position_method_failure_diagnostic: Some(0.into()),
            extension_container: Some(extension_container()),
        }),
    );
    emit_error_param(
        "atmNotAllowedParam",
        error_codes::ATM_NOT_ALLOWED,
        1,
        ber(&ExtensionContainerOnlyParam {
            extension_container: Some(extension_container()),
        }),
    );
}

// ── Shared sub-structures ───────────────────────────────────────────────────

fn requested_info() -> RequestedInfo {
    RequestedInfo {
        location_information: Some(()),
        subscriber_state: Some(()),
        extension_container: Some(extension_container()),
        current_location: Some(()),
        requested_domain: Some(1.into()),
        imei: Some(()),
        ms_classmark: Some(()),
        mnp_requested_info: Some(()),
        location_information_eps_supported: Some(()),
        t_ads_data: Some(()),
        requested_nodes: Some(bits(&[true, true])),
        serving_node_indication: Some(()),
        local_time_zone_request: Some(()),
    }
}

fn subscriber_info() -> SubscriberInfo {
    SubscriberInfo {
        location_information: Some(LocationInformation {
            age_of_location_information: Some(5.into()),
            geographical_information: Some(oct(&[0x10; 8])),
            vlr_number: Some(e164(MSC_DIGITS)),
            location_number: Some(oct(&[0x01, 0x02])),
            cell_global_id_or_service_area_id_or_lai: Some(
                CellGlobalIdOrServiceAreaIdOrLai::CellGlobalIdOrServiceAreaIdFixedLength(oct(&[
                    0x00, 0xF1, 0x10, 0x00, 0x01, 0x00, 0x02,
                ])),
            ),
            extension_container: Some(extension_container()),
            selected_lsa_id: Some(oct(&[0x01, 0x02, 0x03])),
            msc_number: Some(e164(MSC_DIGITS)),
            geodetic_information: Some(oct(&[0x20; 10])),
            current_location_retrieved: Some(()),
            sai_present: Some(()),
            location_information_eps: Some(opaque()),
            user_csg_information: Some(opaque()),
        }),
        subscriber_state: Some(SubscriberState::NetDetNotReachable(
            NotReachableReason::ImsiDetached,
        )),
        extension_container: Some(extension_container()),
        location_information_gprs: Some(opaque()),
        ps_subscriber_state: Some(opaque_choice()),
        imei: Some(oct(&[0x01; 8])),
        ms_classmark2: Some(oct(&[0x33, 0x19, 0xA2])),
        gprs_ms_class: Some(opaque()),
        mnp_info_res: Some(opaque()),
        ims_voice_over_ps_sessions_indication: Some(1.into()),
        last_ue_activity_time: Some(oct(&[0x22, 0x01, 0x01, 0x00])),
        last_rat_type: Some(5.into()),
        eps_subscriber_state: Some(opaque_choice()),
        location_information_eps: Some(opaque()),
        time_zone: Some(oct(&[0x40])),
        daylight_saving_time: Some(1.into()),
        location_information_5gs: Some(opaque()),
    }
}

fn correlation_id() -> CorrelationId {
    CorrelationId {
        // HLR-Id is an IMSI-shaped TBCD string.
        hlr_id: Some(imsi()),
        sip_uri_a: Some(oct(b"sip:a@ex.nl")),
        sip_uri_b: oct(b"sip:b@ex.nl"),
    }
}

// ── Vectors ─────────────────────────────────────────────────────────────────

fn sms_vectors() {
    let gateway = ac::short_msg_gateway_context(ac::V3);

    emit(
        "sri_sm_arg",
        op_codes::SEND_ROUTING_INFO_FOR_SM,
        Some(gateway.clone()),
        14,
        ber(&RoutingInfoForSmArg {
            extension_container: Some(extension_container()),
            gprs_support_indicator: Some(()),
            sm_rp_mti: Some(0.into()),
            sm_rp_smea: Some(oct(&[0x07, 0x91, 0x51, 0x55, 0x10, 0x99])),
            sm_delivery_not_intended: Some(SmDeliveryNotIntended::OnlyImsiRequested),
            ip_sm_gw_guidance_indicator: Some(()),
            imsi: Some(imsi()),
            t4_trigger_indicator: Some(()),
            single_attempt_delivery: Some(()),
            correlation_id: Some(correlation_id()),
            smsf_support_indicator: Some(()),
            ..RoutingInfoForSmArg::new(e164(MSISDN_DIGITS), true, e164(SC_DIGITS))
        }),
    );

    // SCCP UDT carries its data under a one-octet length, so the response goes
    // out in two frames: the outer members with a minimal serving node, then a
    // full LocationInfoWithLMSI on its own.
    emit_result(
        "sri_sm_res_outer",
        op_codes::SEND_ROUTING_INFO_FOR_SM,
        Some(gateway.clone()),
        4,
        ber(&RoutingInfoForSmRes {
            extension_container: Some(extension_container()),
            ip_sm_gw_guidance: Some(IpSmGwGuidance {
                minimum_delivery_time_value: 30.into(),
                recommended_delivery_time_value: 300.into(),
                extension_container: Some(extension_container()),
            }),
            ..RoutingInfoForSmRes::new(imsi(), LocationInfoWithLmsi::new(e164(MSC_DIGITS)))
        }),
    );

    // The serving-node members split again for the same reason.
    emit_result(
        "sri_sm_res_location_info_a",
        op_codes::SEND_ROUTING_INFO_FOR_SM,
        Some(gateway.clone()),
        2,
        ber(&RoutingInfoForSmRes::new(
            imsi(),
            LocationInfoWithLmsi {
                lmsi: Some(oct(&[0x00, 0x00, 0x00, 0x2A])),
                extension_container: Some(extension_container()),
                gprs_node_indicator: Some(()),
                additional_number: Some(AdditionalNumber::SgsnNumber(e164(SC_DIGITS))),
                network_node_diameter_address: Some(diameter("msc.ex.nl")),
                additional_network_node_diameter_address: Some(diameter("sgsn.ex.nl")),
                ..LocationInfoWithLmsi::new(e164(MSC_DIGITS))
            },
        )),
    );

    emit_result(
        "sri_sm_res_location_info_b",
        op_codes::SEND_ROUTING_INFO_FOR_SM,
        Some(gateway),
        2,
        ber(&RoutingInfoForSmRes::new(
            imsi(),
            LocationInfoWithLmsi {
                third_number: Some(AdditionalNumber::MscNumber(e164(MSC_DIGITS))),
                third_network_node_diameter_address: Some(diameter("third.ex.nl")),
                ims_node_indicator: Some(()),
                smsf_3gpp_number: Some(e164(MSC_DIGITS)),
                smsf_3gpp_diameter_address: Some(diameter("smsf3.ex.nl")),
                smsf_non_3gpp_number: Some(e164(MSC_DIGITS)),
                smsf_non_3gpp_diameter_address: Some(diameter("smsfn3.ex.nl")),
                smsf_3gpp_address_indicator: Some(()),
                smsf_non_3gpp_address_indicator: Some(()),
                ..LocationInfoWithLmsi::new(e164(MSC_DIGITS))
            },
        )),
    );

    let tpdu = oct(&[
        0x04, 0x0B, 0x91, 0x51, 0x55, 0x10, 0x00, 0x99, 0xF9, 0x00, 0x00, 0x00,
    ]);

    emit(
        "mo_forward_sm_arg",
        op_codes::MO_FORWARD_SM,
        Some(ac::short_msg_mo_relay_context(ac::V3)),
        7,
        ber(&MoForwardSmArg {
            extension_container: Some(extension_container()),
            imsi: Some(imsi()),
            correlation_id: Some(correlation_id()),
            sm_delivery_outcome: Some(SmDeliveryOutcome::SuccessfulTransfer),
            ..MoForwardSmArg::new(
                SmRpDa::ServiceCentreAddressDa(e164(SC_DIGITS)),
                SmRpOa::MsIsdn(e164(MSISDN_DIGITS)),
                tpdu.clone(),
            )
        }),
    );

    emit(
        "mt_forward_sm_arg",
        op_codes::MT_FORWARD_SM,
        Some(ac::short_msg_mt_relay_context(ac::V3)),
        12,
        ber(&MtForwardSmArg {
            more_messages_to_send: Some(()),
            extension_container: Some(extension_container()),
            sm_delivery_timer: Some(30.into()),
            sm_delivery_start_time: Some(oct(&[0x22, 0x01, 0x01, 0x00])),
            sms_over_ip_only_indicator: Some(()),
            correlation_id: Some(correlation_id()),
            maximum_retransmission_time: Some(oct(&[0x22, 0x01, 0x02, 0x00])),
            sms_gmsc_address: Some(e164(SC_DIGITS)),
            sms_gmsc_diameter_address: Some(diameter("gmsc.ex.nl")),
            ..MtForwardSmArg::new(
                SmRpDa::Imsi(imsi()),
                SmRpOa::ServiceCentreAddressOa(e164(SC_DIGITS)),
                tpdu,
            )
        }),
    );

    emit(
        "report_sm_delivery_status_arg",
        op_codes::REPORT_SM_DELIVERY_STATUS,
        Some(ac::short_msg_gateway_context(ac::V3)),
        21,
        ber(&ReportSmDeliveryStatusArg {
            absent_subscriber_diagnostic_sm: Some(5.into()),
            extension_container: Some(extension_container()),
            gprs_support_indicator: Some(()),
            delivery_outcome_indicator: Some(()),
            additional_sm_delivery_outcome: Some(SmDeliveryOutcome::AbsentSubscriber),
            additional_absent_subscriber_diagnostic_sm: Some(6.into()),
            ip_sm_gw_indicator: Some(()),
            ip_sm_gw_sm_delivery_outcome: Some(SmDeliveryOutcome::SuccessfulTransfer),
            ip_sm_gw_absent_subscriber_diagnostic_sm: Some(7.into()),
            imsi: Some(imsi()),
            single_attempt_delivery: Some(()),
            correlation_id: Some(correlation_id()),
            smsf_3gpp_delivery_outcome_indicator: Some(()),
            smsf_3gpp_delivery_outcome: Some(SmDeliveryOutcome::MemoryCapacityExceeded),
            smsf_3gpp_absent_subscriber_diag_sm: Some(8.into()),
            smsf_non_3gpp_delivery_outcome_indicator: Some(()),
            smsf_non_3gpp_delivery_outcome: Some(SmDeliveryOutcome::AbsentSubscriber),
            smsf_non_3gpp_absent_subscriber_diag_sm: Some(9.into()),
            ..ReportSmDeliveryStatusArg::new(
                e164(MSISDN_DIGITS),
                e164(SC_DIGITS),
                SmDeliveryOutcome::SuccessfulTransfer,
            )
        }),
    );

    emit_result(
        "report_sm_delivery_status_res",
        op_codes::REPORT_SM_DELIVERY_STATUS,
        None,
        2,
        ber(&ReportSmDeliveryStatusRes {
            stored_msisdn: Some(e164(MSISDN_DIGITS)),
            extension_container: Some(extension_container()),
        }),
    );

    emit(
        "alert_service_centre_arg",
        op_codes::ALERT_SERVICE_CENTRE,
        None,
        12,
        ber(&AlertServiceCentreArg {
            imsi: Some(imsi()),
            correlation_id: Some(correlation_id()),
            maximum_ue_availability_time: Some(oct(&[0x22, 0x01, 0x01, 0x00])),
            sms_gmsc_alert_event: Some(SmsGmscAlertEvent::MsUnderNewServingNode),
            sms_gmsc_diameter_address: Some(diameter("gmsc.ex.nl")),
            new_sgsn_number: Some(e164(MSC_DIGITS)),
            new_sgsn_diameter_address: Some(diameter("sgsn.ex.nl")),
            new_mme_number: Some(e164(MSC_DIGITS)),
            new_mme_diameter_address: Some(diameter("mme.ex.nl")),
            new_msc_number: Some(e164(MSC_DIGITS)),
            ..AlertServiceCentreArg::new(e164(MSISDN_DIGITS), e164(SC_DIGITS))
        }),
    );

    emit(
        "inform_service_centre_arg",
        op_codes::INFORM_SERVICE_CENTRE,
        None,
        7,
        ber(&InformServiceCentreArg {
            stored_msisdn: Some(e164(MSISDN_DIGITS)),
            mw_status: Some(
                MwStatusFlags {
                    sc_address_not_included: true,
                    mnrf_set: true,
                    mcef_set: true,
                    mnrg_set: true,
                    mnr5g_set: false,
                    mnr5gn3g_set: true,
                }
                .to_bits(),
            ),
            extension_container: Some(extension_container()),
            absent_subscriber_diagnostic_sm: Some(5.into()),
            additional_absent_subscriber_diagnostic_sm: Some(6.into()),
            smsf_3gpp_absent_subscriber_diagnostic_sm: Some(7.into()),
            smsf_non_3gpp_absent_subscriber_diagnostic_sm: Some(8.into()),
        }),
    );

    emit(
        "ready_for_sm_arg",
        op_codes::READY_FOR_SM,
        None,
        6,
        ber(&ReadyForSmArg {
            alert_reason_indicator: Some(()),
            extension_container: Some(extension_container()),
            additional_alert_reason_indicator: Some(()),
            maximum_ue_availability_time: Some(oct(&[0x22, 0x01, 0x01, 0x00])),
            ..ReadyForSmArg::new(imsi(), AlertReason::MemoryAvailable)
        }),
    );
}

fn subscriber_info_vectors() {
    let ati = ac::any_time_info_handling_context(ac::V3);

    for (label, instruction) in [
        ("atm_ip_sm_gw_activate", ModificationInstruction::Activate),
        (
            "atm_ip_sm_gw_deactivate",
            ModificationInstruction::Deactivate,
        ),
    ] {
        emit(
            label,
            op_codes::ANY_TIME_MODIFICATION,
            Some(ati.clone()),
            16,
            ber(&AnyTimeModificationArg {
                modification_request_for_cf_info: Some(opaque()),
                modification_request_for_cb_info: Some(opaque()),
                modification_request_for_csi: Some(opaque()),
                extension_container: Some(extension_container()),
                long_ftn_supported: Some(()),
                modification_request_for_odb_data: Some(opaque()),
                modification_request_for_ip_sm_gw_data: Some(ModificationRequestForIpSmGwData {
                    modify_registration_status: Some(instruction),
                    extension_container: Some(extension_container()),
                    ip_sm_gw_diameter_address: Some(diameter("ipsmgw.ex.nl")),
                }),
                activation_request_for_ue_reachability: Some(bits(&[true, false])),
                modification_request_for_csg: Some(opaque()),
                modification_request_for_cw_data: Some(opaque()),
                modification_request_for_clip_data: Some(opaque()),
                modification_request_for_clir_data: Some(opaque()),
                modification_request_for_hold_data: Some(opaque()),
                modification_request_for_ect_data: Some(opaque()),
                ..AnyTimeModificationArg::new(
                    SubscriberIdentity::Msisdn(e164(MSISDN_DIGITS)),
                    e164(IP_SM_GW_DIGITS),
                )
            }),
        );
    }

    emit_result(
        "atm_res",
        op_codes::ANY_TIME_MODIFICATION,
        Some(ati.clone()),
        9,
        ber(&AnyTimeModificationRes {
            ss_info_for_cse: Some(opaque_choice()),
            camel_subscription_info: Some(opaque()),
            extension_container: Some(extension_container()),
            odb_info: Some(opaque()),
            cw_data: Some(opaque()),
            ch_data: Some(opaque()),
            clip_data: Some(opaque()),
            clir_data: Some(opaque()),
            ect_data: Some(opaque()),
        }),
    );

    emit(
        "ati_arg",
        op_codes::ANY_TIME_INTERROGATION,
        Some(ati),
        4,
        ber(&AnyTimeInterrogationArg {
            subscriber_identity: SubscriberIdentity::Imsi(imsi()),
            requested_info: requested_info(),
            gsm_scf_address: e164(IP_SM_GW_DIGITS),
            extension_container: Some(extension_container()),
        }),
    );

    emit(
        "psi_arg",
        op_codes::PROVIDE_SUBSCRIBER_INFO,
        None,
        5,
        ber(&ProvideSubscriberInfoArg {
            lmsi: Some(oct(&[0x00, 0x00, 0x00, 0x01])),
            extension_container: Some(extension_container()),
            call_priority: Some(2.into()),
            ..ProvideSubscriberInfoArg::new(imsi(), requested_info())
        }),
    );

    emit_result(
        "psi_res",
        op_codes::PROVIDE_SUBSCRIBER_INFO,
        None,
        2,
        ber(&ProvideSubscriberInfoRes {
            subscriber_info: subscriber_info(),
            extension_container: Some(extension_container()),
        }),
    );
}

fn mobility_vectors() {
    emit(
        "update_location_arg",
        op_codes::UPDATE_LOCATION,
        Some(ac::network_loc_up_context(ac::V3)),
        15,
        ber(&UpdateLocationArg {
            lmsi: Some(oct(&[0x00, 0x00, 0x00, 0x01])),
            extension_container: Some(extension_container()),
            vlr_capability: Some(opaque()),
            inform_previous_network_entity: Some(()),
            cs_lcs_not_supported_by_ue: Some(()),
            v_gmlc_address: Some(oct(&[10, 0, 0, 1])),
            add_info: Some(opaque()),
            paging_area: Some(opaque()),
            skip_subscriber_data_update: Some(()),
            restoration_indicator: Some(()),
            eplmn_list: Some(opaque()),
            mme_diameter_address: Some(diameter("mme.ex.nl")),
            ..UpdateLocationArg::new(imsi(), e164(MSC_DIGITS), e164(MSC_DIGITS))
        }),
    );

    emit_result(
        "update_location_res",
        op_codes::UPDATE_LOCATION,
        None,
        4,
        ber(&UpdateLocationRes {
            extension_container: Some(extension_container()),
            add_capability: Some(()),
            paging_area_capability: Some(()),
            ..UpdateLocationRes::new(e164(SC_DIGITS))
        }),
    );

    emit(
        "cancel_location_arg",
        op_codes::CANCEL_LOCATION,
        None,
        10,
        ber(&CancelLocationArg {
            cancellation_type: Some(CancellationType::SubscriptionWithdraw),
            extension_container: Some(extension_container()),
            type_of_update: Some(1.into()),
            mtrf_supported_and_authorized: Some(()),
            mtrf_supported_and_not_authorized: Some(()),
            new_msc_number: Some(e164(MSC_DIGITS)),
            new_vlr_number: Some(e164(MSC_DIGITS)),
            new_lmsi: Some(oct(&[0x00, 0x00, 0x00, 0x02])),
            reattach_required: Some(()),
            ..CancelLocationArg::new(Identity::Imsi(imsi()))
        }),
    );

    emit(
        "purge_ms_arg",
        op_codes::PURGE_MS,
        None,
        4,
        ber(&PurgeMsArg {
            vlr_number: Some(e164(MSC_DIGITS)),
            sgsn_number: Some(e164(MSC_DIGITS)),
            extension_container: Some(extension_container()),
            ..PurgeMsArg::new(imsi())
        }),
    );

    emit_result(
        "purge_ms_res",
        op_codes::PURGE_MS,
        None,
        4,
        ber(&PurgeMsRes {
            freeze_tmsi: Some(()),
            freeze_p_tmsi: Some(()),
            extension_container: Some(extension_container()),
            freeze_m_tmsi: Some(()),
        }),
    );

    emit(
        "send_identification_arg",
        op_codes::SEND_IDENTIFICATION,
        None,
        10,
        ber(&SendIdentificationArg {
            number_of_requested_vectors: Some(3.into()),
            segmentation_prohibited: Some(()),
            extension_container: Some(extension_container()),
            msc_number: Some(e164(MSC_DIGITS)),
            previous_lai: Some(oct(&[0x00, 0xF1, 0x10, 0x00, 0x01])),
            hop_counter: Some(2.into()),
            mt_roaming_forwarding_supported: Some(()),
            new_vlr_number: Some(e164(MSC_DIGITS)),
            new_lmsi: Some(oct(&[0x00, 0x00, 0x00, 0x01])),
            ..SendIdentificationArg::new(oct(&[0x11, 0x22, 0x33, 0x44]))
        }),
    );

    emit(
        "send_authentication_info_arg",
        op_codes::SEND_AUTHENTICATION_INFO,
        Some(ac::info_retrieval_context(ac::V3)),
        11,
        ber(&SendAuthenticationInfoArg {
            segmentation_prohibited: Some(()),
            immediate_response_preferred: Some(()),
            re_synchronisation_info: Some(ReSynchronisationInfo {
                rand: oct(&[0x11; 16]),
                auts: oct(&[0x22; 14]),
            }),
            extension_container: Some(extension_container()),
            requesting_node_type: Some(3.into()),
            requesting_plmn_id: Some(oct(&[0x00, 0xF1, 0x10])),
            number_of_requested_additional_vectors: Some(2.into()),
            additional_vectors_are_for_eps: Some(()),
            ue_usage_type_request_indication: Some(()),
            ..SendAuthenticationInfoArg::new(imsi(), 3.into())
        }),
    );

    emit_result(
        "send_authentication_info_res",
        op_codes::SEND_AUTHENTICATION_INFO,
        None,
        4,
        ber(&SendAuthenticationInfoRes {
            triplet_list: Some(vec![AuthenticationTriplet {
                rand: oct(&[0x11; 16]),
                sres: oct(&[0x22; 4]),
                kc: oct(&[0x33; 8]),
            }]),
            extension_container: Some(extension_container()),
            eps_authentication_set_list: Some(opaque()),
            ue_usage_type: Some(1.into()),
            ..Default::default()
        }),
    );
}

fn gprs_vectors() {
    emit(
        "update_gprs_location_arg",
        op_codes::UPDATE_GPRS_LOCATION,
        None,
        28,
        ber(&UpdateGprsLocationArg {
            extension_container: Some(extension_container()),
            sgsn_capability: Some(opaque()),
            inform_previous_network_entity: Some(()),
            ps_lcs_not_supported_by_ue: Some(()),
            v_gmlc_address: Some(oct(&[10, 0, 0, 1])),
            add_info: Some(opaque()),
            eps_info: Some(opaque_choice()),
            serving_node_type_indicator: Some(()),
            skip_subscriber_data_update: Some(()),
            used_rat_type: Some(4.into()),
            gprs_subscription_data_not_needed: Some(()),
            node_type_indicator: Some(()),
            area_restricted: Some(()),
            ue_reachable_indicator: Some(()),
            eps_subscription_data_not_needed: Some(()),
            ue_srvcc_capability: Some(1.into()),
            eplmn_list: Some(opaque()),
            mme_number_for_mt_sms: Some(e164(MSC_DIGITS)),
            sms_register_request: Some(0.into()),
            sms_only: Some(()),
            sgsn_name: Some(oct(b"sgsn.ex.nl")),
            sgsn_realm: Some(oct(b"ex.net.nl")),
            lgd_support_indicator: Some(()),
            removal_of_mme_registration_for_sms: Some(()),
            adjacent_plmn_list: Some(opaque()),
            ..UpdateGprsLocationArg::new(imsi(), e164(MSC_DIGITS), oct(&[10, 0, 0, 2]))
        }),
    );

    emit_result(
        "update_gprs_location_res",
        op_codes::UPDATE_GPRS_LOCATION,
        None,
        5,
        ber(&UpdateGprsLocationRes {
            extension_container: Some(extension_container()),
            add_capability: Some(()),
            sgsn_mme_separation_supported: Some(()),
            mme_registered_for_sms: Some(()),
            ..UpdateGprsLocationRes::new(e164(SC_DIGITS))
        }),
    );

    emit(
        "send_routing_info_for_gprs_arg",
        op_codes::SEND_ROUTING_INFO_FOR_GPRS,
        None,
        4,
        ber(&SendRoutingInfoForGprsArg {
            imsi: imsi(),
            ggsn_address: Some(oct(&[10, 0, 0, 3])),
            ggsn_number: e164(SC_DIGITS),
            extension_container: Some(extension_container()),
        }),
    );

    emit_result(
        "send_routing_info_for_gprs_res",
        op_codes::SEND_ROUTING_INFO_FOR_GPRS,
        None,
        4,
        ber(&SendRoutingInfoForGprsRes {
            sgsn_address: oct(&[10, 0, 0, 1]),
            ggsn_address: Some(oct(&[10, 0, 0, 3])),
            mobile_not_reachable_reason: Some(5.into()),
            extension_container: Some(extension_container()),
        }),
    );

    emit(
        "failure_report_arg",
        op_codes::FAILURE_REPORT,
        None,
        4,
        ber(&FailureReportArg {
            imsi: imsi(),
            ggsn_number: e164(SC_DIGITS),
            ggsn_address: Some(oct(&[10, 0, 0, 3])),
            extension_container: Some(extension_container()),
        }),
    );

    emit(
        "note_ms_present_for_gprs_arg",
        op_codes::NOTE_MS_PRESENT_FOR_GPRS,
        None,
        4,
        ber(&NoteMsPresentForGprsArg {
            imsi: imsi(),
            sgsn_address: oct(&[10, 0, 0, 1]),
            ggsn_address: Some(oct(&[10, 0, 0, 3])),
            extension_container: Some(extension_container()),
        }),
    );
}

fn subscriber_data_vectors() {
    // 53 members do not fit under SCCP UDT's one-octet data length, so the
    // argument goes out in three frames covering contiguous runs of the ASN.1
    // declaration order. Order within each run is what the dissector checks.
    emit(
        "insert_subscriber_data_arg_a",
        op_codes::INSERT_SUBSCRIBER_DATA,
        Some(ac::subscriber_data_mngt_context(ac::V3)),
        14,
        ber(&InsertSubscriberDataArg {
            imsi: Some(imsi()),
            msisdn: Some(e164(MSISDN_DIGITS)),
            category: Some(oct(&[0x0A])),
            subscriber_status: Some(SubscriberStatus::ServiceGranted),
            bearer_service_list: Some(vec![oct(&[0x11])]),
            teleservice_list: Some(vec![oct(&[0x21])]),
            provisioned_ss: Some(opaque()),
            odb_data: Some(OdbData {
                odb_hplmn_data: Some(bits(&[false, true])),
                extension_container: Some(extension_container()),
                ..OdbData::new(bits(&[true, false, false, true]))
            }),
            roaming_restriction_due_to_unsupported_feature: Some(()),
            regional_subscription_data: Some(opaque()),
            vbs_subscription_data: Some(opaque()),
            vgcs_subscription_data: Some(opaque()),
            vlr_camel_subscription_info: Some(opaque()),
            extension_container: Some(extension_container()),
            ..Default::default()
        }),
    );

    emit(
        "insert_subscriber_data_arg_b",
        op_codes::INSERT_SUBSCRIBER_DATA,
        None,
        15,
        ber(&InsertSubscriberDataArg {
            naea_preferred_ci: Some(opaque()),
            gprs_subscription_data: Some(opaque()),
            roaming_restricted_in_sgsn_due_to_unsupported_feature: Some(()),
            network_access_mode: Some(NetworkAccessMode::OnlyPacket),
            lsa_information: Some(opaque()),
            lmu_indicator: Some(()),
            lcs_information: Some(opaque()),
            ist_alert_timer: Some(30.into()),
            super_charger_supported_in_hlr: Some(oct(&[0x01, 0x02])),
            mc_ss_info: Some(opaque()),
            cs_allocation_retention_priority: Some(oct(&[0x01])),
            sgsn_camel_subscription_info: Some(opaque()),
            charging_characteristics: Some(bits(&[true, false, false, false])),
            access_restriction_data: Some(bits(&[true, false])),
            ics_indicator: Some(true),
            ..Default::default()
        }),
    );

    emit(
        "insert_subscriber_data_arg_c",
        op_codes::INSERT_SUBSCRIBER_DATA,
        None,
        24,
        ber(&InsertSubscriberDataArg {
            eps_subscription_data: Some(opaque()),
            csg_subscription_data_list: Some(opaque()),
            ue_reachability_request_indicator: Some(()),
            sgsn_number: Some(e164(MSC_DIGITS)),
            mme_name: Some(oct(b"mme.ex.nl")),
            subscribed_periodic_rau_tau_timer: Some(60.into()),
            vplmn_lipa_allowed: Some(()),
            mdt_user_consent: Some(false),
            subscribed_periodic_lau_timer: Some(60.into()),
            vplmn_csg_subscription_data_list: Some(opaque()),
            additional_msisdn: Some(e164(MSISDN_DIGITS)),
            ps_and_sms_only_service_provision: Some(()),
            sms_in_sgsn_allowed: Some(()),
            cs_to_ps_srvcc_allowed_indicator: Some(()),
            pcscf_restoration_request: Some(()),
            adjacent_access_restriction_data_list: Some(opaque()),
            imsi_group_id_list: Some(opaque()),
            ue_usage_type: Some(2.into()),
            user_plane_integrity_protection_indicator: Some(()),
            dl_buffering_suggested_packet_count: Some(5.into()),
            reset_id_list: Some(opaque()),
            edrx_cycle_length_list: Some(opaque()),
            ext_access_restriction_data: Some(bits(&[false, true])),
            iab_operation_allowed_indicator: Some(()),
            ..Default::default()
        }),
    );

    emit_result(
        "insert_subscriber_data_res",
        op_codes::INSERT_SUBSCRIBER_DATA,
        None,
        10,
        ber(&InsertSubscriberDataRes {
            teleservice_list: Some(vec![oct(&[0x21])]),
            bearer_service_list: Some(vec![oct(&[0x11])]),
            ss_list: Some(vec![oct(&[0x21])]),
            odb_general_data: Some(bits(&[false, true])),
            regional_subscription_response: Some(1.into()),
            supported_camel_phases: Some(bits(&[true])),
            extension_container: Some(extension_container()),
            offered_camel4_csis: Some(bits(&[true])),
            supported_features: Some(bits(&[true])),
            ext_supported_features: Some(bits(&[true])),
        }),
    );

    emit(
        "delete_subscriber_data_arg",
        op_codes::DELETE_SUBSCRIBER_DATA,
        None,
        32,
        ber(&DeleteSubscriberDataArg {
            basic_service_list: Some(vec![oct(&[0x21])]),
            ss_list: Some(vec![oct(&[0x21])]),
            roaming_restriction_due_to_unsupported_feature: Some(()),
            regional_subscription_identifier: Some(oct(&[0x00, 0x01])),
            vbs_group_indication: Some(()),
            vgcs_group_indication: Some(()),
            camel_subscription_info_withdraw: Some(()),
            extension_container: Some(extension_container()),
            gprs_subscription_data_withdraw: Some(Opaque::new(vec![0x05, 0x00])),
            roaming_restricted_in_sgsn_due_to_unsupported_feature: Some(()),
            lsa_information_withdraw: Some(Opaque::new(vec![0x05, 0x00])),
            gmlc_list_withdraw: Some(()),
            ist_information_withdraw: Some(()),
            specific_csi_withdraw: Some(bits(&[true, false])),
            charging_characteristics_withdraw: Some(()),
            stn_sr_withdraw: Some(()),
            eps_subscription_data_withdraw: Some(Opaque::new(vec![0x05, 0x00])),
            apn_oi_replacement_withdraw: Some(()),
            csg_subscription_deleted: Some(()),
            subscribed_periodic_tau_rau_timer_withdraw: Some(()),
            subscribed_periodic_lau_timer_withdraw: Some(()),
            subscribed_vsrvcc_withdraw: Some(()),
            vplmn_csg_subscription_deleted: Some(()),
            additional_msisdn_withdraw: Some(()),
            cs_to_ps_srvcc_withdraw: Some(()),
            imsi_group_id_list_withdraw: Some(()),
            user_plane_integrity_protection_withdraw: Some(()),
            dl_buffering_suggested_packet_count_withdraw: Some(()),
            ue_usage_type_withdraw: Some(()),
            reset_ids_withdraw: Some(()),
            iab_operation_withdraw: Some(()),
            ..DeleteSubscriberDataArg::new(imsi())
        }),
    );
}

fn misc_vectors() {
    emit(
        "send_routing_info_arg",
        op_codes::SEND_ROUTING_INFO,
        None,
        30,
        ber(&SendRoutingInfoArg {
            cug_check_info: Some(opaque()),
            number_of_forwarding: Some(1.into()),
            interrogation_type: Some(InterrogationType::BasicCall),
            or_interrogation: Some(()),
            or_capability: Some(1.into()),
            call_reference_number: Some(oct(&[0x01, 0x02, 0x03])),
            forwarding_reason: Some(0.into()),
            basic_service_group: Some(Opaque::new(vec![0x82, 0x01, 0x11])),
            network_signal_info: Some(opaque()),
            camel_info: Some(opaque()),
            suppression_of_announcement: Some(()),
            extension_container: Some(extension_container()),
            alerting_pattern: Some(oct(&[0x01])),
            ccbs_call: Some(()),
            supported_ccbs_phase: Some(1.into()),
            additional_signal_info: Some(opaque()),
            ist_support_indicator: Some(0.into()),
            pre_paging_supported: Some(()),
            call_diversion_treatment_indicator: Some(oct(&[0x01])),
            long_ftn_supported: Some(()),
            suppress_vt_csi: Some(()),
            suppress_incoming_call_barring: Some(()),
            gsm_scf_initiated_call: Some(()),
            basic_service_group2: Some(Opaque::new(vec![0x83, 0x01, 0x21])),
            network_signal_info2: Some(opaque()),
            suppress_mtss: Some(bits(&[true, false])),
            mt_roaming_retry_supported: Some(()),
            call_priority: Some(1.into()),
            ..SendRoutingInfoArg::new(e164(MSISDN_DIGITS), e164(SC_DIGITS))
        }),
    );

    emit(
        "provide_roaming_number_arg",
        op_codes::PROVIDE_ROAMING_NUMBER,
        None,
        26,
        ber(&ProvideRoamingNumberArg {
            msisdn: Some(e164(MSISDN_DIGITS)),
            lmsi: Some(oct(&[0x00, 0x00, 0x00, 0x01])),
            gsm_bearer_capability: Some(opaque()),
            network_signal_info: Some(opaque()),
            suppression_of_announcement: Some(()),
            gmsc_address: Some(e164(SC_DIGITS)),
            call_reference_number: Some(oct(&[0x01, 0x02])),
            or_interrogation: Some(()),
            extension_container: Some(extension_container()),
            alerting_pattern: Some(oct(&[0x01])),
            ccbs_call: Some(()),
            supported_camel_phases_in_interrogating_node: Some(bits(&[true])),
            additional_signal_info: Some(opaque()),
            or_not_supported_in_gmsc: Some(()),
            pre_paging_supported: Some(()),
            long_ftn_supported: Some(()),
            suppress_vt_csi: Some(()),
            offered_camel4_csis_in_interrogating_node: Some(bits(&[true])),
            mt_roaming_retry_supported: Some(()),
            paging_area: Some(opaque()),
            call_priority: Some(1.into()),
            mtrf_indicator: Some(()),
            old_msc_number: Some(e164(MSC_DIGITS)),
            last_used_lte_plmn_id: Some(oct(&[0x00, 0xF1, 0x10])),
            ..ProvideRoamingNumberArg::new(imsi(), e164(MSC_DIGITS))
        }),
    );

    emit_result(
        "provide_roaming_number_res",
        op_codes::PROVIDE_ROAMING_NUMBER,
        None,
        4,
        ber(&ProvideRoamingNumberRes {
            extension_container: Some(extension_container()),
            release_resources_supported: Some(()),
            vmsc_address: Some(e164(MSC_DIGITS)),
            ..ProvideRoamingNumberRes::new(e164(MSC_DIGITS))
        }),
    );

    emit(
        "register_ss_arg",
        op_codes::REGISTER_SS,
        None,
        8,
        ber(&RegisterSsArg {
            teleservice: Some(oct(&[0x21])),
            forwarded_to_number: Some(e164(SC_DIGITS)),
            no_reply_condition_time: Some(20.into()),
            forwarded_to_subaddress: Some(oct(&[0x01, 0x02])),
            default_priority: Some(2.into()),
            nbr_user: Some(3.into()),
            long_ftn_supported: Some(()),
            ..RegisterSsArg::new(oct(&[0x21]))
        }),
    );

    emit(
        "interrogate_ss_arg",
        op_codes::INTERROGATE_SS,
        None,
        3,
        ber(&SsForBsCode {
            bearer_service: Some(oct(&[0x11])),
            long_ftn_supported: Some(()),
            ..SsForBsCode::new(oct(&[0x21]))
        }),
    );

    emit(
        "process_unstructured_ss_request_arg",
        op_codes::PROCESS_UNSTRUCTURED_SS_REQUEST,
        Some(ac::network_unstructured_ss_context(ac::V2)),
        4,
        ber(&ProcessUnstructuredSsRequestArg {
            alerting_pattern: Some(oct(&[0x01])),
            msisdn: Some(e164(MSISDN_DIGITS)),
            ..ProcessUnstructuredSsRequestArg::new(
                oct(&[0x0F]),
                oct(&[0xAA, 0x18, 0x0C, 0x36, 0x02]),
            )
        }),
    );

    emit(
        "reset_arg",
        op_codes::RESET,
        None,
        6,
        ber(&ResetArg {
            hlr_list: Some(vec![imsi()]),
            extension_container: Some(extension_container()),
            reset_id_list: Some(opaque()),
            subscription_data: Some(opaque()),
            subscription_data_deletion: Some(opaque()),
            ..ResetArg::new(SendingNodeNumber::HlrNumber(e164(SC_DIGITS)))
        }),
    );

    emit(
        "restore_data_arg",
        op_codes::RESTORE_DATA,
        None,
        5,
        ber(&RestoreDataArg {
            lmsi: Some(oct(&[0x00, 0x00, 0x00, 0x01])),
            extension_container: Some(extension_container()),
            vlr_capability: Some(opaque()),
            restoration_indicator: Some(()),
            ..RestoreDataArg::new(imsi())
        }),
    );

    emit_result(
        "restore_data_res",
        op_codes::RESTORE_DATA,
        None,
        3,
        ber(&RestoreDataRes {
            ms_not_reachable: Some(()),
            extension_container: Some(extension_container()),
            ..RestoreDataRes::new(e164(SC_DIGITS))
        }),
    );

    emit(
        "activate_trace_mode_arg",
        op_codes::ACTIVATE_TRACE_MODE,
        None,
        12,
        ber(&ActivateTraceModeArg {
            imsi: Some(imsi()),
            omc_id: Some(e164(SC_DIGITS)),
            extension_container: Some(extension_container()),
            trace_reference2: Some(oct(&[0x09, 0x08, 0x07])),
            trace_depth_list: Some(opaque()),
            trace_ne_type_list: Some(bits(&[true, false, true])),
            trace_interface_list: Some(opaque()),
            trace_event_list: Some(opaque()),
            trace_collection_entity: Some(oct(&[10, 0, 0, 9])),
            mdt_configuration: Some(opaque()),
            ..ActivateTraceModeArg::new(oct(&[0x01, 0x02, 0x03]), 1.into())
        }),
    );

    emit(
        "deactivate_trace_mode_arg",
        op_codes::DEACTIVATE_TRACE_MODE,
        None,
        4,
        ber(&DeactivateTraceModeArg {
            imsi: Some(imsi()),
            extension_container: Some(extension_container()),
            trace_reference2: Some(oct(&[0x09, 0x08, 0x07])),
            ..DeactivateTraceModeArg::new(oct(&[0x01, 0x02, 0x03]))
        }),
    );

    emit(
        "check_imei_arg",
        op_codes::CHECK_IMEI,
        None,
        3,
        ber(&CheckImeiArg {
            extension_container: Some(extension_container()),
            ..CheckImeiArg::equipment_status_only(oct(&[0x01; 8]))
        }),
    );

    emit_result(
        "check_imei_res",
        op_codes::CHECK_IMEI,
        None,
        3,
        ber(&CheckImeiRes {
            equipment_status: Some(EquipmentStatus::GreyListed),
            bmuef: Some(UesbiIu {
                uesbi_iu_a: Some(bits(&[true, false])),
                uesbi_iu_b: Some(bits(&[false, true])),
            }),
            extension_container: Some(extension_container()),
        }),
    );
}

fn new_operation_vectors() {
    use gsm_map::operations::auth::AuthenticationFailureReportArg;
    use gsm_map::operations::call_handling::{
        IstAlertArg, IstAlertRes, ReleaseResourcesArg, RemoteUserFreeArg, RemoteUserFreeRes,
        ResumeCallHandlingArg, SetReportingStateArg, SetReportingStateRes, StatusReportArg,
    };
    use gsm_map::operations::group_call::{
        ForwardGroupCallSignallingArg, PrepareGroupCallArg, PrepareGroupCallRes,
        ProcessGroupCallSignallingArg, SendGroupCallEndSignalArg, SendGroupCallInfoArg,
        SendGroupCallInfoRes,
    };
    use gsm_map::operations::lcs::{
        LcsAreaEventRequestArg, LcsLocationNotificationArg, LcsLocationNotificationRes,
        LcsLocationUpdateArg, LcsLocationUpdateRes, LcsMolrArg, LcsMolrRes,
        LcsPeriodicLocationCancellationArg, LcsPeriodicLocationRequestArg,
        LcsPeriodicLocationRequestRes,
    };
    use gsm_map::operations::location::{
        CancelVcsgLocationArg, UpdateVcsgLocationArg, UpdateVcsgLocationRes,
    };
    use gsm_map::operations::mt_forward_sm::{MtForwardSmVgcsArg, MtForwardSmVgcsRes};
    use gsm_map::operations::notification::{
        NoteMmEventArg, NoteSubscriberDataModifiedArg, SsInvocationNotificationArg,
    };
    use gsm_map::operations::subscriber_info::{
        AnyTimeSubscriptionInterrogationArg, AnyTimeSubscriptionInterrogationRes,
    };
    use gsm_map::operations::supplementary::{
        CallDeflectionArg, EraseCcEntryArg, EraseCcEntryRes, NotifySsArg, RegisterCcEntryArg,
        UserUserServiceArg,
    };

    emit(
        "note_subscriber_data_modified_arg",
        op_codes::NOTE_SUBSCRIBER_DATA_MODIFIED,
        None,
        15,
        ber(&NoteSubscriberDataModifiedArg {
            forwarding_info_for_cse: Some(opaque()),
            call_barring_info_for_cse: Some(opaque()),
            odb_info: Some(opaque()),
            camel_subscription_info: Some(opaque()),
            all_information_sent: Some(()),
            extension_container: Some(extension_container()),
            ue_reachable: Some(bits(&[true, false, true])),
            csg_subscription_data_list: Some(opaque()),
            cw_data: Some(opaque()),
            ch_data: Some(opaque()),
            clip_data: Some(opaque()),
            clir_data: Some(opaque()),
            ect_data: Some(opaque()),
            ..NoteSubscriberDataModifiedArg::new(imsi(), e164(MSISDN_DIGITS))
        }),
    );

    emit(
        "ss_invocation_notification_arg",
        op_codes::SS_INVOCATION_NOTIFICATION,
        None,
        7,
        ber(&SsInvocationNotificationArg {
            ss_event_specification: Some(opaque()),
            extension_container: Some(extension_container()),
            b_subscriber_number: Some(e164(MSC_DIGITS)),
            ccbs_request_state: Some(2.into()),
            ..SsInvocationNotificationArg::new(imsi(), e164(MSISDN_DIGITS), oct(&[0x41]))
        }),
    );

    emit(
        "note_mm_event_arg",
        op_codes::NOTE_MM_EVENT,
        None,
        9,
        ber(&NoteMmEventArg {
            location_information: Some(LocationInformation {
                age_of_location_information: Some(3.into()),
                ..Default::default()
            }),
            supported_camel_phases: Some(bits(&[true, true])),
            extension_container: Some(extension_container()),
            location_information_gprs: Some(opaque()),
            offered_camel4_functionalities: Some(bits(&[true])),
            ..NoteMmEventArg::new(7.into(), oct(&[0x00]), imsi(), e164(MSISDN_DIGITS))
        }),
    );

    emit(
        "authentication_failure_report_arg",
        op_codes::AUTHENTICATION_FAILURE_REPORT,
        Some(ac::authentication_failure_report_context(ac::V3)),
        8,
        ber(&AuthenticationFailureReportArg {
            extension_container: Some(extension_container()),
            re_attempt: Some(true),
            access_type: Some(4.into()),
            rand: Some(oct(&[0x11; 16])),
            vlr_number: Some(e164(MSC_DIGITS)),
            sgsn_number: Some(e164(MSC_DIGITS)),
            ..AuthenticationFailureReportArg::new(imsi(), 0.into())
        }),
    );

    emit(
        "mt_forward_sm_vgcs_arg",
        op_codes::MT_FORWARD_SM_VGCS,
        None,
        4,
        ber(&MtForwardSmVgcsArg {
            asci_call_reference: oct(&[0x01, 0x02, 0x03]),
            sm_rp_oa: SmRpOa::MsIsdn(e164(MSISDN_DIGITS)),
            // A TPDU the SMS sub-dissector treats as complete: a synthetic
            // fragment would leave it waiting and swallow the rest of the frame.
            sm_rp_ui: oct(&[0x01, 0x00, 0x00, 0x00, 0x00]),
            extension_container: Some(extension_container()),
        }),
    );

    emit_result(
        "mt_forward_sm_vgcs_res",
        op_codes::MT_FORWARD_SM_VGCS,
        None,
        5,
        ber(&MtForwardSmVgcsRes {
            ongoing_call: Some(()),
            sm_rp_ui: Some(oct(&[0x01])),
            dispatcher_list: Some(vec![e164(MSC_DIGITS)]),
            extension_container: Some(extension_container()),
            additional_dispatcher_list: Some(vec![e164(MSC_DIGITS)]),
        }),
    );

    emit(
        "alert_service_centre_without_result_arg",
        op_codes::ALERT_SERVICE_CENTRE_WITHOUT_RESULT,
        None,
        12,
        ber(&AlertServiceCentreArg {
            imsi: Some(imsi()),
            correlation_id: Some(correlation_id()),
            maximum_ue_availability_time: Some(oct(&[0x22, 0x01, 0x01, 0x00])),
            sms_gmsc_alert_event: Some(SmsGmscAlertEvent::MsAvailableForMtSms),
            sms_gmsc_diameter_address: Some(diameter("gmsc.ex.nl")),
            new_sgsn_number: Some(e164(MSC_DIGITS)),
            new_sgsn_diameter_address: Some(diameter("sgsn.ex.nl")),
            new_mme_number: Some(e164(MSC_DIGITS)),
            new_mme_diameter_address: Some(diameter("mme.ex.nl")),
            new_msc_number: Some(e164(MSC_DIGITS)),
            ..AlertServiceCentreArg::new(e164(MSISDN_DIGITS), e164(SC_DIGITS))
        }),
    );

    emit(
        "update_vcsg_location_arg",
        op_codes::UPDATE_VCSG_LOCATION,
        None,
        5,
        ber(&UpdateVcsgLocationArg {
            extension_container: Some(extension_container()),
            vlr_number: Some(e164(MSC_DIGITS)),
            sgsn_number: Some(e164(MSC_DIGITS)),
            msisdn: Some(e164(MSISDN_DIGITS)),
            ..UpdateVcsgLocationArg::new(imsi())
        }),
    );

    emit_result(
        "update_vcsg_location_res",
        op_codes::UPDATE_VCSG_LOCATION,
        None,
        2,
        ber(&UpdateVcsgLocationRes {
            temporary_empty_subscription_data_indicator: Some(()),
            extension_container: Some(extension_container()),
        }),
    );

    emit(
        "cancel_vcsg_location_arg",
        op_codes::CANCEL_VCSG_LOCATION,
        None,
        2,
        ber(&CancelVcsgLocationArg {
            identity: Identity::Imsi(imsi()),
            extension_container: Some(extension_container()),
        }),
    );

    emit(
        "resume_call_handling_arg",
        op_codes::RESUME_CALL_HANDLING,
        None,
        15,
        ber(&ResumeCallHandlingArg {
            call_reference_number: Some(oct(&[0x01, 0x02])),
            basic_service_group: Some(Opaque::new(vec![0x82, 0x01, 0x11])),
            forwarding_data: Some(opaque()),
            imsi: Some(imsi()),
            cug_check_info: Some(opaque()),
            o_csi: Some(opaque()),
            extension_container: Some(extension_container()),
            ccbs_possible: Some(()),
            msisdn: Some(e164(MSISDN_DIGITS)),
            uu_data: Some(opaque()),
            all_information_sent: Some(()),
            d_csi: Some(opaque()),
            o_bcsm_camel_tdp_criteria_list: Some(opaque()),
            basic_service_group2: Some(Opaque::new(vec![0x83, 0x01, 0x21])),
            mt_roaming_retry: Some(()),
        }),
    );

    emit(
        "release_resources_arg",
        op_codes::RELEASE_RESOURCES,
        None,
        2,
        ber(&ReleaseResourcesArg {
            msrn: e164(MSC_DIGITS),
            extension_container: Some(extension_container()),
        }),
    );

    emit(
        "set_reporting_state_arg",
        op_codes::SET_REPORTING_STATE,
        None,
        4,
        ber(&SetReportingStateArg {
            imsi: Some(imsi()),
            lmsi: Some(oct(&[0x00, 0x00, 0x00, 0x01])),
            ccbs_monitoring: Some(1.into()),
            extension_container: Some(extension_container()),
        }),
    );

    emit_result(
        "set_reporting_state_res",
        op_codes::SET_REPORTING_STATE,
        None,
        2,
        ber(&SetReportingStateRes {
            ccbs_subscriber_status: Some(1.into()),
            extension_container: Some(extension_container()),
        }),
    );

    emit(
        "status_report_arg",
        op_codes::STATUS_REPORT,
        None,
        4,
        ber(&StatusReportArg {
            event_report_data: Some(opaque()),
            call_report_data: Some(opaque()),
            extension_container: Some(extension_container()),
            ..StatusReportArg::new(imsi())
        }),
    );

    emit(
        "remote_user_free_arg",
        op_codes::REMOTE_USER_FREE,
        None,
        7,
        ber(&RemoteUserFreeArg {
            call_info: Some(opaque()),
            ccbs_feature: Some(opaque()),
            translated_b_number: Some(e164(MSC_DIGITS)),
            replace_b_number: Some(()),
            alerting_pattern: Some(oct(&[0x01])),
            extension_container: Some(extension_container()),
            ..RemoteUserFreeArg::new(imsi())
        }),
    );

    emit_result(
        "remote_user_free_res",
        op_codes::REMOTE_USER_FREE,
        None,
        2,
        ber(&RemoteUserFreeRes {
            ruf_outcome: Some(0.into()),
            extension_container: Some(extension_container()),
        }),
    );

    emit(
        "ist_alert_arg",
        op_codes::IST_ALERT,
        None,
        2,
        ber(&IstAlertArg {
            imsi: imsi(),
            extension_container: Some(extension_container()),
        }),
    );

    emit_result(
        "ist_alert_res",
        op_codes::IST_ALERT,
        None,
        4,
        ber(&IstAlertRes {
            ist_alert_timer: Some(30.into()),
            ist_information_withdraw: Some(()),
            call_termination_indicator: Some(1.into()),
            extension_container: Some(extension_container()),
        }),
    );

    emit(
        "notify_ss_arg",
        op_codes::NOTIFY_SS,
        None,
        13,
        ber(&NotifySsArg {
            ss_code: Some(oct(&[0x21])),
            ss_status: Some(oct(&[0x05])),
            ss_notification: Some(bits(&[true, false, true])),
            call_is_waiting_indicator: Some(()),
            call_on_hold_indicator: Some(1.into()),
            mpty_indicator: Some(()),
            cug_index: Some(1.into()),
            clir_suppression_rejected: Some(()),
            ect_indicator: Some(opaque()),
            name_indicator: Some(opaque()),
            ccbs_feature: Some(opaque()),
            alerting_pattern: Some(oct(&[0x01])),
            multicall_indicator: Some(0.into()),
        }),
    );

    emit(
        "register_cc_entry_arg",
        op_codes::REGISTER_CC_ENTRY,
        None,
        2,
        ber(&RegisterCcEntryArg {
            ss_code: oct(&[0x21]),
            ccbs_data: Some(opaque()),
        }),
    );

    emit(
        "erase_cc_entry_arg",
        op_codes::ERASE_CC_ENTRY,
        None,
        2,
        ber(&EraseCcEntryArg {
            ss_code: oct(&[0x21]),
            ccbs_index: Some(1.into()),
        }),
    );

    emit_result(
        "erase_cc_entry_res",
        op_codes::ERASE_CC_ENTRY,
        None,
        2,
        ber(&EraseCcEntryRes {
            ss_code: Some(oct(&[0x21])),
            ss_status: Some(oct(&[0x05])),
        }),
    );

    emit(
        "call_deflection_arg",
        op_codes::CALL_DEFLECTION,
        None,
        2,
        ber(&CallDeflectionArg {
            deflected_to_number: e164(MSC_DIGITS),
            deflected_to_subaddress: Some(oct(&[0x01])),
        }),
    );

    emit(
        "user_user_service_arg",
        op_codes::USER_USER_SERVICE,
        None,
        2,
        ber(&UserUserServiceArg {
            uus_service: 1.into(),
            uus_required: true,
        }),
    );

    emit(
        "any_time_subscription_interrogation_arg",
        op_codes::ANY_TIME_SUBSCRIPTION_INTERROGATION,
        None,
        5,
        ber(&AnyTimeSubscriptionInterrogationArg {
            subscriber_identity: SubscriberIdentity::Msisdn(e164(MSISDN_DIGITS)),
            requested_subscription_info: opaque(),
            gsm_scf_address: Some(e164(IP_SM_GW_DIGITS)),
            extension_container: Some(extension_container()),
            long_ftn_supported: Some(()),
        }),
    );

    emit_result(
        "any_time_subscription_interrogation_res",
        op_codes::ANY_TIME_SUBSCRIPTION_INTERROGATION,
        None,
        16,
        ber(&AnyTimeSubscriptionInterrogationRes {
            call_forwarding_data: Some(opaque()),
            call_barring_data: Some(opaque()),
            odb_info: Some(opaque()),
            camel_subscription_info: Some(opaque()),
            supported_vlr_camel_phases: Some(bits(&[true])),
            supported_sgsn_camel_phases: Some(bits(&[true])),
            extension_container: Some(extension_container()),
            offered_camel4_csis_in_vlr: Some(bits(&[true])),
            offered_camel4_csis_in_sgsn: Some(bits(&[true])),
            msisdn_bs_list: Some(opaque()),
            csg_subscription_data_list: Some(opaque()),
            cw_data: Some(opaque()),
            ch_data: Some(opaque()),
            clip_data: Some(opaque()),
            clir_data: Some(opaque()),
            ect_data: Some(opaque()),
        }),
    );

    emit(
        "prepare_group_call_arg",
        op_codes::PREPARE_GROUP_CALL,
        None,
        13,
        ber(&PrepareGroupCallArg {
            group_key_number_vk_id: Some(1.into()),
            group_key: Some(oct(&[0x11; 8])),
            priority: Some(2.into()),
            uplink_free: Some(()),
            extension_container: Some(extension_container()),
            vstk: Some(oct(&[0x22; 16])),
            vstk_rand: Some(bits(&[true, false, true, false, true])),
            talker_channel_parameter: Some(()),
            uplink_reply_indicator: Some(()),
            ..PrepareGroupCallArg::new(
                oct(&[0x11]),
                oct(&[0x01, 0x02, 0x03]),
                oct(&[0x01, 0x02]),
                oct(&[0x01]),
            )
        }),
    );

    emit_result(
        "prepare_group_call_res",
        op_codes::PREPARE_GROUP_CALL,
        None,
        2,
        ber(&PrepareGroupCallRes {
            group_call_number: e164(MSC_DIGITS),
            extension_container: Some(extension_container()),
        }),
    );

    emit(
        "send_group_call_end_signal_arg",
        op_codes::SEND_GROUP_CALL_END_SIGNAL,
        None,
        4,
        ber(&SendGroupCallEndSignalArg {
            imsi: Some(imsi()),
            extension_container: Some(extension_container()),
            talker_priority: Some(1.into()),
            additional_info: Some(bits(&[true, false])),
        }),
    );

    emit(
        "process_group_call_signalling_arg",
        op_codes::PROCESS_GROUP_CALL_SIGNALLING,
        None,
        8,
        ber(&ProcessGroupCallSignallingArg {
            extension_container: Some(extension_container()),
            uplink_request: Some(()),
            uplink_release_indication: Some(()),
            release_group_call: Some(()),
            talker_priority: Some(1.into()),
            additional_info: Some(bits(&[true])),
            emergency_mode_reset_command_flag: Some(()),
            an_apdu: Some(opaque()),
        }),
    );

    emit(
        "forward_group_call_signalling_arg",
        op_codes::FORWARD_GROUP_CALL_SIGNALLING,
        None,
        13,
        ber(&ForwardGroupCallSignallingArg {
            imsi: Some(imsi()),
            extension_container: Some(extension_container()),
            uplink_request_ack: Some(()),
            uplink_release_indication: Some(()),
            uplink_reject_command: Some(()),
            uplink_seized_command: Some(()),
            uplink_release_command: Some(()),
            state_attributes: Some(opaque()),
            talker_priority: Some(1.into()),
            additional_info: Some(bits(&[true])),
            emergency_mode_reset_command_flag: Some(()),
            sm_rp_ui: Some(oct(&[0x01, 0x02])),
            an_apdu: Some(opaque()),
        }),
    );

    emit(
        "send_group_call_info_arg",
        op_codes::SEND_GROUP_CALL_INFO,
        None,
        10,
        ber(&SendGroupCallInfoArg {
            cell_id: Some(oct(&[0x00, 0xF1, 0x10, 0x00, 0x01, 0x00, 0x02])),
            imsi: Some(imsi()),
            tmsi: Some(oct(&[0x11, 0x22, 0x33, 0x44])),
            additional_info: Some(bits(&[true])),
            talker_priority: Some(1.into()),
            cksn: Some(oct(&[0x01])),
            extension_container: Some(extension_container()),
            ..SendGroupCallInfoArg::new(0.into(), oct(&[0x01, 0x02, 0x03]), oct(&[0x11]))
        }),
    );

    emit_result(
        "send_group_call_info_res",
        op_codes::SEND_GROUP_CALL_INFO,
        None,
        7,
        ber(&SendGroupCallInfoRes {
            anchor_msc_address: Some(e164(MSC_DIGITS)),
            asci_call_reference: Some(oct(&[0x01, 0x02, 0x03])),
            imsi: Some(imsi()),
            additional_info: Some(bits(&[true])),
            additional_subscriptions: Some(bits(&[true, false])),
            kc: Some(oct(&[0x33; 8])),
            extension_container: Some(extension_container()),
        }),
    );

    emit(
        "lcs_periodic_location_cancellation_arg",
        op_codes::LCS_PERIODIC_LOCATION_CANCELLATION,
        None,
        2,
        ber(&LcsPeriodicLocationCancellationArg {
            reference_number: oct(&[0x07]),
            h_gmlc_address: Some(oct(&[10, 0, 0, 5])),
        }),
    );

    emit(
        "lcs_location_update_arg",
        op_codes::LCS_LOCATION_UPDATE,
        None,
        4,
        ber(&LcsLocationUpdateArg {
            reference_number: oct(&[0x07]),
            add_location_estimate: Some(oct(&[0x11; 8])),
            velocity_estimate: Some(oct(&[0x22; 4])),
            sequence_number: Some(3.into()),
        }),
    );

    emit_result(
        "lcs_location_update_res",
        op_codes::LCS_LOCATION_UPDATE,
        None,
        1,
        ber(&LcsLocationUpdateRes {
            termination_cause: Some(0.into()),
        }),
    );

    emit(
        "lcs_periodic_location_request_arg",
        op_codes::LCS_PERIODIC_LOCATION_REQUEST,
        None,
        2,
        ber(&LcsPeriodicLocationRequestArg {
            reference_number: oct(&[0x07]),
            periodic_ldr_info: opaque(),
        }),
    );

    emit_result(
        "lcs_periodic_location_request_res",
        op_codes::LCS_PERIODIC_LOCATION_REQUEST,
        None,
        1,
        ber(&LcsPeriodicLocationRequestRes {
            mo_lr_short_circuit: Some(()),
        }),
    );

    emit(
        "lcs_area_event_request_arg",
        op_codes::LCS_AREA_EVENT_REQUEST,
        None,
        4,
        ber(&LcsAreaEventRequestArg {
            reference_number: oct(&[0x07]),
            h_gmlc_address: Some(oct(&[10, 0, 0, 5])),
            deferred_location_event_type: Some(bits(&[true, false, true, false])),
            area_event_info: Some(opaque()),
        }),
    );

    emit(
        "lcs_molr_arg",
        op_codes::LCS_MOLR,
        None,
        11,
        ber(&LcsMolrArg {
            molr_type: Some(0.into()),
            location_method: Some(1.into()),
            lcs_qos: Some(opaque()),
            lcs_client_external_id: Some(opaque()),
            mlc_number: Some(e164(SC_DIGITS)),
            gps_assistance_data: Some(oct(&[0x01, 0x02])),
            supported_gad_shapes: Some(bits(&[true, false, true])),
            lcs_service_type_id: Some(1.into()),
            age_of_location_info: Some(2.into()),
            location_type: Some(opaque()),
            pseudonym_indicator: Some(()),
            ..Default::default()
        }),
    );

    emit_result(
        "lcs_molr_res",
        op_codes::LCS_MOLR,
        None,
        9,
        ber(&LcsMolrRes {
            location_estimate: Some(oct(&[0x10; 8])),
            deciphering_keys: Some(oct(&[0x11; 4])),
            add_location_estimate: Some(oct(&[0x12; 8])),
            velocity_estimate: Some(oct(&[0x22; 4])),
            reference_number: Some(oct(&[0x07])),
            h_gmlc_address: Some(oct(&[10, 0, 0, 5])),
            mo_lr_short_circuit: Some(()),
            reporting_plmn_list: Some(opaque()),
            timestamp_of_location_estimate: Some(oct(&[0x22, 0x01, 0x01, 0x00])),
        }),
    );

    emit(
        "lcs_location_notification_arg",
        op_codes::LCS_LOCATION_NOTIFICATION,
        None,
        2,
        ber(&LcsLocationNotificationArg {
            notification_type: Some(1.into()),
            location_type: Some(opaque()),
        }),
    );

    emit_result(
        "lcs_location_notification_res",
        op_codes::LCS_LOCATION_NOTIFICATION,
        None,
        3,
        ber(&LcsLocationNotificationRes {
            verification_response: Some(1.into()),
            location_privacy_indication: Some(0.into()),
            valid_time_period: Some(opaque()),
        }),
    );
}

fn handover_vectors() {
    // ProtocolId is an untagged ENUMERATED, so it carries the ENUMERATED
    // universal tag and not INTEGER's — the shape this frame pins down.
    let apdu = ExternalSignalInfo {
        extension_container: Some(extension_container()),
        ..ExternalSignalInfo::new(3.into(), oct(&[0x01, 0x02, 0x03]))
    };

    emit(
        "prepare_handover_arg",
        op_codes::PREPARE_HANDOVER,
        Some(ac::handover_control_context(ac::V3)),
        3,
        ber(&PrepareHandoverArg {
            target_cell_id: Some(oct(&[0x00, 0xF1, 0x10, 0x00, 0x01, 0x00, 0x02])),
            ho_number_not_required: Some(()),
            bss_apdu: Some(apdu.clone()),
        }),
    );

    emit(
        "send_end_signal_arg",
        op_codes::SEND_END_SIGNAL,
        None,
        3,
        ber(&apdu),
    );

    emit(
        "process_access_signalling_arg",
        op_codes::PROCESS_ACCESS_SIGNALLING,
        None,
        3,
        ber(&apdu),
    );

    emit(
        "prepare_subsequent_handover_arg",
        op_codes::PREPARE_SUBSEQUENT_HANDOVER,
        None,
        8,
        ber(&PrepareSubsequentHandoverArg {
            target_cell_id: Some(oct(&[0x00, 0xF1, 0x10, 0x00, 0x01, 0x00, 0x02])),
            target_rnc_id: Some(oct(&[0x00, 0xF1, 0x10, 0x00, 0x01])),
            an_apdu: Some(opaque()),
            selected_rab_id: Some(1.into()),
            extension_container: Some(extension_container()),
            geran_classmark: Some(oct(&[0x33, 0x19])),
            rab_configuration_indicator: Some(()),
            ..PrepareSubsequentHandoverArg::new(e164(MSC_DIGITS))
        }),
    );
}

fn lcs_vectors() {
    emit(
        "provide_subscriber_location_arg",
        lcs_op_codes::PROVIDE_SUBSCRIBER_LOCATION,
        None,
        21,
        ber(&ProvideSubscriberLocationArg {
            lcs_client_id: Some(LcsClientId {
                lcs_client_external_id: Some(opaque()),
                lcs_client_dialed_by_ms: Some(e164(SC_DIGITS)),
                lcs_client_internal_id: Some(1.into()),
                lcs_client_name: Some(opaque()),
                lcs_apn: Some(oct(b"lcs.ex.nl")),
                lcs_requestor_id: Some(opaque()),
                ..LcsClientId::new(0.into())
            }),
            privacy_override: Some(()),
            imsi: Some(imsi()),
            msisdn: Some(e164(MSISDN_DIGITS)),
            lmsi: Some(oct(&[0x00, 0x00, 0x00, 0x01])),
            imei: Some(oct(&[0x01; 8])),
            lcs_priority: Some(oct(&[0x00])),
            lcs_qos: Some(opaque()),
            extension_container: Some(extension_container()),
            supported_gad_shapes: Some(bits(&[true, false, true])),
            lcs_reference_number: Some(oct(&[0x07])),
            lcs_service_type_id: Some(1.into()),
            lcs_codeword: Some(opaque()),
            lcs_privacy_check: Some(opaque()),
            area_event_info: Some(opaque()),
            h_gmlc_address: Some(oct(&[10, 0, 0, 5])),
            mo_lr_short_circuit_indicator: Some(()),
            periodic_ldr_info: Some(opaque()),
            reporting_plmn_list: Some(opaque()),
            ..ProvideSubscriberLocationArg::new(opaque_tlv(), e164(SC_DIGITS))
        }),
    );

    emit(
        "send_routing_info_for_lcs_arg",
        lcs_op_codes::SEND_ROUTING_INFO_FOR_LCS,
        None,
        3,
        ber(&SendRoutingInfoForLcsArg {
            mlc_number: e164(SC_DIGITS),
            target_ms: SubscriberIdentityLcs::Msisdn(e164(MSISDN_DIGITS)),
            extension_container: Some(extension_container()),
        }),
    );

    emit(
        "subscriber_location_report_arg",
        lcs_op_codes::SUBSCRIBER_LOCATION_REPORT,
        None,
        22,
        ber(&SubscriberLocationReportArg {
            lcs_event: LcsEvent::EmergencyCallOrigination,
            lcs_client_id: LcsClientId::new(0.into()),
            lcs_location_info: opaque_tlv(),
            msisdn: Some(e164(MSISDN_DIGITS)),
            imsi: Some(imsi()),
            imei: Some(oct(&[0x01; 8])),
            na_esrd: Some(e164(MSC_DIGITS)),
            na_esrk: Some(e164(MSC_DIGITS)),
            location_estimate: Some(oct(&[0x10; 8])),
            age_of_location_estimate: Some(1.into()),
            slr_arg_extension_container: Some(opaque()),
            add_location_estimate: Some(oct(&[0x11; 8])),
            deferred_mt_lr_data: Some(opaque()),
            lcs_reference_number: Some(oct(&[0x07])),
            geran_positioning_data: Some(oct(&[0x01, 0x02])),
            utran_positioning_data: Some(oct(&[0x03, 0x04])),
            cell_id_or_sai: Some(Opaque::new(vec![
                0x80, 0x07, 0x00, 0xF1, 0x10, 0x00, 0x01, 0x00, 0x02,
            ])),
            h_gmlc_address: Some(oct(&[10, 0, 0, 5])),
            lcs_service_type_id: Some(1.into()),
            sai_present: Some(()),
            pseudonym_indicator: Some(()),
            accuracy_fulfilment_indicator: Some(0.into()),
        }),
    );
}

fn main() {
    operation_name_vectors();
    context_vectors();
    error_vectors();
    sms_vectors();
    subscriber_info_vectors();
    mobility_vectors();
    gprs_vectors();
    subscriber_data_vectors();
    misc_vectors();
    new_operation_vectors();
    handover_vectors();
    lcs_vectors();
}
