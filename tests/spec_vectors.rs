//! The encoder and the decoder against octets derived by hand from TS 29.002.
//!
//! The vectors and their derivations are in `tests/common/spec_vectors.rs`.
//! Each test builds the value with the public API, requires the encoder to
//! emit exactly the hand-written octets, and requires the decoder to turn
//! those octets, which this crate did not produce, back into the value. The
//! same octets go through Wireshark's dissector in
//! `scripts/wireshark_check.sh`.

mod common;

use common::spec_vectors as spec;
use common::{isdn, pinned, IMSI};
use gsm_map::operations::alert_sc::{AlertServiceCentreArg, SmsGmscAlertEvent};
use gsm_map::operations::auth::{
    AuthenticationQuintuplet, AuthenticationSetList, AuthenticationTriplet, EpcAv,
    SendAuthenticationInfoArg, SendAuthenticationInfoRes,
};
use gsm_map::operations::errors::{
    AbsentSubscriberParam, AbsentSubscriberSmParam, SmDeliveryFailureCause,
    SmEnumeratedDeliveryFailureCause, SubBusyForMtSmsParam, UnexpectedDataParam,
    UnknownSubscriberParam,
};
use gsm_map::operations::gprs_location::{
    EpsInfo, PdnGwIdentity, PdnGwUpdate, UpdateGprsLocationArg, UpdateGprsLocationRes,
};
use gsm_map::operations::inform_sc::InformServiceCentreArg;
use gsm_map::operations::location::{
    CancelLocationArg, CancellationType, Identity, ImsiWithLmsi, UpdateLocationArg,
    UpdateLocationRes,
};
use gsm_map::operations::mo_forward_sm::{MoForwardSmArg, MoForwardSmRes};
use gsm_map::operations::mt_forward_sm::{MtForwardSmArg, MtForwardSmRes};
use gsm_map::operations::ready_for_sm::{AlertReason, ReadyForSmArg};
use gsm_map::operations::report_sm::{
    ReportSmDeliveryStatusArg, ReportSmDeliveryStatusRes, SmDeliveryOutcome,
};
use gsm_map::operations::sri_sm::{
    IpSmGwGuidance, RoutingInfoForSmArg, RoutingInfoForSmRes, SmDeliveryNotIntended,
};
use gsm_map::operations::subscriber_data::{
    InsertSubscriberDataArg, NetworkAccessMode, SubscriberStatus,
};
use gsm_map::operations::subscriber_info::{
    AnyTimeModificationArg, AnyTimeModificationRes, ModificationInstruction,
    ModificationRequestForIpSmGwData, SubscriberIdentity,
};
use gsm_map::types::{
    AdditionalNumber, LocationInfoWithLmsi, MwStatusFlags, NetworkNodeDiameterAddress,
    OpenEnumerated, SmRpDa, SmRpOa,
};
use rasn::types::{BitString, OctetString};

fn oct(bytes: &[u8]) -> OctetString {
    OctetString::from_slice(bytes)
}

fn imsi() -> OctetString {
    oct(IMSI)
}

fn number(digits: &str) -> OctetString {
    isdn(digits).into()
}

fn subscriber() -> OctetString {
    number("15550100999")
}

fn service_centre() -> OctetString {
    number("15550199")
}

fn bits(values: &[bool]) -> BitString {
    let mut out = BitString::new();
    for value in values {
        out.push(*value);
    }
    out
}

/// 00 01 .. 0f and the like: `count` octets counting up from `first`.
fn run(first: u8, count: u8) -> OctetString {
    oct(&(0..count).map(|i| first + i).collect::<Vec<u8>>())
}

// ── sendRoutingInfoForSM ────────────────────────────────────────────────────

#[test]
fn send_routing_info_for_sm_argument() {
    pinned(
        &RoutingInfoForSmArg {
            gprs_support_indicator: Some(()),
            sm_rp_mti: Some(0.into()),
            sm_delivery_not_intended: Some(SmDeliveryNotIntended::OnlyImsiRequested),
            ip_sm_gw_guidance_indicator: Some(()),
            ..RoutingInfoForSmArg::new(subscriber(), true, service_centre())
        },
        spec::SRI_SM_ARG.octets,
    );
}

#[test]
fn send_routing_info_for_sm_result_with_an_additional_msc_and_guidance() {
    pinned(
        &RoutingInfoForSmRes {
            ip_sm_gw_guidance: Some(IpSmGwGuidance {
                minimum_delivery_time_value: 30.into(),
                recommended_delivery_time_value: 300.into(),
                extension_container: None,
            }),
            ..RoutingInfoForSmRes::new(
                imsi(),
                LocationInfoWithLmsi {
                    gprs_node_indicator: Some(()),
                    additional_number: Some(AdditionalNumber::MscNumber(number("15550100010"))),
                    ..LocationInfoWithLmsi::new(number("15550100020"))
                },
            )
        },
        spec::SRI_SM_RES_ADDITIONAL_MSC.octets,
    );
}

#[test]
fn send_routing_info_for_sm_result_with_an_additional_sgsn_and_a_third_number() {
    pinned(
        &RoutingInfoForSmRes::new(
            imsi(),
            LocationInfoWithLmsi {
                lmsi: Some(oct(&[0x00, 0x00, 0x00, 0x2a])),
                additional_number: Some(AdditionalNumber::SgsnNumber(number("15550100020"))),
                third_number: Some(AdditionalNumber::MscNumber(number("15550100030"))),
                ..LocationInfoWithLmsi::new(number("15550100010"))
            },
        ),
        spec::SRI_SM_RES_ADDITIONAL_SGSN.octets,
    );
}

// ── mo-forwardSM and mt-forwardSM ───────────────────────────────────────────

#[test]
fn mo_forward_sm_argument_and_result() {
    let submit = "01 00 0b 91 51 55 10 00 88 f8 00 00 02 c8 34";
    pinned(
        &MoForwardSmArg {
            imsi: Some(imsi()),
            ..MoForwardSmArg::new(
                SmRpDa::ServiceCentreAddressDa(service_centre()),
                SmRpOa::MsIsdn(subscriber()),
                common::vector(submit).into(),
            )
        },
        spec::MO_FORWARD_SM_ARG.octets,
    );
    pinned(
        &MoForwardSmRes {
            sm_rp_ui: Some(common::vector("01 00 62 01 01 00 00 00 00").into()),
            extension_container: None,
        },
        spec::MO_FORWARD_SM_RES.octets,
    );
}

#[test]
fn mt_forward_sm_argument_and_result() {
    let deliver = "04 0b 91 51 55 10 00 88 f8 00 00 62 01 01 00 00 00 00 02 c8 34";
    pinned(
        &MtForwardSmArg {
            more_messages_to_send: Some(()),
            sm_delivery_timer: Some(60.into()),
            sms_over_ip_only_indicator: Some(()),
            ..MtForwardSmArg::new(
                SmRpDa::Imsi(imsi()),
                SmRpOa::ServiceCentreAddressOa(service_centre()),
                common::vector(deliver).into(),
            )
        },
        spec::MT_FORWARD_SM_ARG.octets,
    );
    pinned(
        &MtForwardSmRes {
            sm_rp_ui: Some(oct(&[0x00, 0x00])),
            extension_container: None,
        },
        spec::MT_FORWARD_SM_RES.octets,
    );
}

// ── reportSM-DeliveryStatus, alertServiceCentre, informServiceCentre, readyForSM ──

#[test]
fn report_sm_delivery_status_argument_and_result() {
    pinned(
        &ReportSmDeliveryStatusArg {
            absent_subscriber_diagnostic_sm: Some(1.into()),
            ip_sm_gw_indicator: Some(()),
            ip_sm_gw_sm_delivery_outcome: Some(SmDeliveryOutcome::AbsentSubscriber),
            ip_sm_gw_absent_subscriber_diagnostic_sm: Some(4.into()),
            ..ReportSmDeliveryStatusArg::new(
                subscriber(),
                service_centre(),
                SmDeliveryOutcome::AbsentSubscriber,
            )
        },
        spec::REPORT_SM_DELIVERY_STATUS_ARG.octets,
    );
    pinned(
        &ReportSmDeliveryStatusRes {
            stored_msisdn: Some(subscriber()),
            extension_container: None,
        },
        spec::REPORT_SM_DELIVERY_STATUS_RES.octets,
    );
}

#[test]
fn alert_service_centre_argument() {
    pinned(
        &AlertServiceCentreArg {
            imsi: Some(imsi()),
            sms_gmsc_alert_event: Some(SmsGmscAlertEvent::MsUnderNewServingNode),
            ..AlertServiceCentreArg::new(subscriber(), service_centre())
        },
        spec::ALERT_SERVICE_CENTRE_ARG.octets,
    );
}

#[test]
fn inform_service_centre_argument() {
    let flags = MwStatusFlags {
        mnrf_set: true,
        mcef_set: true,
        ..MwStatusFlags::default()
    };
    pinned(
        &InformServiceCentreArg {
            stored_msisdn: Some(subscriber()),
            mw_status: Some(flags.to_bits()),
            absent_subscriber_diagnostic_sm: Some(1.into()),
            additional_absent_subscriber_diagnostic_sm: Some(2.into()),
            ..InformServiceCentreArg::default()
        },
        spec::INFORM_SERVICE_CENTRE_ARG.octets,
    );
}

#[test]
fn ready_for_sm_argument() {
    pinned(
        &ReadyForSmArg {
            alert_reason_indicator: Some(()),
            ..ReadyForSmArg::new(imsi(), AlertReason::MemoryAvailable)
        },
        spec::READY_FOR_SM_ARG.octets,
    );
}

// ── sendAuthenticationInfo ──────────────────────────────────────────────────

#[test]
fn send_authentication_info_argument() {
    pinned(
        &SendAuthenticationInfoArg {
            immediate_response_preferred: Some(()),
            requesting_node_type: Some(16.into()),
            requesting_plmn_id: Some(oct(&[0x00, 0xf1, 0x10])),
            number_of_requested_additional_vectors: Some(2.into()),
            additional_vectors_are_for_eps: Some(()),
            ..SendAuthenticationInfoArg::new(imsi(), 3.into())
        },
        spec::SEND_AUTHENTICATION_INFO_ARG.octets,
    );
}

#[test]
fn send_authentication_info_result_with_a_triplet() {
    let triplet = AuthenticationTriplet {
        rand: run(0x00, 16),
        sres: oct(&[0xa1, 0xa2, 0xa3, 0xa4]),
        kc: run(0xc0, 8),
    };
    let result = SendAuthenticationInfoRes {
        triplet_list: Some(vec![triplet.clone()]),
        ..SendAuthenticationInfoRes::default()
    };
    pinned(&result, spec::SEND_AUTHENTICATION_INFO_RES_TRIPLET.octets);
    assert_eq!(
        result.authentication_set_list(),
        Some(AuthenticationSetList::TripletList(vec![triplet]))
    );
}

#[test]
fn send_authentication_info_result_with_a_quintuplet() {
    pinned(
        &SendAuthenticationInfoRes {
            quintuplet_list: Some(vec![AuthenticationQuintuplet {
                rand: run(0x00, 16),
                xres: run(0xd0, 8),
                ck: run(0x20, 16),
                ik: run(0x30, 16),
                autn: run(0x40, 16),
            }]),
            ..SendAuthenticationInfoRes::default()
        },
        spec::SEND_AUTHENTICATION_INFO_RES_QUINTUPLET.octets,
    );
}

#[test]
fn send_authentication_info_result_with_an_eps_vector() {
    pinned(
        &SendAuthenticationInfoRes {
            eps_authentication_set_list: Some(vec![EpcAv {
                rand: run(0x00, 16),
                xres: run(0xd0, 8),
                autn: run(0x40, 16),
                kasme: run(0x50, 32),
                extension_container: None,
            }]),
            ue_usage_type: Some(oct(&[0x00, 0x00, 0x00, 0x01])),
            ..SendAuthenticationInfoRes::default()
        },
        spec::SEND_AUTHENTICATION_INFO_RES_EPS.octets,
    );
}

#[test]
fn ue_usage_type_as_an_integer_is_no_longer_what_is_emitted() {
    // Before this was corrected the member was modelled as an INTEGER, so the
    // value 1 went out in one octet, `83 01 01`. UE-UsageType is an OCTET
    // STRING (SIZE (4)); a receiver that checks the size refuses one octet.
    // The decoder still reads it, as the octet string it is on the wire, and
    // the caller sees the wrong length.
    let old: SendAuthenticationInfoRes = common::accepted(&common::vector("a3 03 83 01 01"));
    assert_eq!(old.ue_usage_type, Some(oct(&[0x01])));
    let now = SendAuthenticationInfoRes {
        ue_usage_type: Some(oct(&[0x00, 0x00, 0x00, 0x01])),
        ..SendAuthenticationInfoRes::default()
    };
    assert_eq!(
        gsm_map::encode(&now).unwrap(),
        common::vector("a3 06 83 04 00 00 00 01")
    );
}

// ── updateLocation, updateGprsLocation, cancelLocation ──────────────────────

#[test]
fn update_location_argument_and_result() {
    pinned(
        &UpdateLocationArg {
            inform_previous_network_entity: Some(()),
            // ADD-Info is carried opaquely: its content, imeisv [0].
            add_info: Some(gsm_map::types::Opaque::new(common::vector(
                "80 08 00 11 22 33 44 55 66 77",
            ))),
            ..UpdateLocationArg::new(imsi(), number("15550100010"), number("15550100050"))
        },
        spec::UPDATE_LOCATION_ARG.octets,
    );
    pinned(
        &UpdateLocationRes {
            add_capability: Some(()),
            ..UpdateLocationRes::new(number("15550100040"))
        },
        spec::UPDATE_LOCATION_RES.octets,
    );
}

#[test]
fn a_sequence_carried_opaquely_is_constructed_on_the_wire() {
    // add-info [13] is a SEQUENCE (ADD-Info), so its identifier is `ad`.
    // Before this was corrected the opaque members took the constructed bit
    // from the first octet of their content, and since ADD-Info starts with
    // the primitive imeisv [0] the member went out as `8d`: a primitive
    // element where X.690 8.9.1 requires a constructed one. Those octets are
    // no longer emitted and no longer accepted.
    let previous = spec::UPDATE_LOCATION_ARG.octets.replace("ad 0a", "8d 0a");
    let error = common::refused::<UpdateLocationArg>(&common::vector(&previous));
    assert!(error.contains("constructed"), "{error}");

    // An empty SEQUENCE is emitted, not dropped: pcs-Extensions ::= SEQUENCE {...}.
    use gsm_map::types::{ExtensionContainer, Opaque};
    let container = ExtensionContainer {
        private_extension_list: None,
        pcs_extensions: Some(Opaque::new(Vec::new())),
    };
    pinned(&container, "30 02 a1 00");
}

fn update_gprs_location(eps_info: EpsInfo) -> UpdateGprsLocationArg {
    UpdateGprsLocationArg {
        eps_info: Some(eps_info),
        ..UpdateGprsLocationArg::new(
            imsi(),
            number("15550100020"),
            oct(&[0x04, 0xc0, 0x00, 0x02, 0x01]),
        )
    }
}

#[test]
fn update_gprs_location_argument_with_isr_information() {
    pinned(
        &update_gprs_location(EpsInfo::IsrInformation(bits(&[true, false, true]))),
        spec::UPDATE_GPRS_LOCATION_ARG_ISR.octets,
    );
}

#[test]
fn update_gprs_location_argument_with_a_pdn_gw_update() {
    pinned(
        &update_gprs_location(EpsInfo::PdnGwUpdate(PdnGwUpdate {
            apn: Some(oct(&[0x03, b'i', b'm', b's'])),
            pdn_gw_identity: Some(PdnGwIdentity {
                pdn_gw_ipv4_address: Some(oct(&[0xc0, 0x00, 0x02, 0x0a])),
                ..PdnGwIdentity::default()
            }),
            context_id: Some(5.into()),
            extension_container: None,
        })),
        spec::UPDATE_GPRS_LOCATION_ARG_PDN_GW.octets,
    );
}

#[test]
fn update_gprs_location_result() {
    pinned(
        &UpdateGprsLocationRes::new(number("15550100040")),
        spec::UPDATE_GPRS_LOCATION_RES.octets,
    );
}

#[test]
fn cancel_location_argument() {
    pinned(
        &CancelLocationArg {
            cancellation_type: Some(CancellationType::UpdateProcedure),
            type_of_update: Some(1.into()),
            reattach_required: Some(()),
            ..CancelLocationArg::new(Identity::Imsi(imsi()))
        },
        spec::CANCEL_LOCATION_ARG.octets,
    );
    pinned(
        &CancelLocationArg {
            cancellation_type: Some(CancellationType::SubscriptionWithdraw),
            ..CancelLocationArg::new(Identity::ImsiWithLmsi(ImsiWithLmsi {
                imsi: imsi(),
                lmsi: oct(&[0x00, 0x00, 0x00, 0x2a]),
            }))
        },
        spec::CANCEL_LOCATION_ARG_WITH_LMSI.octets,
    );
}

// ── insertSubscriberData ────────────────────────────────────────────────────

#[test]
fn insert_subscriber_data_argument() {
    pinned(
        &InsertSubscriberDataArg {
            imsi: Some(imsi()),
            msisdn: Some(subscriber()),
            category: Some(oct(&[0x0a])),
            subscriber_status: Some(SubscriberStatus::ServiceGranted),
            teleservice_list: Some(vec![oct(&[0x21]), oct(&[0x22])]),
            network_access_mode: Some(NetworkAccessMode::PacketAndCircuit),
            charging_characteristics: Some(oct(&[0x08, 0x00])),
            ue_usage_type: Some(oct(&[0x00, 0x00, 0x00, 0x01])),
            ..InsertSubscriberDataArg::default()
        },
        spec::INSERT_SUBSCRIBER_DATA_ARG.octets,
    );
}

#[test]
fn charging_characteristics_as_a_bit_string_is_no_longer_what_is_emitted() {
    // Before this was corrected the member was modelled as a BIT STRING, so
    // the two octets 08 00 went out with a leading count of unused bits:
    // `92 03 00 08 00`. ChargingCharacteristics is an OCTET STRING (SIZE (2));
    // a receiver reads three octets there and the first is not part of the
    // value.
    let now = InsertSubscriberDataArg {
        charging_characteristics: Some(oct(&[0x08, 0x00])),
        ..InsertSubscriberDataArg::default()
    };
    assert_eq!(
        gsm_map::encode(&now).unwrap(),
        common::vector("30 04 92 02 08 00")
    );
    let old: InsertSubscriberDataArg = common::accepted(&common::vector("30 05 92 03 00 08 00"));
    assert_eq!(
        old.charging_characteristics,
        Some(oct(&[0x00, 0x08, 0x00])),
        "the old encoding decodes to three octets, which is not a valid value"
    );
}

// ── anyTimeModification for IP-SM-GW data ───────────────────────────────────

#[test]
fn any_time_modification_registers_and_deregisters_an_ip_sm_gw() {
    pinned(
        &AnyTimeModificationArg {
            modification_request_for_ip_sm_gw_data: Some(ModificationRequestForIpSmGwData {
                modify_registration_status: Some(ModificationInstruction::Activate),
                extension_container: None,
                ip_sm_gw_diameter_address: None,
            }),
            ..AnyTimeModificationArg::new(
                SubscriberIdentity::Msisdn(subscriber()),
                number("15550100060"),
            )
        },
        spec::ANY_TIME_MODIFICATION_ARG_ACTIVATE.octets,
    );
    pinned(
        &AnyTimeModificationArg {
            modification_request_for_ip_sm_gw_data: Some(ModificationRequestForIpSmGwData {
                modify_registration_status: Some(ModificationInstruction::Deactivate),
                extension_container: None,
                ip_sm_gw_diameter_address: Some(NetworkNodeDiameterAddress {
                    diameter_name: oct(b"ipsmgw01.test"),
                    diameter_realm: oct(b"realm.test"),
                }),
            }),
            ..AnyTimeModificationArg::new(SubscriberIdentity::Imsi(imsi()), number("15550100060"))
        },
        spec::ANY_TIME_MODIFICATION_ARG_DEACTIVATE.octets,
    );
    pinned(
        &AnyTimeModificationRes {
            service_centre_address: Some(service_centre()),
            ..AnyTimeModificationRes::default()
        },
        spec::ANY_TIME_MODIFICATION_RES.octets,
    );
}

// ── Error parameters ────────────────────────────────────────────────────────

#[test]
fn absent_subscriber_sm_parameter() {
    pinned(
        &AbsentSubscriberSmParam {
            absent_subscriber_diagnostic_sm: Some(1.into()),
            extension_container: None,
            additional_absent_subscriber_diagnostic_sm: Some(5.into()),
            imsi: Some(imsi()),
            requested_retransmission_time: Some(oct(&[0x00, 0x00, 0x0e, 0x10])),
            user_identifier_alert: Some(imsi()),
        },
        spec::ABSENT_SUBSCRIBER_SM.octets,
    );
}

#[test]
fn sm_delivery_failure_cause() {
    pinned(
        &SmDeliveryFailureCause {
            diagnostic_info: Some(oct(&[0x00, 0xd3, 0x00])),
            ..SmDeliveryFailureCause::new(SmEnumeratedDeliveryFailureCause::MemoryCapacityExceeded)
        },
        spec::SM_DELIVERY_FAILURE.octets,
    );
}

#[test]
fn the_other_error_parameters() {
    pinned(
        &UnknownSubscriberParam {
            extension_container: None,
            unknown_subscriber_diagnostic: Some(OpenEnumerated::from(0)),
        },
        spec::UNKNOWN_SUBSCRIBER.octets,
    );
    pinned(
        &AbsentSubscriberParam {
            extension_container: None,
            absent_subscriber_reason: Some(0.into()),
        },
        spec::ABSENT_SUBSCRIBER.octets,
    );
    pinned(
        &SubBusyForMtSmsParam {
            extension_container: None,
            gprs_connection_suspended: Some(()),
        },
        spec::SUBSCRIBER_BUSY_FOR_MT_SMS.octets,
    );
    pinned(
        &UnexpectedDataParam {
            extension_container: None,
            unexpected_subscriber: Some(()),
        },
        spec::UNEXPECTED_DATA_VALUE.octets,
    );
}

#[test]
fn every_vector_is_well_formed_and_has_a_distinct_label() {
    let mut labels = std::collections::HashSet::new();
    for vector in spec::ALL {
        assert!(labels.insert(vector.label), "{} twice", vector.label);
        let octets = common::vector(vector.octets);
        // One element, definite short or long form, nothing after it.
        let length = match octets[1] {
            short if short < 0x80 => 2 + usize::from(short),
            0x81 => 3 + usize::from(octets[2]),
            other => panic!("{}: unexpected length octet {other:02x}", vector.label),
        };
        assert_eq!(octets.len(), length, "{}", vector.label);
        assert!(!vector.fields.is_empty(), "{}", vector.label);
    }
}
