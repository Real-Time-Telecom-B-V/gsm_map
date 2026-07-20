//! GSM MAP (Mobile Application Part) per 3GPP TS 29.002.
//!
//! Provides BER encode/decode for MAP operations across all major groups:
//! - **SMS**: SRI-SM, MO/MT-ForwardSM, reportSM-DeliveryStatus, alertSC, informSC, readyForSM
//! - **Location Management**: updateLocation, cancelLocation, purgeMS, sendIdentification
//! - **Authentication**: sendAuthenticationInfo (triplets + quintuplets)
//! - **Subscriber Data**: insertSubscriberData, deleteSubscriberData
//! - **USSD**: processUnstructuredSS-Request, unstructuredSS-Request/Notify
//! - **Call Handling**: sendRoutingInfo, provideRoamingNumber
//! - **Supplementary Services**: registerSS, eraseSS, activateSS, deactivateSS, interrogateSS
//! - **Fault Recovery**: reset, restoreData
//!
//! Application contexts (v1/v2/v3) are provided for TCAP dialogue negotiation.
//!
//! Uses `rasn` for ASN.1 BER encoding/decoding.

pub mod address;
pub mod application_context;
pub mod dialogue;
pub mod error;
pub mod operations;
pub mod types;

/// PyO3 bindings (`--features python`). The default crate build is pyo3-free.
#[cfg(feature = "python")]
pub mod python;

#[cfg(feature = "python")]
pub use python::register;

pub use error::MapError;
pub use types::{
    op_codes, operation_name, AddressString, Imsi, IsdnAddressString, Lmsi, LocationInfoWithLmsi,
    SmRpDa, SmRpOa,
};

#[cfg(test)]
mod tests {
    use super::*;
    use operations::alert_sc::AlertServiceCentreArg;
    use operations::auth::{
        AuthenticationQuintuplet, AuthenticationSetList, AuthenticationTriplet,
        SendAuthenticationInfoArg, SendAuthenticationInfoRes,
    };
    use operations::call_handling::{
        ProvideRoamingNumberArg, ProvideRoamingNumberRes, SendRoutingInfoArg,
    };
    use operations::fault_recovery::{ResetArg, RestoreDataArg, RestoreDataRes};
    use operations::inform_sc::InformServiceCentreArg;
    use operations::location::{
        CancelLocationArg, CancellationType, PurgeMsArg, UpdateLocationArg, UpdateLocationRes,
    };
    use operations::mo_forward_sm::MoForwardSmArg;
    use operations::mt_forward_sm::MtForwardSmArg;
    use operations::ready_for_sm::{AlertReason, ReadyForSmArg};
    use operations::report_sm::{ReportSmDeliveryStatusArg, SmDeliveryOutcome};
    use operations::sri_sm::{RoutingInfoForSmArg, RoutingInfoForSmRes};
    use operations::subscriber_data::{
        DeleteSubscriberDataArg, InsertSubscriberDataArg, SubscriberStatus,
    };
    use operations::supplementary::{BasicServiceCode, InterrogateSsArg, RegisterSsArg};
    use operations::ussd::{
        ProcessUnstructuredSsRequestArg, ProcessUnstructuredSsRequestRes, UnstructuredSsNotifyArg,
        UnstructuredSsRequestArg,
    };

    // ── Helper ──

    fn round_trip<T: rasn::Decode + rasn::Encode + std::fmt::Debug + PartialEq>(val: &T) {
        let encoded = rasn::ber::encode(val).expect("encode failed");
        let decoded: T = rasn::ber::decode(&encoded).expect("decode failed");
        assert_eq!(&decoded, val);
    }

    // ── SMS ──

    #[test]
    fn sri_sm_arg() {
        let arg = RoutingInfoForSmArg {
            msisdn: vec![0x91, 0x51, 0x55, 0x10, 0x00, 0x99, 0xF9].into(),
            sm_rp_pri: true,
            service_centre_address: vec![0x91, 0x44, 0x77, 0x89, 0x01, 0x23].into(),
            gprs_support_indicator: None,
            sm_rp_mti: None,
            sm_rp_smea: None,
        };
        round_trip(&arg);
    }

    #[test]
    fn sri_sm_res() {
        let res = RoutingInfoForSmRes {
            imsi: vec![0x09, 0x10, 0x10, 0x00, 0x00, 0x00, 0x00, 0x01].into(),
            location_info_with_lmsi: LocationInfoWithLmsi {
                network_node_number: vec![0x91, 0x44, 0x77, 0x12, 0x34, 0x56].into(),
                lmsi: Some(vec![0x00, 0x00, 0x00, 0x01].into()),
                gprs_node_indicator: None,
                additional_number: None,
            },
        };
        round_trip(&res);
    }

    #[test]
    fn mo_forward_sm() {
        let arg = MoForwardSmArg {
            sm_rp_da: SmRpDa::ServiceCentreAddressDa(vec![0x91, 0x44].into()),
            sm_rp_oa: SmRpOa::MsIsdn(vec![0x91, 0x51].into()),
            sm_rp_ui: vec![0x01, 0x00, 0x0B].into(),
            imsi: None,
        };
        round_trip(&arg);
    }

    #[test]
    fn mt_forward_sm() {
        let arg = MtForwardSmArg {
            sm_rp_da: SmRpDa::Imsi(vec![0x09, 0x10].into()),
            sm_rp_oa: SmRpOa::ServiceCentreAddressOa(vec![0x91, 0x44].into()),
            sm_rp_ui: vec![0x04, 0x0B, 0x91].into(),
            more_messages_to_send: None,
        };
        round_trip(&arg);
    }

    #[test]
    fn report_sm_delivery_status() {
        let arg = ReportSmDeliveryStatusArg {
            msisdn: vec![0x91, 0x51].into(),
            service_centre_address: vec![0x91, 0x44].into(),
            sm_delivery_outcome: SmDeliveryOutcome::SuccessfulTransfer,
        };
        round_trip(&arg);
    }

    #[test]
    fn alert_service_centre() {
        let arg = AlertServiceCentreArg {
            msisdn: vec![0x91, 0x51].into(),
            service_centre_address: vec![0x91, 0x44].into(),
        };
        round_trip(&arg);
    }

    #[test]
    fn inform_service_centre() {
        let arg = InformServiceCentreArg {
            stored_msisdn: Some(vec![0x91, 0x51].into()),
            mw_status: None,
        };
        round_trip(&arg);
    }

    #[test]
    fn ready_for_sm() {
        let arg = ReadyForSmArg {
            imsi: vec![0x09, 0x10, 0x10].into(),
            alert_reason: AlertReason::MsPresent,
        };
        round_trip(&arg);
    }

    // ── Location Management ──

    #[test]
    fn update_location() {
        let arg = UpdateLocationArg {
            imsi: vec![0x09, 0x10, 0x10, 0x00, 0x00, 0x00, 0x00, 0x01].into(),
            msc_number: vec![0x91, 0x44, 0x77, 0x12, 0x34, 0x56].into(),
            vlr_number: vec![0x91, 0x44, 0x77, 0x12, 0x34, 0x57].into(),
            lmsi: Some(vec![0x00, 0x00, 0x00, 0x01].into()),
            vlr_capability: None,
        };
        round_trip(&arg);
    }

    #[test]
    fn update_location_res() {
        let res = UpdateLocationRes {
            hlr_number: vec![0x91, 0x44, 0x77, 0x89, 0x01, 0x23].into(),
        };
        round_trip(&res);
    }

    #[test]
    fn cancel_location() {
        let arg = CancelLocationArg {
            identity: vec![0x09, 0x10, 0x10, 0x00, 0x00, 0x00, 0x00, 0x01].into(),
            cancellation_type: Some(CancellationType::UpdateProcedure),
        };
        round_trip(&arg);
    }

    #[test]
    fn purge_ms() {
        let arg = PurgeMsArg {
            imsi: vec![0x09, 0x10].into(),
            vlr_number: Some(vec![0x91, 0x44].into()),
            sgsn_number: None,
        };
        round_trip(&arg);
    }

    // ── Authentication ──

    #[test]
    fn send_authentication_info() {
        let arg = SendAuthenticationInfoArg {
            imsi: vec![0x09, 0x10, 0x10, 0x00, 0x00, 0x00, 0x00, 0x01].into(),
            number_of_requested_vectors: 5.into(),
            re_synchronisation_info: None,
            requesting_node_type: None,
        };
        round_trip(&arg);
    }

    #[test]
    fn send_authentication_info_res_triplets() {
        let res = SendAuthenticationInfoRes {
            authentication_set_list: Some(AuthenticationSetList::TripletList(vec![
                AuthenticationTriplet {
                    rand: vec![0u8; 16].into(),
                    sres: vec![0u8; 4].into(),
                    kc: vec![0u8; 8].into(),
                },
            ])),
        };
        round_trip(&res);
    }

    #[test]
    fn send_authentication_info_res_quintuplets() {
        let res = SendAuthenticationInfoRes {
            authentication_set_list: Some(AuthenticationSetList::QuintupletList(vec![
                AuthenticationQuintuplet {
                    rand: vec![0u8; 16].into(),
                    xres: vec![0u8; 8].into(),
                    ck: vec![0u8; 16].into(),
                    ik: vec![0u8; 16].into(),
                    autn: vec![0u8; 16].into(),
                },
            ])),
        };
        round_trip(&res);
    }

    // ── Subscriber Data ──

    #[test]
    fn insert_subscriber_data() {
        let arg = InsertSubscriberDataArg {
            imsi: Some(vec![0x09, 0x10].into()),
            msisdn: Some(vec![0x91, 0x51].into()),
            category: None,
            subscriber_status: Some(SubscriberStatus::ServiceGranted),
            bearer_service_list: None,
            teleservice_list: None,
            odb_data: None,
            roaming_restricted_in_sgsn_due_to_unsupported_feature: None,
            network_access_mode: None,
        };
        round_trip(&arg);
    }

    #[test]
    fn delete_subscriber_data() {
        let arg = DeleteSubscriberDataArg {
            imsi: vec![0x09, 0x10].into(),
            basic_service_list: None,
            ss_list: None,
            roaming_restricted_in_sgsn_due_to_unsupported_feature: None,
        };
        round_trip(&arg);
    }

    // ── USSD ──

    #[test]
    fn process_unstructured_ss_request() {
        let arg = ProcessUnstructuredSsRequestArg {
            ussd_data_coding_scheme: vec![0x0F].into(), // Default GSM 7-bit
            ussd_string: vec![0xAA, 0x58, 0x0C, 0xA6, 0x82].into(), // *100# in GSM 7-bit
            msisdn: Some(vec![0x91, 0x51, 0x55, 0x10].into()),
        };
        round_trip(&arg);
    }

    #[test]
    fn process_unstructured_ss_response() {
        let res = ProcessUnstructuredSsRequestRes {
            ussd_data_coding_scheme: vec![0x0F].into(),
            ussd_string: vec![0xC2, 0x27, 0x3D].into(),
        };
        round_trip(&res);
    }

    #[test]
    fn unstructured_ss_request() {
        let arg = UnstructuredSsRequestArg {
            ussd_data_coding_scheme: vec![0x0F].into(),
            ussd_string: vec![0xD4, 0xF2, 0x9C].into(), // "Enter PIN"
        };
        round_trip(&arg);
    }

    #[test]
    fn unstructured_ss_notify() {
        let arg = UnstructuredSsNotifyArg {
            ussd_data_coding_scheme: vec![0x0F].into(),
            ussd_string: vec![0xC2, 0x27].into(),
        };
        round_trip(&arg);
    }

    // ── Call Handling ──

    #[test]
    fn send_routing_info() {
        let arg = SendRoutingInfoArg {
            msisdn: vec![0x91, 0x51, 0x55, 0x10, 0x00, 0x99, 0xF9].into(),
            cug_check_info: None,
            number_of_forwarding: None,
            interrogation_type: None,
            gmsc_or_gmscs_address: Some(vec![0x91, 0x44, 0x77].into()),
        };
        round_trip(&arg);
    }

    #[test]
    fn provide_roaming_number() {
        let arg = ProvideRoamingNumberArg {
            imsi: vec![0x09, 0x10].into(),
            msc_number: vec![0x91, 0x44].into(),
            msisdn: Some(vec![0x91, 0x51].into()),
            lmsi: Some(vec![0x00, 0x00, 0x00, 0x01].into()),
            gsm_bearer_capability: None,
        };
        round_trip(&arg);
    }

    #[test]
    fn provide_roaming_number_res() {
        let res = ProvideRoamingNumberRes {
            roaming_number: vec![0x91, 0x44, 0x77, 0x99, 0x88, 0x77].into(),
        };
        round_trip(&res);
    }

    // ── Supplementary Services ──

    #[test]
    fn register_ss() {
        let arg = RegisterSsArg {
            ss_code: vec![0x21].into(), // CFU (Call Forwarding Unconditional)
            basic_service: Some(BasicServiceCode::Teleservice(vec![0x11].into())),
            forwarded_to_number: Some(vec![0x91, 0x51, 0x55].into()),
            no_reply_condition_time: None,
        };
        round_trip(&arg);
    }

    #[test]
    fn interrogate_ss() {
        let arg = InterrogateSsArg {
            ss_code: vec![0x21].into(),
            basic_service: None,
        };
        round_trip(&arg);
    }

    // ── Fault Recovery ──

    #[test]
    fn reset() {
        let arg = ResetArg {
            hlr_number: vec![0x91, 0x44, 0x77, 0x89, 0x01, 0x23].into(),
            hlr_list: None,
        };
        round_trip(&arg);
    }

    #[test]
    fn restore_data() {
        let arg = RestoreDataArg {
            imsi: vec![0x09, 0x10, 0x10, 0x00, 0x00, 0x00, 0x00, 0x01].into(),
            lmsi: Some(vec![0x00, 0x00, 0x00, 0x01].into()),
        };
        round_trip(&arg);
    }

    #[test]
    fn restore_data_res() {
        let res = RestoreDataRes {
            hlr_number: vec![0x91, 0x44, 0x77, 0x89, 0x01, 0x23].into(),
        };
        round_trip(&res);
    }

    // ── Operation names ──

    #[test]
    fn operation_names() {
        assert_eq!(operation_name(45), "sendRoutingInfoForSM");
        assert_eq!(operation_name(44), "mt-ForwardSM");
        assert_eq!(operation_name(46), "mo-ForwardSM");
        assert_eq!(operation_name(47), "reportSM-DeliveryStatus");
        assert_eq!(operation_name(64), "alertServiceCentre");
        assert_eq!(operation_name(63), "informServiceCentre");
        assert_eq!(operation_name(66), "readyForSM");
        assert_eq!(operation_name(99), "unknown");
    }

    // ── OAM ──

    use operations::oam::{ActivateTraceModeArg, DeactivateTraceModeArg, SendImsiArg};

    #[test]
    fn activate_trace_mode() {
        let arg = ActivateTraceModeArg {
            imsi: Some(vec![0x09, 0x10].into()),
            trace_reference: vec![0x01, 0x02].into(),
            trace_type: 1.into(),
            omc_id: None,
        };
        round_trip(&arg);
    }

    #[test]
    fn deactivate_trace_mode() {
        let arg = DeactivateTraceModeArg {
            imsi: Some(vec![0x09, 0x10].into()),
            trace_reference: vec![0x01, 0x02].into(),
        };
        round_trip(&arg);
    }

    #[test]
    fn send_imsi() {
        let arg = SendImsiArg {
            msisdn: vec![0x91, 0x51].into(),
        };
        round_trip(&arg);
    }

    // ── Subscriber Information ──

    use operations::subscriber_info::{
        AnyTimeInterrogationArg, AnyTimeModificationArg, ProvideSubscriberInfoArg, RequestedInfo,
        SubscriberIdentity,
    };

    #[test]
    fn provide_subscriber_info() {
        let arg = ProvideSubscriberInfoArg {
            imsi: vec![0x09, 0x10].into(),
            lmsi: None,
            requested_info: RequestedInfo {
                location_information: Some(()),
                subscriber_state: Some(()),
                current_location: None,
                imei: None,
                ms_classmark: None,
                mn_p_requested_info: None,
            },
        };
        round_trip(&arg);
    }

    #[test]
    fn any_time_interrogation() {
        let arg = AnyTimeInterrogationArg {
            subscriber_identity: SubscriberIdentity::Msisdn(vec![0x91, 0x51].into()),
            requested_info: RequestedInfo {
                location_information: Some(()),
                subscriber_state: Some(()),
                current_location: None,
                imei: Some(()),
                ms_classmark: None,
                mn_p_requested_info: None,
            },
            gsm_scf_address: vec![0x91, 0x44].into(),
        };
        round_trip(&arg);
    }

    #[test]
    fn any_time_modification() {
        let arg = AnyTimeModificationArg {
            subscriber_identity: SubscriberIdentity::Imsi(vec![0x09, 0x10].into()),
            gsm_scf_address: vec![0x91, 0x44].into(),
            modification_request_for_cf_info: None,
            modification_request_for_cb_info: None,
            modification_request_for_csi: None,
        };
        round_trip(&arg);
    }

    // ── GPRS Location ──

    use operations::gprs_location::{
        FailureReportArg, NoteMsPresentForGprsArg, SendRoutingInfoForGprsArg,
        UpdateGprsLocationArg, UpdateGprsLocationRes,
    };

    #[test]
    fn update_gprs_location() {
        let arg = UpdateGprsLocationArg {
            imsi: vec![0x09, 0x10].into(),
            sgsn_number: vec![0x91, 0x44].into(),
            sgsn_address: vec![0x0A, 0x01, 0x01, 0x01].into(),
            sgsn_capability: None,
            informprevious_network_entity: None,
            ps_lcs_not_supported_by_ue: None,
            eps_info: None,
        };
        round_trip(&arg);
    }

    #[test]
    fn update_gprs_location_res() {
        let res = UpdateGprsLocationRes {
            hlr_number: vec![0x91, 0x44].into(),
            add_capability: None,
            sgsn_mm_separation_supported: None,
        };
        round_trip(&res);
    }

    #[test]
    fn send_routing_info_for_gprs() {
        let arg = SendRoutingInfoForGprsArg {
            imsi: vec![0x09, 0x10].into(),
            ggsn_address: Some(vec![0x0A, 0x02, 0x02, 0x02].into()),
            ggsn_number: vec![0x91, 0x44].into(),
        };
        round_trip(&arg);
    }

    #[test]
    fn failure_report() {
        let arg = FailureReportArg {
            imsi: vec![0x09, 0x10].into(),
            ggsn_number: vec![0x91, 0x44].into(),
            ggsn_address: None,
        };
        round_trip(&arg);
    }

    #[test]
    fn note_ms_present_for_gprs() {
        let arg = NoteMsPresentForGprsArg {
            imsi: vec![0x09, 0x10].into(),
            sgsn_address: vec![0x0A, 0x01, 0x01, 0x01].into(),
            ggsn_address: None,
        };
        round_trip(&arg);
    }

    // ── Handover ──

    use operations::handover::{
        ForwardAccessSignallingArg, PrepareHandoverArg, PrepareSubsequentHandoverArg,
        SendEndSignalArg,
    };

    #[test]
    fn prepare_handover() {
        let arg = PrepareHandoverArg {
            target_cell_id: Some(vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07].into()),
            ho_number_not_required: None,
            target_rnc_id: None,
            an_apdu: Some(vec![0xAA, 0xBB].into()),
            multiplicity_indicator: None,
            rab_id: None,
        };
        round_trip(&arg);
    }

    #[test]
    fn send_end_signal() {
        let arg = SendEndSignalArg {
            an_apdu: vec![0x01, 0x02, 0x03].into(),
        };
        round_trip(&arg);
    }

    #[test]
    fn forward_access_signalling() {
        let arg = ForwardAccessSignallingArg {
            an_apdu: vec![0x01, 0x02].into(),
            integrityprotection_information: None,
            encryption_information: None,
            allowed_gsm_algorithms: None,
            allowed_umts_algorithms: None,
        };
        round_trip(&arg);
    }

    #[test]
    fn prepare_subsequent_handover() {
        let arg = PrepareSubsequentHandoverArg {
            target_cell_id: Some(vec![0x01, 0x02, 0x03, 0x04].into()),
            target_msc_number: vec![0x91, 0x44].into(),
            target_rnc_id: None,
            an_apdu: None,
        };
        round_trip(&arg);
    }

    // ── IMEI Check ──

    use operations::imei::{CheckImeiArg, CheckImeiRes, EquipmentStatus};

    #[test]
    fn check_imei() {
        let arg = CheckImeiArg {
            imei: vec![0x53, 0x45, 0x77, 0x89, 0x01, 0x23, 0x45, 0xF6].into(),
            requested_equipment_info: None,
        };
        round_trip(&arg);
    }

    #[test]
    fn check_imei_res() {
        let res = CheckImeiRes {
            equipment_status: Some(EquipmentStatus::Whitelist),
        };
        round_trip(&res);
    }

    // ── LCS ──

    use operations::lcs::{
        LcsClientId, LcsClientType, LcsEvent, LocationEstimateType, LocationType,
        ProvideSubscriberLocationArg, SendRoutingInfoForLcsArg, SubscriberIdentityLcs,
        SubscriberLocationReportArg,
    };

    #[test]
    fn provide_subscriber_location() {
        let arg = ProvideSubscriberLocationArg {
            location_type: LocationType {
                location_estimate_type: LocationEstimateType::CurrentLocation,
                deferred_location_event_type: None,
            },
            mlc_number: vec![0x91, 0x44].into(),
            lcs_client_id: Some(LcsClientId {
                lcs_client_type: LcsClientType::EmergencyServices,
                lcs_client_external_id: None,
                lcs_client_dialed_by_ms: None,
                lcs_client_internal_id: None,
                lcs_client_name: None,
            }),
            imsi: Some(vec![0x09, 0x10].into()),
            msisdn: None,
            imei: None,
            lcs_priority: None,
            lcs_qos: None,
            lcs_service_type_id: None,
        };
        round_trip(&arg);
    }

    #[test]
    fn subscriber_location_report() {
        let arg = SubscriberLocationReportArg {
            lcs_event: LcsEvent::EmergencyCallOrigination,
            lcs_client_id: LcsClientId {
                lcs_client_type: LcsClientType::EmergencyServices,
                lcs_client_external_id: None,
                lcs_client_dialed_by_ms: None,
                lcs_client_internal_id: None,
                lcs_client_name: None,
            },
            network_node_number: vec![0x91, 0x44].into(),
            msisdn: Some(vec![0x91, 0x51].into()),
            imsi: None,
            imei: None,
            location_estimate: Some(vec![0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80].into()),
            age_of_location_estimate: None,
        };
        round_trip(&arg);
    }

    #[test]
    fn send_routing_info_for_lcs() {
        let arg = SendRoutingInfoForLcsArg {
            mlc_number: vec![0x91, 0x44].into(),
            target_ms: SubscriberIdentityLcs::Msisdn(vec![0x91, 0x51].into()),
        };
        round_trip(&arg);
    }

    // ── MAP Errors ──

    use operations::errors;

    #[test]
    fn error_names() {
        assert_eq!(errors::error_name(34), "systemFailure");
        assert_eq!(errors::error_name(1), "unknownSubscriber");
        assert_eq!(errors::error_name(27), "absentSubscriber");
        assert_eq!(errors::error_name(32), "sm-DeliveryFailure");
        assert_eq!(errors::error_name(72), "ussd-Busy");
        assert_eq!(errors::error_name(9999), "unknown");
    }

    // ── Display ──

    #[test]
    fn sm_rp_da_display() {
        let da = SmRpDa::Imsi(vec![0x09, 0x10].into());
        assert!(format!("{da}").contains("IMSI"));

        let da = SmRpDa::NoSmRpDa(());
        assert!(format!("{da}").contains("NoSmRpDa"));
    }
}
