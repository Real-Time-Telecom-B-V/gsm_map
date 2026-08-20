//! MAP application-context OIDs — 3GPP TS 29.002 `MAP-ApplicationContexts`.
//!
//! A TCAP dialogue names its application context so the peer knows which ASN.1
//! module — and therefore which operation set and which version of each
//! operation — the components belong to. Get the arc or the version wrong and a
//! conformant peer aborts the dialogue before any operation is decoded.
//!
//! Every arc and every version below was read back from an independent decoder
//! (see [`scripts/wireshark_check.sh`](../scripts/wireshark_check.sh)); the
//! doc comment on each function lists the versions TS 29.002 actually defines,
//! because most contexts are not available in all three.

use rasn::types::ObjectIdentifier;

/// Base OID for MAP application contexts: `0.4.0.0.1.0`
const MAP_AC_BASE: [u32; 6] = [0, 4, 0, 0, 1, 0];

/// Build a MAP application-context OID from its arc and version.
///
/// Prefer the named functions below: they carry the version each context is
/// actually defined for.
pub fn map_ac(ac_id: u32, version: u32) -> ObjectIdentifier {
    let components: Vec<u32> = vec![
        MAP_AC_BASE[0],
        MAP_AC_BASE[1],
        MAP_AC_BASE[2],
        MAP_AC_BASE[3],
        MAP_AC_BASE[4],
        MAP_AC_BASE[5],
        ac_id,
        version,
    ];
    ObjectIdentifier::new_unchecked(components.into())
}

/// MAP versions.
pub const V1: u32 = 1;
pub const V2: u32 = 2;
pub const V3: u32 = 3;

// ── Mobility ────────────────────────────────────────────────────────────────

/// networkLocUpContext (arc 1) — updateLocation. v1, v2, v3.
pub fn network_loc_up_context(version: u32) -> ObjectIdentifier {
    map_ac(1, version)
}
/// locationCancellationContext (arc 2) — cancelLocation. v1, v2, v3.
pub fn location_cancellation_context(version: u32) -> ObjectIdentifier {
    map_ac(2, version)
}
/// roamingNumberEnquiryContext (arc 3) — provideRoamingNumber. v1, v2, v3.
pub fn roaming_number_enquiry_context(version: u32) -> ObjectIdentifier {
    map_ac(3, version)
}
/// istAlertingContext (arc 4) — istAlert. **v3 only.**
pub fn ist_alerting_context(version: u32) -> ObjectIdentifier {
    map_ac(4, version)
}
/// locationInfoRetrievalContext (arc 5) — sendRoutingInfo. v1, v2, v3.
pub fn location_info_retrieval_context(version: u32) -> ObjectIdentifier {
    map_ac(5, version)
}
/// callControlTransferContext (arc 6) — resumeCallHandling. **v3 only.**
pub fn call_control_transfer_context(version: u32) -> ObjectIdentifier {
    map_ac(6, version)
}
/// reportingContext (arc 7) — setReportingState, statusReport, remoteUserFree.
/// **v3 only.**
pub fn reporting_context(version: u32) -> ObjectIdentifier {
    map_ac(7, version)
}
/// callCompletionContext (arc 8) — registerCC-Entry, eraseCC-Entry. **v3 only.**
pub fn call_completion_context(version: u32) -> ObjectIdentifier {
    map_ac(8, version)
}
/// serviceTerminationContext (arc 9) — istCommand. **v3 only.**
pub fn service_termination_context(version: u32) -> ObjectIdentifier {
    map_ac(9, version)
}
/// resetContext (arc 10) — reset. v1, v2, v3.
pub fn reset_context(version: u32) -> ObjectIdentifier {
    map_ac(10, version)
}
/// handoverControlContext (arc 11) — the handover operation set. v1, v2, v3.
pub fn handover_control_context(version: u32) -> ObjectIdentifier {
    map_ac(11, version)
}
/// sIWFSAllocationContext (arc 12). **v3 only.**
pub fn siwfs_allocation_context(version: u32) -> ObjectIdentifier {
    map_ac(12, version)
}
/// equipmentMngtContext (arc 13) — checkIMEI. v1, v2, v3.
pub fn equipment_mngt_context(version: u32) -> ObjectIdentifier {
    map_ac(13, version)
}
/// infoRetrievalContext (arc 14) — sendAuthenticationInfo. v1, v2, v3.
///
/// Note the arc: **14**, not 5. Arc 5 is
/// [`location_info_retrieval_context`], a different context entirely.
pub fn info_retrieval_context(version: u32) -> ObjectIdentifier {
    map_ac(14, version)
}
/// interVlrInfoRetrievalContext (arc 15) — sendIdentification. **v2, v3.**
pub fn inter_vlr_info_retrieval_context(version: u32) -> ObjectIdentifier {
    map_ac(15, version)
}
/// subscriberDataMngtContext (arc 16) — insertSubscriberData,
/// deleteSubscriberData. v1, v2, v3.
pub fn subscriber_data_mngt_context(version: u32) -> ObjectIdentifier {
    map_ac(16, version)
}
/// tracingContext (arc 17) — activateTraceMode, deactivateTraceMode. v1, v2, v3.
pub fn tracing_context(version: u32) -> ObjectIdentifier {
    map_ac(17, version)
}
/// networkFunctionalSsContext (arc 18) — the supplementary-service operations.
/// **v1, v2 only.**
pub fn network_functional_ss_context(version: u32) -> ObjectIdentifier {
    map_ac(18, version)
}
/// networkUnstructuredSsContext (arc 19) — the USSD operations. **v2 only.**
pub fn network_unstructured_ss_context(version: u32) -> ObjectIdentifier {
    map_ac(19, version)
}

// ── Short message service ───────────────────────────────────────────────────

/// shortMsgGatewayContext (arc 20) — sendRoutingInfoForSM,
/// reportSM-DeliveryStatus, informServiceCentre. v1, v2, v3.
pub fn short_msg_gateway_context(version: u32) -> ObjectIdentifier {
    map_ac(20, version)
}
/// shortMsgMO-RelayContext (arc 21) — mo-ForwardSM. v1, v2, v3.
///
/// Named `shortMsgRelayContext` in v1/v2, where it carried both directions;
/// v3 renamed it and split MT off to [`short_msg_mt_relay_context`].
pub fn short_msg_mo_relay_context(version: u32) -> ObjectIdentifier {
    map_ac(21, version)
}
/// subscriberDataModificationNotificationContext (arc 22). **v3 only.**
pub fn subscriber_data_modification_notification_context(version: u32) -> ObjectIdentifier {
    map_ac(22, version)
}
/// shortMsgAlertContext (arc 23) — alertServiceCentre. **v1, v2 only.**
pub fn short_msg_alert_context(version: u32) -> ObjectIdentifier {
    map_ac(23, version)
}
/// mwdMngtContext (arc 24) — readyForSM. v1, v2, v3.
pub fn mwd_mngt_context(version: u32) -> ObjectIdentifier {
    map_ac(24, version)
}
/// shortMsgMT-RelayContext (arc 25) — mt-ForwardSM. **v2, v3.**
pub fn short_msg_mt_relay_context(version: u32) -> ObjectIdentifier {
    map_ac(25, version)
}
/// shortMsgMT-Relay-VGCS-Context (arc 41) — mt-ForwardSM-VGCS. **v3 only.**
pub fn short_msg_mt_relay_vgcs_context(version: u32) -> ObjectIdentifier {
    map_ac(41, version)
}

// ── Subscriber information, any-time interrogation ──────────────────────────

/// imsiRetrievalContext (arc 26) — sendIMSI. **v2 only.**
pub fn imsi_retrieval_context(version: u32) -> ObjectIdentifier {
    map_ac(26, version)
}
/// msPurgingContext (arc 27) — purgeMS. **v2, v3.**
pub fn ms_purging_context(version: u32) -> ObjectIdentifier {
    map_ac(27, version)
}
/// subscriberInfoEnquiryContext (arc 28) — provideSubscriberInfo. **v3 only.**
pub fn subscriber_info_enquiry_context(version: u32) -> ObjectIdentifier {
    map_ac(28, version)
}
/// anyTimeInfoEnquiryContext (arc 29) — **anyTimeInterrogation**. **v3 only.**
pub fn any_time_info_enquiry_context(version: u32) -> ObjectIdentifier {
    map_ac(29, version)
}
/// anyTimeInfoHandlingContext (arc 43) — **anyTimeSubscriberDataModification**
/// (op 65), which is how a node registers itself as the MT-SMS routing node for
/// a subscriber. **v3 only.**
///
/// Not to be confused with [`any_time_info_enquiry_context`] (arc 29), which is
/// the context anyTimeInterrogation runs under.
pub fn any_time_info_handling_context(version: u32) -> ObjectIdentifier {
    map_ac(43, version)
}

// ── GPRS ────────────────────────────────────────────────────────────────────

/// groupCallControlContext (arc 31). **v3 only.**
pub fn group_call_control_context(version: u32) -> ObjectIdentifier {
    map_ac(31, version)
}
/// gprsLocationUpdateContext (arc 32) — updateGprsLocation. **v3 only.**
pub fn gprs_location_update_context(version: u32) -> ObjectIdentifier {
    map_ac(32, version)
}
/// gprsLocationInfoRetrievalContext (arc 33) — sendRoutingInfoForGprs.
/// **v3 only.**
pub fn gprs_location_info_retrieval_context(version: u32) -> ObjectIdentifier {
    map_ac(33, version)
}
/// failureReportContext (arc 34) — failureReport. **v3 only.**
pub fn failure_report_context(version: u32) -> ObjectIdentifier {
    map_ac(34, version)
}
/// gprsNotifyContext (arc 35) — noteMsPresentForGprs. **v3 only.**
pub fn gprs_notify_context(version: u32) -> ObjectIdentifier {
    map_ac(35, version)
}

// ── Supplementary services, location services, misc ─────────────────────────

/// ss-InvocationNotificationContext (arc 36) — ss-InvocationNotification.
/// **v3 only.**
pub fn ss_invocation_notification_context(version: u32) -> ObjectIdentifier {
    map_ac(36, version)
}
/// locationSvcGatewayContext (arc 37) — sendRoutingInfoForLCS. **v3 only.**
pub fn location_svc_gateway_context(version: u32) -> ObjectIdentifier {
    map_ac(37, version)
}
/// locationSvcEnquiryContext (arc 38) — provideSubscriberLocation,
/// subscriberLocationReport. **v3 only.**
pub fn location_svc_enquiry_context(version: u32) -> ObjectIdentifier {
    map_ac(38, version)
}
/// authenticationFailureReportContext (arc 39) — authenticationFailureReport.
/// **v3 only.**
///
/// Note the arc: **39**, not 27. Arc 27 is [`ms_purging_context`].
pub fn authentication_failure_report_context(version: u32) -> ObjectIdentifier {
    map_ac(39, version)
}
/// secureTransportHandlingContext (arc 40). **v3 only.**
pub fn secure_transport_handling_context(version: u32) -> ObjectIdentifier {
    map_ac(40, version)
}
/// mm-EventReportingContext (arc 42) — noteMM-Event. **v3 only.**
pub fn mm_event_reporting_context(version: u32) -> ObjectIdentifier {
    map_ac(42, version)
}
/// resourceManagementContext (arc 44). **v3 only.**
pub fn resource_management_context(version: u32) -> ObjectIdentifier {
    map_ac(44, version)
}
/// groupCallInfoRetrievalContext (arc 45). **v3 only.**
pub fn group_call_info_retrieval_context(version: u32) -> ObjectIdentifier {
    map_ac(45, version)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn arcs(oid: &ObjectIdentifier) -> Vec<u32> {
        oid.iter().copied().collect()
    }

    #[test]
    fn arcs_match_ts_29_002() {
        // Every one of these was read back from Wireshark's gsm_map dissector,
        // which carries the compiled TS 29.002 ASN.1.
        for (oid, arc) in [
            (network_loc_up_context(V3), 1),
            (location_cancellation_context(V3), 2),
            (roaming_number_enquiry_context(V3), 3),
            (ist_alerting_context(V3), 4),
            (location_info_retrieval_context(V3), 5),
            (reset_context(V3), 10),
            (handover_control_context(V3), 11),
            (equipment_mngt_context(V3), 13),
            (info_retrieval_context(V3), 14),
            (inter_vlr_info_retrieval_context(V3), 15),
            (subscriber_data_mngt_context(V3), 16),
            (tracing_context(V3), 17),
            (network_functional_ss_context(V2), 18),
            (network_unstructured_ss_context(V2), 19),
            (short_msg_gateway_context(V3), 20),
            (short_msg_mo_relay_context(V3), 21),
            (short_msg_alert_context(V2), 23),
            (mwd_mngt_context(V3), 24),
            (short_msg_mt_relay_context(V3), 25),
            (imsi_retrieval_context(V2), 26),
            (ms_purging_context(V3), 27),
            (subscriber_info_enquiry_context(V3), 28),
            (any_time_info_enquiry_context(V3), 29),
            (gprs_location_update_context(V3), 32),
            (gprs_location_info_retrieval_context(V3), 33),
            (failure_report_context(V3), 34),
            (gprs_notify_context(V3), 35),
            (ss_invocation_notification_context(V3), 36),
            (location_svc_gateway_context(V3), 37),
            (location_svc_enquiry_context(V3), 38),
            (authentication_failure_report_context(V3), 39),
            (short_msg_mt_relay_vgcs_context(V3), 41),
            (any_time_info_handling_context(V3), 43),
        ] {
            let components = arcs(&oid);
            assert_eq!(&components[..6], &[0, 4, 0, 0, 1, 0], "MAP AC base");
            assert_eq!(components[6], arc, "arc for {components:?}");
        }
    }

    #[test]
    fn the_two_arcs_that_were_wrong_in_1_x() {
        // infoRetrievalContext is 14; 1.x had it at 5, which is
        // locationInfoRetrievalContext.
        assert_eq!(arcs(&info_retrieval_context(V3))[6], 14);
        assert_eq!(arcs(&location_info_retrieval_context(V3))[6], 5);
        // authenticationFailureReportContext is 39; 1.x had it at 27, which is
        // msPurgingContext.
        assert_eq!(arcs(&authentication_failure_report_context(V3))[6], 39);
        assert_eq!(arcs(&ms_purging_context(V3))[6], 27);
    }

    #[test]
    fn any_time_contexts_are_distinct() {
        // Interrogation and modification are different contexts.
        assert_eq!(arcs(&any_time_info_enquiry_context(V3))[6], 29);
        assert_eq!(arcs(&any_time_info_handling_context(V3))[6], 43);
        assert_eq!(
            arcs(&any_time_info_handling_context(V3)),
            vec![0, 4, 0, 0, 1, 0, 43, 3]
        );
    }

    #[test]
    fn different_versions() {
        let v1 = short_msg_gateway_context(V1);
        let v2 = short_msg_gateway_context(V2);
        let v3 = short_msg_gateway_context(V3);
        assert_ne!(v1, v2);
        assert_ne!(v2, v3);
        assert_eq!(arcs(&v3).last().copied(), Some(3));
    }
}
