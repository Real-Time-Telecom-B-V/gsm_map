//! MAP Application Context OIDs — 3GPP TS 29.002.
//!
//! Application contexts identify the MAP operation set and version
//! used in a TCAP dialogue. The OID structure is:
//!
//! `{itu-t(0) identified-organization(4) etsi(0) mobileDomain(0)
//!   gsm-Network(1) map-ac(0) <ac-name>(<ac-id>) version(<ver>)}`
//!
//! Base OID: 0.4.0.0.1.0

use rasn::types::ObjectIdentifier;

/// Base OID for MAP application contexts: 0.4.0.0.1.0
const MAP_AC_BASE: [u32; 6] = [0, 4, 0, 0, 1, 0];

/// Create a MAP application context OID.
fn map_ac(ac_id: u32, version: u32) -> ObjectIdentifier {
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

// ─── Location Management ───────────────────────────────────────
/// networkLocUpContext (ac 1)
pub fn network_loc_up_context(version: u32) -> ObjectIdentifier { map_ac(1, version) }
/// locationCancellationContext (ac 2)
pub fn location_cancellation_context(version: u32) -> ObjectIdentifier { map_ac(2, version) }
/// interVlrInfoRetrievalContext (ac 15)
pub fn inter_vlr_info_retrieval_context(version: u32) -> ObjectIdentifier { map_ac(15, version) }
/// msPurgingContext (ac 27)
pub fn ms_purging_context(version: u32) -> ObjectIdentifier { map_ac(27, version) }

// ─── Authentication ────────────────────────────────────────────
/// infoRetrievalContext (ac 5) — v1/v2
pub fn info_retrieval_context(version: u32) -> ObjectIdentifier { map_ac(5, version) }
/// authenticationFailureReportContext (ac 27) — v3
pub fn authentication_failure_report_context(version: u32) -> ObjectIdentifier { map_ac(27, version) }

// ─── Subscriber Data ──────────────────────────────────────────
/// subscriberDataMngtContext (ac 16)
pub fn subscriber_data_mngt_context(version: u32) -> ObjectIdentifier { map_ac(16, version) }

// ─── Fault Recovery ───────────────────────────────────────────
/// resetContext (ac 10)
pub fn reset_context(version: u32) -> ObjectIdentifier { map_ac(10, version) }

// ─── Call Handling ────────────────────────────────────────────
/// roamingNumberEnquiryContext (ac 3)
pub fn roaming_number_enquiry_context(version: u32) -> ObjectIdentifier { map_ac(3, version) }
/// locationInfoRetrievalContext (ac 5)
pub fn location_info_retrieval_context(version: u32) -> ObjectIdentifier { map_ac(5, version) }

// ─── USSD ─────────────────────────────────────────────────────
/// networkUnstructuredSsContext (ac 19)
pub fn network_unstructured_ss_context(version: u32) -> ObjectIdentifier { map_ac(19, version) }

// ─── Supplementary Services ──────────────────────────────────
/// ss-InvocationNotificationContext (ac 36)
pub fn ss_invocation_notification_context(version: u32) -> ObjectIdentifier { map_ac(36, version) }

// ─── SMS ──────────────────────────────────────────────────────
/// shortMsgGatewayContext (ac 20) — for SRI-SM
pub fn short_msg_gateway_context(version: u32) -> ObjectIdentifier { map_ac(20, version) }
/// shortMsgMO-RelayContext (ac 21) — for MO-ForwardSM
pub fn short_msg_mo_relay_context(version: u32) -> ObjectIdentifier { map_ac(21, version) }
/// shortMsgMT-RelayContext (ac 25) — for MT-ForwardSM (v3)
pub fn short_msg_mt_relay_context(version: u32) -> ObjectIdentifier { map_ac(25, version) }
/// shortMsgAlertContext (ac 23) — for alertServiceCentre
pub fn short_msg_alert_context(version: u32) -> ObjectIdentifier { map_ac(23, version) }
/// shortMsgMT-VgcsRelayContext (ac 21) — for MT-ForwardSM (v1/v2)
pub fn short_msg_relay_context(version: u32) -> ObjectIdentifier { map_ac(21, version) }

// ─── CAP (CAMEL Application Part) — 3GPP TS 29.078 ──────────
// CAP OID structure:
//   CAP v1/v2: 0.4.0.0.1.0.50.<version>  (under MAP AC space)
//   CAP v3:    0.4.0.0.1.21.3.<ac_id>     (module 21)
//   CAP v4:    0.4.0.0.1.23.3.<ac_id>     (module 23)
// AC IDs: 4=gsmSSF-scfGeneric, 6=assistHandoff, 10=gsmSRF, 50=sms

/// CAP v1 (phase 1)
pub const CAP_V1: u32 = 1;
/// CAP v2 (phase 2)
pub const CAP_V2: u32 = 2;
/// CAP v3 (phase 3)
pub const CAP_V3: u32 = 3;
/// CAP v4 (phase 4)
pub const CAP_V4: u32 = 4;

fn cap_ac(version: u32, ac_id: u32) -> ObjectIdentifier {
    let components: Vec<u32> = match version {
        1 => vec![0, 4, 0, 0, 1, 0, 50, 0],          // CAP v1
        2 => vec![0, 4, 0, 0, 1, 0, 50, 1],          // CAP v2
        3 => vec![0, 4, 0, 0, 1, 21, 3, ac_id],      // CAP v3
        4 => vec![0, 4, 0, 0, 1, 23, 3, ac_id],      // CAP v4
        _ => vec![0, 4, 0, 0, 1, 21, 3, ac_id],      // default to v3
    };
    ObjectIdentifier::new_unchecked(components.into())
}

/// gsmSSF-scfGenericAC — gsmSSF ↔ gsmSCF call control
pub fn cap_gsmssf_scf_generic(version: u32) -> ObjectIdentifier { cap_ac(version, 4) }
/// gsmSSF-scfAssistHandoffAC
pub fn cap_gsmssf_scf_assist_handoff(version: u32) -> ObjectIdentifier { cap_ac(version, 6) }
/// gsmSRF-gsmSCF-AC — specialised resources
pub fn cap_gsmsrf_scf(version: u32) -> ObjectIdentifier { cap_ac(version, 10) }
/// cap-sms-AC — SMS control
pub fn cap_sms_ac(version: u32) -> ObjectIdentifier { cap_ac(version, 50) }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_msg_gateway_v3() {
        let oid = short_msg_gateway_context(V3);
        // 0.4.0.0.1.0.20.3
        let components: Vec<u32> = oid.iter().copied().collect();
        assert_eq!(components, vec![0, 4, 0, 0, 1, 0, 20, 3]);
    }

    #[test]
    fn network_loc_up_v2() {
        let oid = network_loc_up_context(V2);
        let components: Vec<u32> = oid.iter().copied().collect();
        assert_eq!(components, vec![0, 4, 0, 0, 1, 0, 1, 2]);
    }

    #[test]
    fn ussd_v2() {
        let oid = network_unstructured_ss_context(V2);
        let components: Vec<u32> = oid.iter().copied().collect();
        assert_eq!(components, vec![0, 4, 0, 0, 1, 0, 19, 2]);
    }

    #[test]
    fn different_versions() {
        let v1 = short_msg_gateway_context(V1);
        let v2 = short_msg_gateway_context(V2);
        let v3 = short_msg_gateway_context(V3);
        assert_ne!(v1, v2);
        assert_ne!(v2, v3);
    }
}
