//! Call Handling operations — 3GPP TS 29.002.
//!
//! - sendRoutingInfo (op 22)
//! - provideRoamingNumber (op 4)
//!
//! Every member TS 29.002 defines is modelled; see [`crate`] on what
//! happens to a member that is not. The call-control
//! sub-structures are carried as [`Opaque`] and survive the round trip unchanged.

use rasn::prelude::*;

use crate::types::{ExtensionContainer, Imsi, IsdnAddressString, Lmsi, Opaque};

/// InterrogationType — basic call or forwarding interrogation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, AsnType, Decode, Encode)]
#[rasn(enumerated)]
pub enum InterrogationType {
    BasicCall = 0,
    Forwarding = 1,
}

/// SendRoutingInfo-Arg (op 22).
///
/// ```asn1
/// SendRoutingInfoArg ::= SEQUENCE {
///     msisdn                          [0] ISDN-AddressString,
///     cug-CheckInfo                   [1] CUG-CheckInfo OPTIONAL,
///     numberOfForwarding              [2] NumberOfForwarding OPTIONAL,
///     interrogationType               [3] InterrogationType OPTIONAL,
///     or-Interrogation                [4] NULL OPTIONAL,
///     or-Capability                   [5] OR-Phase OPTIONAL,
///     gmsc-OrGsmSCF-Address           [6] ISDN-AddressString,
///     callReferenceNumber             [7] CallReferenceNumber OPTIONAL,
///     forwardingReason                [8] ForwardingReason OPTIONAL,
///     basicServiceGroup               [9] Ext-BasicServiceCode OPTIONAL,
///     networkSignalInfo              [10] ExternalSignalInfo OPTIONAL,
///     camelInfo                      [11] CamelInfo OPTIONAL,
///     suppressionOfAnnouncement      [12] SuppressionOfAnnouncement OPTIONAL,
///     extensionContainer             [13] ExtensionContainer OPTIONAL,
///     ...,
///     alertingPattern                [14] AlertingPattern OPTIONAL,
///     ccbs-Call                      [15] NULL OPTIONAL,
///     supportedCCBS-Phase            [16] SupportedCCBS-Phase OPTIONAL,
///     additionalSignalInfo           [17] Ext-ExternalSignalInfo OPTIONAL,
///     istSupportIndicator            [18] IST-SupportIndicator OPTIONAL,
///     pre-pagingSupported            [19] NULL OPTIONAL,
///     callDiversionTreatmentIndicator [20] CallDiversionTreatmentIndicator OPTIONAL,
///     longFTN-Supported              [21] NULL OPTIONAL,
///     suppress-VT-CSI                [22] NULL OPTIONAL,
///     suppressIncomingCallBarring    [23] NULL OPTIONAL,
///     gsmSCF-InitiatedCall           [24] NULL OPTIONAL,
///     basicServiceGroup2             [25] Ext-BasicServiceCode OPTIONAL,
///     networkSignalInfo2             [26] ExternalSignalInfo OPTIONAL,
///     suppressMTSS                   [27] SuppressMTSS OPTIONAL,
///     mtRoamingRetrySupported        [28] NULL OPTIONAL,
///     callPriority                   [29] EMLPP-Priority OPTIONAL }
/// ```
///
/// `basicServiceGroup` and `basicServiceGroup2` are CHOICEs, so `[9]` and `[25]`
/// are **explicit** tags.
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct SendRoutingInfoArg {
    #[rasn(tag(context, 0))]
    pub msisdn: IsdnAddressString,
    #[rasn(tag(context, 1))]
    pub cug_check_info: Option<Opaque>,
    #[rasn(tag(context, 2))]
    pub number_of_forwarding: Option<Integer>,
    #[rasn(tag(context, 3))]
    pub interrogation_type: Option<InterrogationType>,
    #[rasn(tag(context, 4))]
    pub or_interrogation: Option<()>,
    #[rasn(tag(context, 5))]
    pub or_capability: Option<Integer>,
    #[rasn(tag(context, 6))]
    pub gmsc_or_gsm_scf_address: IsdnAddressString,
    #[rasn(tag(context, 7))]
    pub call_reference_number: Option<OctetString>,
    #[rasn(tag(context, 8))]
    pub forwarding_reason: Option<Integer>,
    #[rasn(tag(explicit(context, 9)))]
    pub basic_service_group: Option<Opaque>,
    #[rasn(tag(context, 10))]
    pub network_signal_info: Option<Opaque>,
    #[rasn(tag(context, 11))]
    pub camel_info: Option<Opaque>,
    #[rasn(tag(context, 12))]
    pub suppression_of_announcement: Option<()>,
    #[rasn(tag(context, 13))]
    pub extension_container: Option<ExtensionContainer>,
    #[rasn(tag(context, 14))]
    pub alerting_pattern: Option<OctetString>,
    #[rasn(tag(context, 15))]
    pub ccbs_call: Option<()>,
    #[rasn(tag(context, 16))]
    pub supported_ccbs_phase: Option<Integer>,
    #[rasn(tag(context, 17))]
    pub additional_signal_info: Option<Opaque>,
    #[rasn(tag(context, 18))]
    pub ist_support_indicator: Option<Integer>,
    #[rasn(tag(context, 19))]
    pub pre_paging_supported: Option<()>,
    #[rasn(tag(context, 20))]
    pub call_diversion_treatment_indicator: Option<OctetString>,
    #[rasn(tag(context, 21))]
    pub long_ftn_supported: Option<()>,
    #[rasn(tag(context, 22))]
    pub suppress_vt_csi: Option<()>,
    #[rasn(tag(context, 23))]
    pub suppress_incoming_call_barring: Option<()>,
    #[rasn(tag(context, 24))]
    pub gsm_scf_initiated_call: Option<()>,
    #[rasn(tag(explicit(context, 25)))]
    pub basic_service_group2: Option<Opaque>,
    #[rasn(tag(context, 26))]
    pub network_signal_info2: Option<Opaque>,
    #[rasn(tag(context, 27))]
    pub suppress_mtss: Option<BitString>,
    #[rasn(tag(context, 28))]
    pub mt_roaming_retry_supported: Option<()>,
    #[rasn(tag(context, 29))]
    pub call_priority: Option<Integer>,
}

impl SendRoutingInfoArg {
    /// The two mandatory members; every optional member starts `None`.
    pub fn new(msisdn: IsdnAddressString, gmsc_or_gsm_scf_address: IsdnAddressString) -> Self {
        Self {
            msisdn,
            cug_check_info: None,
            number_of_forwarding: None,
            interrogation_type: None,
            or_interrogation: None,
            or_capability: None,
            gmsc_or_gsm_scf_address,
            call_reference_number: None,
            forwarding_reason: None,
            basic_service_group: None,
            network_signal_info: None,
            camel_info: None,
            suppression_of_announcement: None,
            extension_container: None,
            alerting_pattern: None,
            ccbs_call: None,
            supported_ccbs_phase: None,
            additional_signal_info: None,
            ist_support_indicator: None,
            pre_paging_supported: None,
            call_diversion_treatment_indicator: None,
            long_ftn_supported: None,
            suppress_vt_csi: None,
            suppress_incoming_call_barring: None,
            gsm_scf_initiated_call: None,
            basic_service_group2: None,
            network_signal_info2: None,
            suppress_mtss: None,
            mt_roaming_retry_supported: None,
            call_priority: None,
        }
    }
}

/// SendRoutingInfo-Res (op 22).
///
/// ```asn1
/// SendRoutingInfoRes ::= [3] SEQUENCE {
///     imsi                            [9] IMSI OPTIONAL,
///     extendedRoutingInfo             [8] ExtendedRoutingInfo OPTIONAL,
///     cug-CheckInfo                   [3] CUG-CheckInfo OPTIONAL,
///     cugSubscriptionFlag             [6] NULL OPTIONAL,
///     subscriberInfo                  [7] SubscriberInfo OPTIONAL,
///     ss-List                         [1] SS-List OPTIONAL,
///     basicService                    [5] Ext-BasicServiceCode OPTIONAL,
///     forwardingInterrogationRequired [4] NULL OPTIONAL,
///     vmsc-Address                    [2] ISDN-AddressString OPTIONAL,
///     extensionContainer              [0] ExtensionContainer OPTIONAL,
///     ...,
///     naea-PreferredCI               [10] NAEA-PreferredCI OPTIONAL,
///     ccbs-Indicators                [11] CCBS-Indicators OPTIONAL,
///     msisdn                         [12] ISDN-AddressString OPTIONAL,
///     numberPortabilityStatus        [13] NumberPortabilityStatus OPTIONAL,
///     istAlertTimer                  [14] IST-AlertTimerValue OPTIONAL,
///     supportedCamelPhasesInVMSC     [15] SupportedCamelPhases OPTIONAL,
///     offeredCamel4CSIsInVMSC        [16] OfferedCamel4CSIs OPTIONAL,
///     routingInfo2                   [17] RoutingInfo OPTIONAL,
///     ss-List2                       [18] SS-List OPTIONAL,
///     basicService2                  [19] Ext-BasicServiceCode OPTIONAL,
///     allowedServices                [20] AllowedServices OPTIONAL,
///     unavailabilityCause            [21] UnavailabilityCause OPTIONAL,
///     releaseResourcesSupported      [22] NULL OPTIONAL,
///     gsm-BearerCapability           [23] ExternalSignalInfo OPTIONAL }
/// ```
///
/// The result as a whole carries context tag `[3]`, which is what distinguishes
/// it from the bare `RoutingInfo` CHOICE a v1/v2 peer sends. `extendedRoutingInfo`,
/// `basicService`, `basicService2` and `routingInfo2` are CHOICEs, so their tags
/// are **explicit**.
#[derive(Debug, Clone, Default, PartialEq, Eq, AsnType, Decode, Encode)]
#[rasn(tag(context, 3))]
pub struct SendRoutingInfoRes {
    #[rasn(tag(context, 9))]
    pub imsi: Option<Imsi>,
    #[rasn(tag(explicit(context, 8)))]
    pub extended_routing_info: Option<Opaque>,
    #[rasn(tag(context, 3))]
    pub cug_check_info: Option<Opaque>,
    #[rasn(tag(context, 6))]
    pub cug_subscription_flag: Option<()>,
    #[rasn(tag(context, 7))]
    pub subscriber_info: Option<crate::operations::subscriber_info::SubscriberInfo>,
    #[rasn(tag(context, 1))]
    pub ss_list: Option<Vec<OctetString>>,
    #[rasn(tag(explicit(context, 5)))]
    pub basic_service: Option<Opaque>,
    #[rasn(tag(context, 4))]
    pub forwarding_interrogation_required: Option<()>,
    #[rasn(tag(context, 2))]
    pub vmsc_address: Option<IsdnAddressString>,
    #[rasn(tag(context, 0))]
    pub extension_container: Option<ExtensionContainer>,
    #[rasn(tag(context, 10))]
    pub naea_preferred_ci: Option<Opaque>,
    #[rasn(tag(context, 11))]
    pub ccbs_indicators: Option<Opaque>,
    #[rasn(tag(context, 12))]
    pub msisdn: Option<IsdnAddressString>,
    #[rasn(tag(context, 13))]
    pub number_portability_status: Option<Integer>,
    #[rasn(tag(context, 14))]
    pub ist_alert_timer: Option<Integer>,
    #[rasn(tag(context, 15))]
    pub supported_camel_phases_in_vmsc: Option<BitString>,
    #[rasn(tag(context, 16))]
    pub offered_camel4_csis_in_vmsc: Option<BitString>,
    #[rasn(tag(explicit(context, 17)))]
    pub routing_info2: Option<Opaque>,
    #[rasn(tag(context, 18))]
    pub ss_list2: Option<Vec<OctetString>>,
    #[rasn(tag(explicit(context, 19)))]
    pub basic_service2: Option<Opaque>,
    #[rasn(tag(context, 20))]
    pub allowed_services: Option<BitString>,
    #[rasn(tag(context, 21))]
    pub unavailability_cause: Option<Integer>,
    #[rasn(tag(context, 22))]
    pub release_resources_supported: Option<()>,
    #[rasn(tag(context, 23))]
    pub gsm_bearer_capability: Option<Opaque>,
}

/// ProvideRoamingNumber-Arg (op 4).
///
/// ```asn1
/// ProvideRoamingNumberArg ::= SEQUENCE {
///     imsi                        [0] IMSI,
///     msc-Number                  [1] ISDN-AddressString,
///     msisdn                      [2] ISDN-AddressString OPTIONAL,
///     lmsi                        [4] LMSI OPTIONAL,
///     gsm-BearerCapability        [5] ExternalSignalInfo OPTIONAL,
///     networkSignalInfo           [6] ExternalSignalInfo OPTIONAL,
///     suppressionOfAnnouncement   [7] SuppressionOfAnnouncement OPTIONAL,
///     gmsc-Address                [8] ISDN-AddressString OPTIONAL,
///     callReferenceNumber         [9] CallReferenceNumber OPTIONAL,
///     or-Interrogation           [10] NULL OPTIONAL,
///     extensionContainer         [11] ExtensionContainer OPTIONAL,
///     ...,
///     alertingPattern            [12] AlertingPattern OPTIONAL,
///     ccbs-Call                  [13] NULL OPTIONAL,
///     supportedCamelPhasesInInterrogatingNode [15] SupportedCamelPhases OPTIONAL,
///     additionalSignalInfo       [14] Ext-ExternalSignalInfo OPTIONAL,
///     orNotSupportedInGMSC       [16] NULL OPTIONAL,
///     pre-pagingSupported        [17] NULL OPTIONAL,
///     longFTN-Supported          [18] NULL OPTIONAL,
///     suppress-VT-CSI            [19] NULL OPTIONAL,
///     offeredCamel4CSIsInInterrogatingNode [20] OfferedCamel4CSIs OPTIONAL,
///     mtRoamingRetrySupported    [21] NULL OPTIONAL,
///     pagingArea                 [22] PagingArea OPTIONAL,
///     callPriority               [23] EMLPP-Priority OPTIONAL,
///     mtrf-Indicator             [24] NULL OPTIONAL,
///     oldMSC-Number              [25] ISDN-AddressString OPTIONAL,
///     lastUsedLtePLMN-Id         [26] PLMN-Id OPTIONAL }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct ProvideRoamingNumberArg {
    #[rasn(tag(context, 0))]
    pub imsi: Imsi,
    #[rasn(tag(context, 1))]
    pub msc_number: IsdnAddressString,
    #[rasn(tag(context, 2))]
    pub msisdn: Option<IsdnAddressString>,
    #[rasn(tag(context, 4))]
    pub lmsi: Option<Lmsi>,
    #[rasn(tag(context, 5))]
    pub gsm_bearer_capability: Option<Opaque>,
    #[rasn(tag(context, 6))]
    pub network_signal_info: Option<Opaque>,
    #[rasn(tag(context, 7))]
    pub suppression_of_announcement: Option<()>,
    #[rasn(tag(context, 8))]
    pub gmsc_address: Option<IsdnAddressString>,
    #[rasn(tag(context, 9))]
    pub call_reference_number: Option<OctetString>,
    #[rasn(tag(context, 10))]
    pub or_interrogation: Option<()>,
    #[rasn(tag(context, 11))]
    pub extension_container: Option<ExtensionContainer>,
    #[rasn(tag(context, 12))]
    pub alerting_pattern: Option<OctetString>,
    #[rasn(tag(context, 13))]
    pub ccbs_call: Option<()>,
    #[rasn(tag(context, 15))]
    pub supported_camel_phases_in_interrogating_node: Option<BitString>,
    #[rasn(tag(context, 14))]
    pub additional_signal_info: Option<Opaque>,
    #[rasn(tag(context, 16))]
    pub or_not_supported_in_gmsc: Option<()>,
    #[rasn(tag(context, 17))]
    pub pre_paging_supported: Option<()>,
    #[rasn(tag(context, 18))]
    pub long_ftn_supported: Option<()>,
    #[rasn(tag(context, 19))]
    pub suppress_vt_csi: Option<()>,
    #[rasn(tag(context, 20))]
    pub offered_camel4_csis_in_interrogating_node: Option<BitString>,
    #[rasn(tag(context, 21))]
    pub mt_roaming_retry_supported: Option<()>,
    #[rasn(tag(context, 22))]
    pub paging_area: Option<Opaque>,
    #[rasn(tag(context, 23))]
    pub call_priority: Option<Integer>,
    #[rasn(tag(context, 24))]
    pub mtrf_indicator: Option<()>,
    #[rasn(tag(context, 25))]
    pub old_msc_number: Option<IsdnAddressString>,
    #[rasn(tag(context, 26))]
    pub last_used_lte_plmn_id: Option<OctetString>,
}

impl ProvideRoamingNumberArg {
    /// The two mandatory members; every optional member starts `None`.
    pub fn new(imsi: Imsi, msc_number: IsdnAddressString) -> Self {
        Self {
            imsi,
            msc_number,
            msisdn: None,
            lmsi: None,
            gsm_bearer_capability: None,
            network_signal_info: None,
            suppression_of_announcement: None,
            gmsc_address: None,
            call_reference_number: None,
            or_interrogation: None,
            extension_container: None,
            alerting_pattern: None,
            ccbs_call: None,
            supported_camel_phases_in_interrogating_node: None,
            additional_signal_info: None,
            or_not_supported_in_gmsc: None,
            pre_paging_supported: None,
            long_ftn_supported: None,
            suppress_vt_csi: None,
            offered_camel4_csis_in_interrogating_node: None,
            mt_roaming_retry_supported: None,
            paging_area: None,
            call_priority: None,
            mtrf_indicator: None,
            old_msc_number: None,
            last_used_lte_plmn_id: None,
        }
    }
}

/// ProvideRoamingNumber-Res (op 4).
///
/// ```asn1
/// ProvideRoamingNumberRes ::= SEQUENCE {
///     roamingNumber              ISDN-AddressString,
///     extensionContainer         ExtensionContainer OPTIONAL,
///     ...,
///     releaseResourcesSupported  NULL OPTIONAL,
///     vmsc-Address               ISDN-AddressString OPTIONAL }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct ProvideRoamingNumberRes {
    pub roaming_number: IsdnAddressString,
    pub extension_container: Option<ExtensionContainer>,
    pub release_resources_supported: Option<()>,
    pub vmsc_address: Option<IsdnAddressString>,
}

impl ProvideRoamingNumberRes {
    /// The one mandatory member; every optional member starts `None`.
    pub fn new(roaming_number: IsdnAddressString) -> Self {
        Self {
            roaming_number,
            extension_container: None,
            release_resources_supported: None,
            vmsc_address: None,
        }
    }
}

/// Operation codes for call handling. Re-exported from
/// [`crate::types::op_codes`].
pub mod op_codes {
    pub use crate::types::op_codes::{
        IST_ALERT, IST_COMMAND, PROVIDE_ROAMING_NUMBER, RELEASE_RESOURCES, REMOTE_USER_FREE,
        RESUME_CALL_HANDLING, SEND_ROUTING_INFO, SET_REPORTING_STATE, STATUS_REPORT,
    };
}

/// ResumeCallHandling-Arg (op 6) — the VMSC handing an unanswered call back to
/// the GMSC so it can apply call forwarding.
///
/// ```asn1
/// ResumeCallHandlingArg ::= SEQUENCE {
///     callReferenceNumber        [0] CallReferenceNumber OPTIONAL,
///     basicServiceGroup          [1] Ext-BasicServiceCode OPTIONAL,
///     forwardingData             [2] ForwardingData OPTIONAL,
///     imsi                       [3] IMSI OPTIONAL,
///     cug-CheckInfo              [4] CUG-CheckInfo OPTIONAL,
///     o-CSI                      [5] O-CSI OPTIONAL,
///     extensionContainer         [7] ExtensionContainer OPTIONAL,
///     ...,
///     ccbs-Possible              [8] NULL OPTIONAL,
///     msisdn                     [9] ISDN-AddressString OPTIONAL,
///     uu-Data                   [10] UU-Data OPTIONAL,
///     allInformationSent        [11] NULL OPTIONAL,
///     d-csi                     [12] D-CSI OPTIONAL,
///     o-BcsmCamelTDPCriteriaList [13] O-BcsmCamelTDPCriteriaList OPTIONAL,
///     basicServiceGroup2        [14] Ext-BasicServiceCode OPTIONAL,
///     mtRoamingRetry            [15] NULL OPTIONAL }
/// ```
///
/// `basicServiceGroup` and `basicServiceGroup2` are CHOICEs, so `[1]` and `[14]`
/// are **explicit** tags.
#[derive(Debug, Clone, Default, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct ResumeCallHandlingArg {
    #[rasn(tag(context, 0))]
    pub call_reference_number: Option<OctetString>,
    #[rasn(tag(explicit(context, 1)))]
    pub basic_service_group: Option<Opaque>,
    #[rasn(tag(context, 2))]
    pub forwarding_data: Option<Opaque>,
    #[rasn(tag(context, 3))]
    pub imsi: Option<Imsi>,
    #[rasn(tag(context, 4))]
    pub cug_check_info: Option<Opaque>,
    #[rasn(tag(context, 5))]
    pub o_csi: Option<Opaque>,
    #[rasn(tag(context, 7))]
    pub extension_container: Option<ExtensionContainer>,
    #[rasn(tag(context, 8))]
    pub ccbs_possible: Option<()>,
    #[rasn(tag(context, 9))]
    pub msisdn: Option<IsdnAddressString>,
    #[rasn(tag(context, 10))]
    pub uu_data: Option<Opaque>,
    #[rasn(tag(context, 11))]
    pub all_information_sent: Option<()>,
    #[rasn(tag(context, 12))]
    pub d_csi: Option<Opaque>,
    #[rasn(tag(context, 13))]
    pub o_bcsm_camel_tdp_criteria_list: Option<Opaque>,
    #[rasn(tag(explicit(context, 14)))]
    pub basic_service_group2: Option<Opaque>,
    #[rasn(tag(context, 15))]
    pub mt_roaming_retry: Option<()>,
}

/// ResumeCallHandling-Res (op 6).
#[derive(Debug, Clone, Default, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct ResumeCallHandlingRes {
    pub extension_container: Option<ExtensionContainer>,
}

/// ReleaseResources-Arg (op 20) — tell the VMSC the roaming number it allocated
/// is no longer needed.
///
/// ```asn1
/// ReleaseResourcesArg ::= SEQUENCE {
///     msrn                ISDN-AddressString,
///     extensionContainer  ExtensionContainer OPTIONAL,
///     ... }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct ReleaseResourcesArg {
    pub msrn: IsdnAddressString,
    pub extension_container: Option<ExtensionContainer>,
}

/// ReleaseResources-Res (op 20).
#[derive(Debug, Clone, Default, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct ReleaseResourcesRes {
    pub extension_container: Option<ExtensionContainer>,
}

/// SetReportingState-Arg (op 73) — arm or disarm CCBS monitoring in the VLR.
///
/// ```asn1
/// SetReportingStateArg ::= SEQUENCE {
///     imsi                [0] IMSI OPTIONAL,
///     lmsi                [1] LMSI OPTIONAL,
///     ccbs-Monitoring     [2] ReportingState OPTIONAL,
///     extensionContainer  [3] ExtensionContainer OPTIONAL,
///     ... }
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct SetReportingStateArg {
    #[rasn(tag(context, 0))]
    pub imsi: Option<Imsi>,
    #[rasn(tag(context, 1))]
    pub lmsi: Option<Lmsi>,
    /// `ReportingState ::= ENUMERATED { stopMonitoring(0), startMonitoring(1) }`.
    #[rasn(tag(context, 2))]
    pub ccbs_monitoring: Option<Integer>,
    #[rasn(tag(context, 3))]
    pub extension_container: Option<ExtensionContainer>,
}

/// SetReportingState-Res (op 73).
///
/// ```asn1
/// SetReportingStateRes ::= SEQUENCE {
///     ccbs-SubscriberStatus [0] CCBS-SubscriberStatus OPTIONAL,
///     extensionContainer    [1] ExtensionContainer OPTIONAL,
///     ... }
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct SetReportingStateRes {
    /// `ccbsNotIdle(0)`, `ccbsIdle(1)`, `ccbsNotReachable(2)`.
    #[rasn(tag(context, 0))]
    pub ccbs_subscriber_status: Option<Integer>,
    #[rasn(tag(context, 1))]
    pub extension_container: Option<ExtensionContainer>,
}

/// StatusReport-Arg (op 74) — the VLR reporting a monitored CCBS event.
///
/// ```asn1
/// StatusReportArg ::= SEQUENCE {
///     imsi                [0] IMSI,
///     eventReportData     [1] EventReportData OPTIONAL,
///     callReportdata      [2] CallReportData OPTIONAL,
///     extensionContainer  [3] ExtensionContainer OPTIONAL,
///     ... }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct StatusReportArg {
    #[rasn(tag(context, 0))]
    pub imsi: Imsi,
    #[rasn(tag(context, 1))]
    pub event_report_data: Option<Opaque>,
    #[rasn(tag(context, 2))]
    pub call_report_data: Option<Opaque>,
    #[rasn(tag(context, 3))]
    pub extension_container: Option<ExtensionContainer>,
}

impl StatusReportArg {
    /// The one mandatory member; every optional member starts `None`.
    pub fn new(imsi: Imsi) -> Self {
        Self {
            imsi,
            event_report_data: None,
            call_report_data: None,
            extension_container: None,
        }
    }
}

/// StatusReport-Res (op 74).
///
/// ```asn1
/// StatusReportRes ::= SEQUENCE {
///     extensionContainer  [0] ExtensionContainer OPTIONAL,
///     ... }
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct StatusReportRes {
    #[rasn(tag(context, 0))]
    pub extension_container: Option<ExtensionContainer>,
}

/// RemoteUserFree-Arg (op 75) — the HLR telling the VLR the B party is free, so
/// a queued CCBS recall can go out.
///
/// ```asn1
/// RemoteUserFreeArg ::= SEQUENCE {
///     imsi                [0] IMSI,
///     callInfo            [1] ExternalSignalInfo,
///     ccbs-Feature        [2] CCBS-Feature,
///     translatedB-Number  [3] ISDN-AddressString,
///     replaceB-Number     [4] NULL OPTIONAL,
///     alertingPattern     [5] AlertingPattern OPTIONAL,
///     extensionContainer  [6] ExtensionContainer OPTIONAL,
///     ... }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct RemoteUserFreeArg {
    #[rasn(tag(context, 0))]
    pub imsi: Imsi,
    #[rasn(tag(context, 1))]
    pub call_info: Option<Opaque>,
    #[rasn(tag(context, 2))]
    pub ccbs_feature: Option<Opaque>,
    #[rasn(tag(context, 3))]
    pub translated_b_number: Option<IsdnAddressString>,
    #[rasn(tag(context, 4))]
    pub replace_b_number: Option<()>,
    #[rasn(tag(context, 5))]
    pub alerting_pattern: Option<OctetString>,
    #[rasn(tag(context, 6))]
    pub extension_container: Option<ExtensionContainer>,
}

impl RemoteUserFreeArg {
    /// The one member this crate treats as mandatory; the rest start `None`.
    pub fn new(imsi: Imsi) -> Self {
        Self {
            imsi,
            call_info: None,
            ccbs_feature: None,
            translated_b_number: None,
            replace_b_number: None,
            alerting_pattern: None,
            extension_container: None,
        }
    }
}

/// RemoteUserFree-Res (op 75).
///
/// ```asn1
/// RemoteUserFreeRes ::= SEQUENCE {
///     ruf-Outcome        [0] RUF-Outcome,
///     extensionContainer [1] ExtensionContainer OPTIONAL,
///     ... }
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct RemoteUserFreeRes {
    /// `accepted(0)`, `rejected(1)`, `noResponseFromFreeMS(2)`,
    /// `noResponseFromBusyMS(3)`, `udubFromFreeMS(4)`, `udubFromBusyMS(5)`.
    #[rasn(tag(context, 0))]
    pub ruf_outcome: Option<Integer>,
    #[rasn(tag(context, 1))]
    pub extension_container: Option<ExtensionContainer>,
}

/// IST-Alert-Arg (op 87) — the VMSC asking the HLR what to do about a call that
/// has exceeded its immediate-service-termination timer.
///
/// ```asn1
/// IST-AlertArg ::= SEQUENCE {
///     imsi                [0] IMSI,
///     extensionContainer  [1] ExtensionContainer OPTIONAL,
///     ... }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct IstAlertArg {
    #[rasn(tag(context, 0))]
    pub imsi: Imsi,
    #[rasn(tag(context, 1))]
    pub extension_container: Option<ExtensionContainer>,
}

/// IST-Alert-Res (op 87).
///
/// ```asn1
/// IST-AlertRes ::= SEQUENCE {
///     istAlertTimer            [0] IST-AlertTimerValue OPTIONAL,
///     istInformationWithdraw   [1] NULL OPTIONAL,
///     callTerminationIndicator [2] CallTerminationIndicator OPTIONAL,
///     extensionContainer       [3] ExtensionContainer OPTIONAL,
///     ... }
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct IstAlertRes {
    #[rasn(tag(context, 0))]
    pub ist_alert_timer: Option<Integer>,
    #[rasn(tag(context, 1))]
    pub ist_information_withdraw: Option<()>,
    /// `terminateCallActivityReferred(0)`, `terminateAllCallActivities(1)`.
    #[rasn(tag(context, 2))]
    pub call_termination_indicator: Option<Integer>,
    #[rasn(tag(context, 3))]
    pub extension_container: Option<ExtensionContainer>,
}

/// IST-Command-Arg (op 88) — the HLR telling the VMSC to terminate the call.
///
/// ```asn1
/// IST-CommandArg ::= SEQUENCE {
///     imsi                [0] IMSI,
///     extensionContainer  [1] ExtensionContainer OPTIONAL,
///     ... }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct IstCommandArg {
    #[rasn(tag(context, 0))]
    pub imsi: Imsi,
    #[rasn(tag(context, 1))]
    pub extension_container: Option<ExtensionContainer>,
}

/// IST-Command-Res (op 88).
#[derive(Debug, Clone, Default, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct IstCommandRes {
    pub extension_container: Option<ExtensionContainer>,
}
