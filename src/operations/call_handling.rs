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
///     extendedRoutingInfo                 ExtendedRoutingInfo OPTIONAL,
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
/// it from the bare `RoutingInfo` CHOICE a v1/v2 peer sends.
/// `extendedRoutingInfo` is untagged; `basicService`, `basicService2` and
/// `routingInfo2` have explicit context tags because they are CHOICEs.
#[derive(Debug, Clone, Default, PartialEq, Eq, AsnType)]
#[rasn(tag(context, 3))]
pub struct SendRoutingInfoRes {
    #[rasn(tag(context, 9))]
    pub imsi: Option<Imsi>,
    /// Complete ExtendedRoutingInfo TLV, without an extra explicit wrapper.
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

// Typed views of the opaque call-handling members.
use super::camel_subscription::{OCsi, TCsi};

/// ForwardingData (TS 29.002). Tags and declaration order follow the ASN.1.
#[derive(Debug, Clone, Default, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct ForwardingData {
    #[rasn(tag(context, 5))]
    pub forwarded_to_number: Option<IsdnAddressString>,
    #[rasn(tag(context, 4))]
    pub forwarded_to_subaddress: Option<OctetString>,
    #[rasn(tag(context, 6))]
    pub forwarding_options: Option<OctetString>,
    #[rasn(tag(context, 7))]
    pub extension_container: Option<ExtensionContainer>,
    // ... (ASN.1 extension marker)
    #[rasn(tag(context, 8))]
    pub long_forwarded_to_number: Option<OctetString>,
}

/// RoutingInfo, an untagged CHOICE.
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
#[rasn(choice)]
pub enum RoutingInfo {
    RoamingNumber(IsdnAddressString),
    ForwardingData(ForwardingData),
}

/// ExtendedRoutingInfo, with an implicitly tagged SEQUENCE alternative [8].
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
#[rasn(choice)]
// Keep the ASN.1 alternatives directly constructible, as with EpsInfo.
#[allow(clippy::large_enum_variant)]
pub enum ExtendedRoutingInfo {
    RoutingInfo(RoutingInfo),
    #[rasn(tag(context, 8))]
    CamelRoutingInfo(CamelRoutingInfo),
}

/// CamelRoutingInfo (TS 29.002). Tags and declaration order follow the ASN.1.
#[derive(Debug, Clone, Default, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct CamelRoutingInfo {
    pub forwarding_data: Option<ForwardingData>,
    #[rasn(tag(context, 0))]
    pub gmsc_camel_subscription_info: GmscCamelSubscriptionInfo,
    #[rasn(tag(context, 1))]
    pub extension_container: Option<ExtensionContainer>,
    // ... (ASN.1 extension marker)
}

/// GmscCamelSubscriptionInfo (TS 29.002). Tags and declaration order follow the ASN.1.
#[derive(Debug, Clone, Default, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct GmscCamelSubscriptionInfo {
    #[rasn(tag(context, 0))]
    pub t_csi: Option<TCsi>,
    #[rasn(tag(context, 1))]
    pub o_csi: Option<OCsi>,
    #[rasn(tag(context, 2))]
    pub extension_container: Option<ExtensionContainer>,
    // ... (ASN.1 extension marker)
    #[rasn(tag(context, 3))]
    pub o_bcsm_camel_tdp_criteria_list: Option<Opaque>,
    #[rasn(tag(context, 4))]
    pub t_bcsm_camel_tdp_criteria_list: Option<Opaque>,
    #[rasn(tag(context, 5))]
    pub d_csi: Option<Opaque>,
}

/// CamelInfo (TS 29.002). Tags and declaration order follow the ASN.1.
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct CamelInfo {
    pub supported_camel_phases: BitString,
    pub suppress_t_csi: Option<()>,
    pub extension_container: Option<ExtensionContainer>,
    // ... (ASN.1 extension marker)
    #[rasn(tag(context, 0))]
    pub offered_camel4_csis: Option<BitString>,
}

impl CamelInfo {
    /// Mandatory members; optional members start absent.
    pub fn new(supported_camel_phases: BitString) -> Self {
        Self {
            supported_camel_phases,
            suppress_t_csi: None,
            extension_container: None,
            offered_camel4_csis: None,
        }
    }
}

impl SendRoutingInfoArg {
    /// Encode a typed value into the existing opaque field. On error the field is unchanged.
    pub fn set_camel_info(&mut self, value: &CamelInfo) -> Result<(), crate::MapError> {
        self.camel_info = Some(Opaque::from_sequence(value)?);
        Ok(())
    }

    /// Decode a present opaque field using the strict MAP decoder.
    pub fn camel_info_typed(&self) -> Option<Result<CamelInfo, crate::MapError>> {
        self.camel_info.as_ref().map(Opaque::decode_sequence)
    }
}

impl SendRoutingInfoRes {
    /// Encode a typed value into the existing opaque field. On error the field is unchanged.
    pub fn set_extended_routing_info(
        &mut self,
        value: &ExtendedRoutingInfo,
    ) -> Result<(), crate::MapError> {
        self.extended_routing_info = Some(Opaque::new(crate::encode(value)?));
        Ok(())
    }

    /// Decode a present opaque field using the strict MAP decoder.
    pub fn extended_routing_info_typed(
        &self,
    ) -> Option<Result<ExtendedRoutingInfo, crate::MapError>> {
        self.extended_routing_info
            .as_ref()
            .map(|value| crate::decode(value.as_bytes()))
    }
}

// Split the untagged optional CHOICE into its wire alternatives. Each opaque
// value keeps the complete TLV; a concrete tag prevents greedy optional decoding.
#[derive(Debug, Clone, PartialEq, Eq)]
struct RoutingInfoEncoding<const IDENTIFIER: u8>(Opaque);

impl<const IDENTIFIER: u8> AsnType for RoutingInfoEncoding<IDENTIFIER> {
    const TAG: Tag = Tag::new(
        if IDENTIFIER & 0x80 == 0 {
            Class::Universal
        } else {
            Class::Context
        },
        (IDENTIFIER & 0x1f) as u32,
    );
}

impl<const IDENTIFIER: u8> Encode for RoutingInfoEncoding<IDENTIFIER> {
    fn encode_with_tag_and_constraints<'b, E: Encoder<'b>>(
        &self,
        encoder: &mut E,
        _tag: Tag,
        constraints: &Constraints,
        identifier: Identifier,
    ) -> Result<(), E::Error> {
        self.0
            .encode_with_tag_and_constraints(encoder, Tag::EOC, constraints, identifier)
    }
}

impl<const IDENTIFIER: u8> Decode for RoutingInfoEncoding<IDENTIFIER> {
    fn decode_with_tag_and_constraints<D: Decoder>(
        decoder: &mut D,
        _tag: Tag,
        constraints: &Constraints,
    ) -> Result<Self, D::Error> {
        Opaque::decode_with_tag_and_constraints(decoder, Tag::EOC, constraints).map(Self)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, AsnType, Decode, Encode)]
#[rasn(tag(context, 3))]
struct SendRoutingInfoResWire {
    #[rasn(tag(context, 9))]
    pub imsi: Option<Imsi>,
    pub roaming_number: Option<RoutingInfoEncoding<0x04>>,
    pub forwarding_data: Option<RoutingInfoEncoding<0x30>>,
    pub camel_routing_info: Option<RoutingInfoEncoding<0xa8>>,
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

impl From<SendRoutingInfoRes> for SendRoutingInfoResWire {
    fn from(value: SendRoutingInfoRes) -> Self {
        Self {
            imsi: value.imsi,
            roaming_number: value
                .extended_routing_info
                .as_ref()
                .filter(|v| v.as_bytes().first() == Some(&0x04))
                .cloned()
                .map(RoutingInfoEncoding),
            forwarding_data: value
                .extended_routing_info
                .as_ref()
                .filter(|v| v.as_bytes().first() == Some(&0x30))
                .cloned()
                .map(RoutingInfoEncoding),
            camel_routing_info: value
                .extended_routing_info
                .filter(|v| !matches!(v.as_bytes().first(), Some(0x04 | 0x30)))
                .map(RoutingInfoEncoding),
            cug_check_info: value.cug_check_info,
            cug_subscription_flag: value.cug_subscription_flag,
            subscriber_info: value.subscriber_info,
            ss_list: value.ss_list,
            basic_service: value.basic_service,
            forwarding_interrogation_required: value.forwarding_interrogation_required,
            vmsc_address: value.vmsc_address,
            extension_container: value.extension_container,
            naea_preferred_ci: value.naea_preferred_ci,
            ccbs_indicators: value.ccbs_indicators,
            msisdn: value.msisdn,
            number_portability_status: value.number_portability_status,
            ist_alert_timer: value.ist_alert_timer,
            supported_camel_phases_in_vmsc: value.supported_camel_phases_in_vmsc,
            offered_camel4_csis_in_vmsc: value.offered_camel4_csis_in_vmsc,
            routing_info2: value.routing_info2,
            ss_list2: value.ss_list2,
            basic_service2: value.basic_service2,
            allowed_services: value.allowed_services,
            unavailability_cause: value.unavailability_cause,
            release_resources_supported: value.release_resources_supported,
            gsm_bearer_capability: value.gsm_bearer_capability,
        }
    }
}

impl From<SendRoutingInfoResWire> for SendRoutingInfoRes {
    fn from(value: SendRoutingInfoResWire) -> Self {
        Self {
            imsi: value.imsi,
            extended_routing_info: value
                .roaming_number
                .map(|v| v.0)
                .or_else(|| value.forwarding_data.map(|v| v.0))
                .or_else(|| value.camel_routing_info.map(|v| v.0)),
            cug_check_info: value.cug_check_info,
            cug_subscription_flag: value.cug_subscription_flag,
            subscriber_info: value.subscriber_info,
            ss_list: value.ss_list,
            basic_service: value.basic_service,
            forwarding_interrogation_required: value.forwarding_interrogation_required,
            vmsc_address: value.vmsc_address,
            extension_container: value.extension_container,
            naea_preferred_ci: value.naea_preferred_ci,
            ccbs_indicators: value.ccbs_indicators,
            msisdn: value.msisdn,
            number_portability_status: value.number_portability_status,
            ist_alert_timer: value.ist_alert_timer,
            supported_camel_phases_in_vmsc: value.supported_camel_phases_in_vmsc,
            offered_camel4_csis_in_vmsc: value.offered_camel4_csis_in_vmsc,
            routing_info2: value.routing_info2,
            ss_list2: value.ss_list2,
            basic_service2: value.basic_service2,
            allowed_services: value.allowed_services,
            unavailability_cause: value.unavailability_cause,
            release_resources_supported: value.release_resources_supported,
            gsm_bearer_capability: value.gsm_bearer_capability,
        }
    }
}

impl Encode for SendRoutingInfoRes {
    fn encode_with_tag_and_constraints<'b, E: Encoder<'b>>(
        &self,
        encoder: &mut E,
        tag: Tag,
        constraints: &Constraints,
        identifier: Identifier,
    ) -> Result<(), E::Error> {
        SendRoutingInfoResWire::from(self.clone()).encode_with_tag_and_constraints(
            encoder,
            tag,
            constraints,
            identifier,
        )
    }
}

impl Decode for SendRoutingInfoRes {
    fn decode_with_tag_and_constraints<D: Decoder>(
        decoder: &mut D,
        tag: Tag,
        constraints: &Constraints,
    ) -> Result<Self, D::Error> {
        let wire =
            SendRoutingInfoResWire::decode_with_tag_and_constraints(decoder, tag, constraints)?;
        let alternatives = usize::from(wire.roaming_number.is_some())
            + usize::from(wire.forwarding_data.is_some())
            + usize::from(wire.camel_routing_info.is_some());
        if alternatives > 1 {
            return Err(rasn::de::Error::custom(
                "multiple ExtendedRoutingInfo alternatives",
                decoder.codec(),
            ));
        }
        Ok(wire.into())
    }
}
