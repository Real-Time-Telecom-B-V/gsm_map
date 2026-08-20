//! Location Services (LCS) operations — 3GPP TS 29.002.
//!
//! - provideSubscriberLocation (op 83)
//! - sendRoutingInfoForLCS (op 85)
//! - subscriberLocationReport (op 86)
//!
//! Every member TS 29.002 defines is modelled; see [`crate`] on why an
//! unmodelled member is fatal rather than merely absent. The positioning
//! sub-structures are carried as [`Opaque`] and survive the round trip unchanged.

use rasn::prelude::*;

use crate::types::{ExtensionContainer, Imsi, IsdnAddressString, Lmsi, Opaque};

/// LCS-Event — why a location report is being sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, AsnType, Decode, Encode)]
#[rasn(enumerated)]
pub enum LcsEvent {
    EmergencyCallOrigination = 0,
    EmergencyCallRelease = 1,
    MoLr = 2,
    DeferredMtLrResponse = 3,
    DeferredMoLrTttpInitiation = 4,
}

/// SubscriberIdentity for LCS — a CHOICE, so a `[n]` on it is **explicit**.
///
/// ```asn1
/// SubscriberIdentity ::= CHOICE {
///     imsi    [0] IMSI,
///     msisdn  [1] ISDN-AddressString }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
#[rasn(choice)]
pub enum SubscriberIdentityLcs {
    #[rasn(tag(context, 0))]
    Imsi(Imsi),
    #[rasn(tag(context, 1))]
    Msisdn(IsdnAddressString),
}

/// LCS-ClientID — who is asking for the subscriber's location, and under what
/// authority. The privacy check an operator applies turns on this.
///
/// ```asn1
/// LCS-ClientID ::= SEQUENCE {
///     lcsClientType        [0] LCSClientType,
///     lcsClientExternalID  [1] LCSClientExternalID OPTIONAL,
///     lcsClientDialedByMS  [2] AddressString OPTIONAL,
///     lcsClientInternalID  [3] LCSClientInternalID OPTIONAL,
///     lcsClientName        [4] LCSClientName OPTIONAL,
///     ...,
///     lcsAPN               [5] APN OPTIONAL,
///     lcsRequestorID       [6] LCSRequestorID OPTIONAL }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct LcsClientId {
    /// `emergencyServices(0)`, `valueAddedServices(1)`,
    /// `plmnOperatorServices(2)`, `lawfulInterceptServices(3)`.
    #[rasn(tag(context, 0))]
    pub lcs_client_type: Integer,
    #[rasn(tag(context, 1))]
    pub lcs_client_external_id: Option<Opaque>,
    #[rasn(tag(context, 2))]
    pub lcs_client_dialed_by_ms: Option<IsdnAddressString>,
    /// `broadcastService(0)`, `o-andM-HPLMN(1)`, `o-andM-VPLMN(2)`,
    /// `anonymousLocation(3)`, `targetMSsubscribedService(4)`.
    #[rasn(tag(context, 3))]
    pub lcs_client_internal_id: Option<Integer>,
    #[rasn(tag(context, 4))]
    pub lcs_client_name: Option<Opaque>,
    #[rasn(tag(context, 5))]
    pub lcs_apn: Option<OctetString>,
    #[rasn(tag(context, 6))]
    pub lcs_requestor_id: Option<Opaque>,
}

impl LcsClientId {
    /// The one mandatory member; every optional member starts `None`.
    pub fn new(lcs_client_type: Integer) -> Self {
        Self {
            lcs_client_type,
            lcs_client_external_id: None,
            lcs_client_dialed_by_ms: None,
            lcs_client_internal_id: None,
            lcs_client_name: None,
            lcs_apn: None,
            lcs_requestor_id: None,
        }
    }
}

/// ProvideSubscriberLocation-Arg (op 83).
///
/// ```asn1
/// ProvideSubscriberLocation-Arg ::= SEQUENCE {
///     locationType                    LocationType,
///     mlc-Number                      ISDN-AddressString,
///     lcs-ClientID                [0] LCS-ClientID OPTIONAL,
///     privacyOverride             [1] NULL OPTIONAL,
///     imsi                        [2] IMSI OPTIONAL,
///     msisdn                      [3] ISDN-AddressString OPTIONAL,
///     lmsi                        [4] LMSI OPTIONAL,
///     imei                        [5] IMEI OPTIONAL,
///     lcs-Priority                [6] LCS-Priority OPTIONAL,
///     lcs-QoS                     [7] LCS-QoS OPTIONAL,
///     extensionContainer          [8] ExtensionContainer OPTIONAL,
///     ...,
///     supportedGADShapes          [9] SupportedGADShapes OPTIONAL,
///     lcs-ReferenceNumber        [10] LCS-ReferenceNumber OPTIONAL,
///     lcsServiceTypeID           [11] LCSServiceTypeID OPTIONAL,
///     lcsCodeword                [12] LCSCodeword OPTIONAL,
///     lcs-PrivacyCheck           [13] LCS-PrivacyCheck OPTIONAL,
///     areaEventInfo              [14] AreaEventInfo OPTIONAL,
///     h-gmlc-Address             [15] GSN-Address OPTIONAL,
///     mo-lrShortCircuitIndicator [16] NULL OPTIONAL,
///     periodicLDRInfo            [17] PeriodicLDRInfo OPTIONAL,
///     reportingPLMNList          [18] ReportingPLMNList OPTIONAL }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct ProvideSubscriberLocationArg {
    /// `LocationType ::= SEQUENCE { locationEstimateType [0] ..., ... }`.
    pub location_type: Opaque,
    pub mlc_number: IsdnAddressString,
    #[rasn(tag(context, 0))]
    pub lcs_client_id: Option<LcsClientId>,
    #[rasn(tag(context, 1))]
    pub privacy_override: Option<()>,
    #[rasn(tag(context, 2))]
    pub imsi: Option<Imsi>,
    #[rasn(tag(context, 3))]
    pub msisdn: Option<IsdnAddressString>,
    #[rasn(tag(context, 4))]
    pub lmsi: Option<Lmsi>,
    #[rasn(tag(context, 5))]
    pub imei: Option<OctetString>,
    #[rasn(tag(context, 6))]
    pub lcs_priority: Option<OctetString>,
    #[rasn(tag(context, 7))]
    pub lcs_qos: Option<Opaque>,
    #[rasn(tag(context, 8))]
    pub extension_container: Option<ExtensionContainer>,
    #[rasn(tag(context, 9))]
    pub supported_gad_shapes: Option<BitString>,
    #[rasn(tag(context, 10))]
    pub lcs_reference_number: Option<OctetString>,
    #[rasn(tag(context, 11))]
    pub lcs_service_type_id: Option<Integer>,
    #[rasn(tag(context, 12))]
    pub lcs_codeword: Option<Opaque>,
    #[rasn(tag(context, 13))]
    pub lcs_privacy_check: Option<Opaque>,
    #[rasn(tag(context, 14))]
    pub area_event_info: Option<Opaque>,
    #[rasn(tag(context, 15))]
    pub h_gmlc_address: Option<OctetString>,
    #[rasn(tag(context, 16))]
    pub mo_lr_short_circuit_indicator: Option<()>,
    #[rasn(tag(context, 17))]
    pub periodic_ldr_info: Option<Opaque>,
    #[rasn(tag(context, 18))]
    pub reporting_plmn_list: Option<Opaque>,
}

impl ProvideSubscriberLocationArg {
    /// The two mandatory members; every optional member starts `None`.
    pub fn new(location_type: Opaque, mlc_number: IsdnAddressString) -> Self {
        Self {
            location_type,
            mlc_number,
            lcs_client_id: None,
            privacy_override: None,
            imsi: None,
            msisdn: None,
            lmsi: None,
            imei: None,
            lcs_priority: None,
            lcs_qos: None,
            extension_container: None,
            supported_gad_shapes: None,
            lcs_reference_number: None,
            lcs_service_type_id: None,
            lcs_codeword: None,
            lcs_privacy_check: None,
            area_event_info: None,
            h_gmlc_address: None,
            mo_lr_short_circuit_indicator: None,
            periodic_ldr_info: None,
            reporting_plmn_list: None,
        }
    }
}

/// ProvideSubscriberLocation-Res (op 83).
///
/// ```asn1
/// ProvideSubscriberLocation-Res ::= SEQUENCE {
///     locationEstimate                Ext-GeographicalInformation,
///     ageOfLocationEstimate       [0] AgeOfLocationInformation OPTIONAL,
///     extensionContainer          [1] ExtensionContainer OPTIONAL,
///     ...,
///     add-LocationEstimate        [2] Add-GeographicalInformation OPTIONAL,
///     deferredmt-lrResponseIndicator [3] NULL OPTIONAL,
///     geranPositioningData        [4] PositioningDataInformation OPTIONAL,
///     utranPositioningData        [5] UtranPositioningDataInfo OPTIONAL,
///     cellIdOrSai                 [6] CellGlobalIdOrServiceAreaIdOrLAI OPTIONAL,
///     sai-Present                 [7] NULL OPTIONAL,
///     accuracyFulfilmentIndicator [8] AccuracyFulfilmentIndicator OPTIONAL,
///     velocityEstimate            [9] VelocityEstimate OPTIONAL,
///     mo-lrShortCircuitIndicator [10] NULL OPTIONAL,
///     geranGANSSpositioningData  [11] GANSSPositioningDataInfo OPTIONAL,
///     utranGANSSpositioningData  [12] GANSSPositioningDataInfo OPTIONAL,
///     targetServingNodeForHandover [13] ServingNodeAddress OPTIONAL,
///     utranAdditionalPositioningData [14] UtranAdditionalPositioningData OPTIONAL,
///     utranBaroPressureMeas      [15] UtranBarometricPressureMeasurement OPTIONAL }
/// ```
///
/// `cellIdOrSai` and `targetServingNodeForHandover` are CHOICEs, so `[6]` and
/// `[13]` are **explicit** tags.
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct ProvideSubscriberLocationRes {
    pub location_estimate: OctetString,
    #[rasn(tag(context, 0))]
    pub age_of_location_estimate: Option<Integer>,
    #[rasn(tag(context, 1))]
    pub extension_container: Option<ExtensionContainer>,
    #[rasn(tag(context, 2))]
    pub add_location_estimate: Option<OctetString>,
    #[rasn(tag(context, 3))]
    pub deferred_mt_lr_response_indicator: Option<()>,
    #[rasn(tag(context, 4))]
    pub geran_positioning_data: Option<OctetString>,
    #[rasn(tag(context, 5))]
    pub utran_positioning_data: Option<OctetString>,
    #[rasn(tag(explicit(context, 6)))]
    pub cell_id_or_sai: Option<Opaque>,
    #[rasn(tag(context, 7))]
    pub sai_present: Option<()>,
    #[rasn(tag(context, 8))]
    pub accuracy_fulfilment_indicator: Option<Integer>,
    #[rasn(tag(context, 9))]
    pub velocity_estimate: Option<OctetString>,
    #[rasn(tag(context, 10))]
    pub mo_lr_short_circuit_indicator: Option<()>,
    #[rasn(tag(context, 11))]
    pub geran_ganss_positioning_data: Option<OctetString>,
    #[rasn(tag(context, 12))]
    pub utran_ganss_positioning_data: Option<OctetString>,
    #[rasn(tag(explicit(context, 13)))]
    pub target_serving_node_for_handover: Option<Opaque>,
    #[rasn(tag(context, 14))]
    pub utran_additional_positioning_data: Option<OctetString>,
    #[rasn(tag(context, 15))]
    pub utran_baro_pressure_meas: Option<Integer>,
}

impl ProvideSubscriberLocationRes {
    /// The one mandatory member; every optional member starts `None`.
    pub fn new(location_estimate: OctetString) -> Self {
        Self {
            location_estimate,
            age_of_location_estimate: None,
            extension_container: None,
            add_location_estimate: None,
            deferred_mt_lr_response_indicator: None,
            geran_positioning_data: None,
            utran_positioning_data: None,
            cell_id_or_sai: None,
            sai_present: None,
            accuracy_fulfilment_indicator: None,
            velocity_estimate: None,
            mo_lr_short_circuit_indicator: None,
            geran_ganss_positioning_data: None,
            utran_ganss_positioning_data: None,
            target_serving_node_for_handover: None,
            utran_additional_positioning_data: None,
            utran_baro_pressure_meas: None,
        }
    }
}

/// SendRoutingInfoForLCS-Arg (op 85).
///
/// ```asn1
/// RoutingInfoForLCS-Arg ::= SEQUENCE {
///     mlcNumber           [0] ISDN-AddressString,
///     targetMS            [1] SubscriberIdentity,
///     extensionContainer  [2] ExtensionContainer OPTIONAL,
///     ... }
/// ```
///
/// `targetMS` is a CHOICE, so `[1]` is an **explicit** tag.
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct SendRoutingInfoForLcsArg {
    #[rasn(tag(context, 0))]
    pub mlc_number: IsdnAddressString,
    #[rasn(tag(explicit(context, 1)))]
    pub target_ms: SubscriberIdentityLcs,
    #[rasn(tag(context, 2))]
    pub extension_container: Option<ExtensionContainer>,
}

/// SendRoutingInfoForLCS-Res (op 85).
///
/// ```asn1
/// RoutingInfoForLCS-Res ::= SEQUENCE {
///     targetMS            [0] SubscriberIdentity,
///     lcsLocationInfo     [1] LCSLocationInfo,
///     extensionContainer  [2] ExtensionContainer OPTIONAL,
///     ...,
///     v-gmlc-Address      [3] GSN-Address OPTIONAL,
///     h-gmlc-Address      [4] GSN-Address OPTIONAL,
///     ppr-Address         [5] GSN-Address OPTIONAL,
///     additional-v-gmlc-Address [6] GSN-Address OPTIONAL }
/// ```
///
/// `targetMS` is a CHOICE, so `[0]` is an **explicit** tag.
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct SendRoutingInfoForLcsRes {
    #[rasn(tag(explicit(context, 0)))]
    pub target_ms: SubscriberIdentityLcs,
    #[rasn(tag(context, 1))]
    pub lcs_location_info: Opaque,
    #[rasn(tag(context, 2))]
    pub extension_container: Option<ExtensionContainer>,
    #[rasn(tag(context, 3))]
    pub v_gmlc_address: Option<OctetString>,
    #[rasn(tag(context, 4))]
    pub h_gmlc_address: Option<OctetString>,
    #[rasn(tag(context, 5))]
    pub ppr_address: Option<OctetString>,
    #[rasn(tag(context, 6))]
    pub additional_v_gmlc_address: Option<OctetString>,
}

/// SubscriberLocationReport-Arg (op 86).
///
/// ```asn1
/// SubscriberLocationReport-Arg ::= SEQUENCE {
///     lcs-Event                       LCS-Event,
///     lcs-ClientID                    LCS-ClientID,
///     lcsLocationInfo                 LCSLocationInfo,
///     msisdn                      [0] ISDN-AddressString OPTIONAL,
///     imsi                        [1] IMSI OPTIONAL,
///     imei                        [2] IMEI OPTIONAL,
///     na-ESRD                     [3] ISDN-AddressString OPTIONAL,
///     na-ESRK                     [4] ISDN-AddressString OPTIONAL,
///     locationEstimate            [5] Ext-GeographicalInformation OPTIONAL,
///     ageOfLocationEstimate       [6] AgeOfLocationInformation OPTIONAL,
///     slr-ArgExtensionContainer   [7] SLR-ArgExtensionContainer OPTIONAL,
///     ...,
///     add-LocationEstimate        [8] Add-GeographicalInformation OPTIONAL,
///     deferredmt-lrData           [9] Deferredmt-lrData OPTIONAL,
///     lcs-ReferenceNumber        [10] LCS-ReferenceNumber OPTIONAL,
///     geranPositioningData       [11] PositioningDataInformation OPTIONAL,
///     utranPositioningData       [12] UtranPositioningDataInfo OPTIONAL,
///     cellIdOrSai                [13] CellGlobalIdOrServiceAreaIdOrLAI OPTIONAL,
///     h-gmlc-Address             [14] GSN-Address OPTIONAL,
///     lcsServiceTypeID           [15] LCSServiceTypeID OPTIONAL,
///     sai-Present                [17] NULL OPTIONAL,
///     pseudonymIndicator         [18] NULL OPTIONAL,
///     accuracyFulfilmentIndicator [19] AccuracyFulfilmentIndicator OPTIONAL, ... }
/// ```
///
/// `cellIdOrSai` is a CHOICE, so `[13]` is an **explicit** tag.
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct SubscriberLocationReportArg {
    pub lcs_event: LcsEvent,
    pub lcs_client_id: LcsClientId,
    pub lcs_location_info: Opaque,
    #[rasn(tag(context, 0))]
    pub msisdn: Option<IsdnAddressString>,
    #[rasn(tag(context, 1))]
    pub imsi: Option<Imsi>,
    #[rasn(tag(context, 2))]
    pub imei: Option<OctetString>,
    #[rasn(tag(context, 3))]
    pub na_esrd: Option<IsdnAddressString>,
    #[rasn(tag(context, 4))]
    pub na_esrk: Option<IsdnAddressString>,
    #[rasn(tag(context, 5))]
    pub location_estimate: Option<OctetString>,
    #[rasn(tag(context, 6))]
    pub age_of_location_estimate: Option<Integer>,
    #[rasn(tag(context, 7))]
    pub slr_arg_extension_container: Option<Opaque>,
    #[rasn(tag(context, 8))]
    pub add_location_estimate: Option<OctetString>,
    #[rasn(tag(context, 9))]
    pub deferred_mt_lr_data: Option<Opaque>,
    #[rasn(tag(context, 10))]
    pub lcs_reference_number: Option<OctetString>,
    #[rasn(tag(context, 11))]
    pub geran_positioning_data: Option<OctetString>,
    #[rasn(tag(context, 12))]
    pub utran_positioning_data: Option<OctetString>,
    #[rasn(tag(explicit(context, 13)))]
    pub cell_id_or_sai: Option<Opaque>,
    #[rasn(tag(context, 14))]
    pub h_gmlc_address: Option<OctetString>,
    #[rasn(tag(context, 15))]
    pub lcs_service_type_id: Option<Integer>,
    #[rasn(tag(context, 17))]
    pub sai_present: Option<()>,
    #[rasn(tag(context, 18))]
    pub pseudonym_indicator: Option<()>,
    #[rasn(tag(context, 19))]
    pub accuracy_fulfilment_indicator: Option<Integer>,
}

/// SubscriberLocationReport-Res (op 86).
///
/// ```asn1
/// SubscriberLocationReport-Res ::= SEQUENCE {
///     extensionContainer          ExtensionContainer OPTIONAL,
///     ...,
///     na-ESRK                 [0] ISDN-AddressString OPTIONAL,
///     na-ESRD                 [1] ISDN-AddressString OPTIONAL,
///     h-gmlc-Address          [2] GSN-Address OPTIONAL,
///     mo-lrShortCircuitIndicator [3] NULL OPTIONAL,
///     reportingPLMNList       [4] ReportingPLMNList OPTIONAL,
///     lcs-ReferenceNumber     [5] LCS-ReferenceNumber OPTIONAL }
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct SubscriberLocationReportRes {
    pub extension_container: Option<ExtensionContainer>,
    #[rasn(tag(context, 0))]
    pub na_esrk: Option<IsdnAddressString>,
    #[rasn(tag(context, 1))]
    pub na_esrd: Option<IsdnAddressString>,
    #[rasn(tag(context, 2))]
    pub h_gmlc_address: Option<OctetString>,
    #[rasn(tag(context, 3))]
    pub mo_lr_short_circuit_indicator: Option<()>,
    #[rasn(tag(context, 4))]
    pub reporting_plmn_list: Option<Opaque>,
    #[rasn(tag(context, 5))]
    pub lcs_reference_number: Option<OctetString>,
}

/// Operation codes for LCS. Re-exported from [`crate::types::op_codes`].
pub mod op_codes {
    pub use crate::types::op_codes::{
        LCS_AREA_EVENT_CANCELLATION, LCS_AREA_EVENT_REPORT, LCS_AREA_EVENT_REQUEST,
        LCS_LOCATION_NOTIFICATION, LCS_LOCATION_UPDATE, LCS_MOLR,
        LCS_PERIODIC_LOCATION_CANCELLATION, LCS_PERIODIC_LOCATION_REQUEST,
        PROVIDE_SUBSCRIBER_LOCATION, SEND_ROUTING_INFO_FOR_LCS, SUBSCRIBER_LOCATION_REPORT,
    };
}

// ── Deferred and mobile-originated location (TS 29.002 clause 13) ───────────

/// LCS-PeriodicLocationCancellation-Arg (op 109). The operation has no result.
///
/// ```asn1
/// LCS-PeriodicLocationCancellationArg ::= SEQUENCE {
///     referenceNumber [0] LCS-ReferenceNumber,
///     h-gmlc-address  [1] GSN-Address OPTIONAL,
///     ... }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct LcsPeriodicLocationCancellationArg {
    #[rasn(tag(context, 0))]
    pub reference_number: OctetString,
    #[rasn(tag(context, 1))]
    pub h_gmlc_address: Option<OctetString>,
}

/// LCS-AreaEventCancellation-Arg (op 112). The operation has no result.
pub type LcsAreaEventCancellationArg = LcsPeriodicLocationCancellationArg;

/// LCS-AreaEventReport-Arg (op 113). The operation has no result.
pub type LcsAreaEventReportArg = LcsPeriodicLocationCancellationArg;

/// LCS-LocationUpdate-Arg (op 110).
///
/// ```asn1
/// LCS-LocationUpdateArg ::= SEQUENCE {
///     referenceNumber      [0] LCS-ReferenceNumber,
///     add-LocationEstimate [1] Add-GeographicalInformation OPTIONAL,
///     velocityEstimate     [2] VelocityEstimate OPTIONAL,
///     sequenceNumber       [3] SequenceNumber OPTIONAL,
///     ... }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct LcsLocationUpdateArg {
    #[rasn(tag(context, 0))]
    pub reference_number: OctetString,
    #[rasn(tag(context, 1))]
    pub add_location_estimate: Option<OctetString>,
    #[rasn(tag(context, 2))]
    pub velocity_estimate: Option<OctetString>,
    #[rasn(tag(context, 3))]
    pub sequence_number: Option<Integer>,
}

/// LCS-LocationUpdate-Res (op 110).
///
/// ```asn1
/// LCS-LocationUpdateRes ::= SEQUENCE {
///     terminationCause [0] TerminationCause OPTIONAL,
///     ... }
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct LcsLocationUpdateRes {
    /// `normal(0)`, `errorundefined(1)`, `internalTimeout(2)`,
    /// `congestion(3)`, `mt-lrRestart(4)`, `privacyViolation(5)`,
    /// `shapeOfLocationEstimateNotSupported(6)`, `subscriberTermination(7)`,
    /// `uETermination(8)`, `networkTermination(9)`.
    #[rasn(tag(context, 0))]
    pub termination_cause: Option<Integer>,
}

/// LCS-PeriodicLocationRequest-Arg (op 111).
///
/// ```asn1
/// LCS-PeriodicLocationRequestArg ::= SEQUENCE {
///     referenceNumber [0] LCS-ReferenceNumber,
///     periodicLDRInfo [1] PeriodicLDRInfo,
///     ... }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct LcsPeriodicLocationRequestArg {
    #[rasn(tag(context, 0))]
    pub reference_number: OctetString,
    #[rasn(tag(context, 1))]
    pub periodic_ldr_info: Opaque,
}

/// LCS-PeriodicLocationRequest-Res (op 111).
///
/// ```asn1
/// LCS-PeriodicLocationRequestRes ::= SEQUENCE {
///     mo-lrShortCircuit [0] NULL OPTIONAL,
///     ... }
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct LcsPeriodicLocationRequestRes {
    #[rasn(tag(context, 0))]
    pub mo_lr_short_circuit: Option<()>,
}

/// LCS-AreaEventRequest-Arg (op 114). The operation has no result.
///
/// ```asn1
/// LCS-AreaEventRequestArg ::= SEQUENCE {
///     referenceNumber           [0] LCS-ReferenceNumber,
///     h-gmlc-address            [1] GSN-Address OPTIONAL,
///     deferredLocationEventType [3] DeferredLocationEventType,
///     areaEventInfo             [4] AreaEventInfo,
///     ... }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct LcsAreaEventRequestArg {
    #[rasn(tag(context, 0))]
    pub reference_number: OctetString,
    #[rasn(tag(context, 1))]
    pub h_gmlc_address: Option<OctetString>,
    #[rasn(tag(context, 3))]
    pub deferred_location_event_type: Option<BitString>,
    #[rasn(tag(context, 4))]
    pub area_event_info: Option<Opaque>,
}

/// LCS-MOLR-Arg (op 115) — a mobile-originated location request.
///
/// ```asn1
/// LCS-MOLRArg ::= SEQUENCE {
///     molr-Type            [0] MOLR-Type,
///     locationMethod       [1] LocationMethod OPTIONAL,
///     lcs-QoS              [2] LCS-QoS OPTIONAL,
///     lcsClientExternalID  [3] LCSClientExternalID OPTIONAL,
///     mlc-Number           [4] ISDN-AddressString OPTIONAL,
///     gpsAssistanceData    [5] GPSAssistanceData OPTIONAL,
///     supportedGADShapes   [6] SupportedGADShapes OPTIONAL,
///     lcsServiceTypeID     [7] LCSServiceTypeID OPTIONAL,
///     ageOfLocationInfo    [8] AgeOfLocationInformation OPTIONAL,
///     locationType         [9] LocationType OPTIONAL,
///     pseudonymIndicator  [10] NULL OPTIONAL,
///     h-gmlc-address      [11] GSN-Address OPTIONAL,
///     locationEstimate    [12] Ext-GeographicalInformation OPTIONAL,
///     velocityEstimate    [13] VelocityEstimate OPTIONAL,
///     referenceNumber     [14] LCS-ReferenceNumber OPTIONAL,
///     periodicLDRInfo     [15] PeriodicLDRInfo OPTIONAL,
///     locationUpdateRequest [16] NULL OPTIONAL,
///     sequenceNumber      [17] SequenceNumber OPTIONAL,
///     terminationCause    [18] TerminationCause OPTIONAL,
///     mo-lrShortCircuit   [19] NULL OPTIONAL,
///     ... }
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct LcsMolrArg {
    /// `locationEstimate(0)`, `assistanceData(1)`, `deCipheringKeys(2)`.
    #[rasn(tag(context, 0))]
    pub molr_type: Option<Integer>,
    /// `msBased(0)`, `msAssisted(1)`, `msBasedPreferred(2)`, `msAssistedPreferred(3)`.
    #[rasn(tag(context, 1))]
    pub location_method: Option<Integer>,
    #[rasn(tag(context, 2))]
    pub lcs_qos: Option<Opaque>,
    #[rasn(tag(context, 3))]
    pub lcs_client_external_id: Option<Opaque>,
    #[rasn(tag(context, 4))]
    pub mlc_number: Option<IsdnAddressString>,
    #[rasn(tag(context, 5))]
    pub gps_assistance_data: Option<OctetString>,
    #[rasn(tag(context, 6))]
    pub supported_gad_shapes: Option<BitString>,
    #[rasn(tag(context, 7))]
    pub lcs_service_type_id: Option<Integer>,
    #[rasn(tag(context, 8))]
    pub age_of_location_info: Option<Integer>,
    #[rasn(tag(context, 9))]
    pub location_type: Option<Opaque>,
    #[rasn(tag(context, 10))]
    pub pseudonym_indicator: Option<()>,
    #[rasn(tag(context, 11))]
    pub h_gmlc_address: Option<OctetString>,
    #[rasn(tag(context, 12))]
    pub location_estimate: Option<OctetString>,
    #[rasn(tag(context, 13))]
    pub velocity_estimate: Option<OctetString>,
    #[rasn(tag(context, 14))]
    pub reference_number: Option<OctetString>,
    #[rasn(tag(context, 15))]
    pub periodic_ldr_info: Option<Opaque>,
    #[rasn(tag(context, 16))]
    pub location_update_request: Option<()>,
    #[rasn(tag(context, 17))]
    pub sequence_number: Option<Integer>,
    #[rasn(tag(context, 18))]
    pub termination_cause: Option<Integer>,
    #[rasn(tag(context, 19))]
    pub mo_lr_short_circuit: Option<()>,
}

/// LCS-MOLR-Res (op 115).
///
/// ```asn1
/// LCS-MOLRRes ::= SEQUENCE {
///     locationEstimate           [0] Ext-GeographicalInformation OPTIONAL,
///     decipheringKeys            [1] DecipheringKeys OPTIONAL,
///     add-LocationEstimate       [2] Add-GeographicalInformation OPTIONAL,
///     velocityEstimate           [3] VelocityEstimate OPTIONAL,
///     referenceNumber            [4] LCS-ReferenceNumber OPTIONAL,
///     h-gmlc-address             [5] GSN-Address OPTIONAL,
///     mo-lrShortCircuit          [6] NULL OPTIONAL,
///     reportingPLMNList          [7] ReportingPLMNList OPTIONAL,
///     timestampOfLocationEstimate [8] Time OPTIONAL,
///     ... }
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct LcsMolrRes {
    #[rasn(tag(context, 0))]
    pub location_estimate: Option<OctetString>,
    #[rasn(tag(context, 1))]
    pub deciphering_keys: Option<OctetString>,
    #[rasn(tag(context, 2))]
    pub add_location_estimate: Option<OctetString>,
    #[rasn(tag(context, 3))]
    pub velocity_estimate: Option<OctetString>,
    #[rasn(tag(context, 4))]
    pub reference_number: Option<OctetString>,
    #[rasn(tag(context, 5))]
    pub h_gmlc_address: Option<OctetString>,
    #[rasn(tag(context, 6))]
    pub mo_lr_short_circuit: Option<()>,
    #[rasn(tag(context, 7))]
    pub reporting_plmn_list: Option<Opaque>,
    #[rasn(tag(context, 8))]
    pub timestamp_of_location_estimate: Option<OctetString>,
}

/// LCS-LocationNotification-Arg (op 116) — ask the subscriber to verify a
/// location request.
///
/// ```asn1
/// LCS-LocationNotificationArg ::= SEQUENCE {
///     notificationType [0] NotificationToMSUser,
///     locationType     [1] LocationType,
///     ... }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct LcsLocationNotificationArg {
    /// `notifyLocationAllowed(0)`, `notifyAndVerify-LocationAllowedIfNoResponse(1)`,
    /// `notifyAndVerify-LocationNotAllowedIfNoResponse(2)`,
    /// `locationNotAllowed(3)`.
    #[rasn(tag(context, 0))]
    pub notification_type: Option<Integer>,
    #[rasn(tag(context, 1))]
    pub location_type: Option<Opaque>,
}

/// LCS-LocationNotification-Res (op 116).
///
/// ```asn1
/// LCS-LocationNotificationRes ::= SEQUENCE {
///     verificationResponse      [0] VerificationResponse OPTIONAL,
///     locationPrivacyIndication [1] LocationPrivacyIndication OPTIONAL,
///     validTimePeriod           [2] ValidTimePeriod OPTIONAL,
///     ... }
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct LcsLocationNotificationRes {
    /// `permissionDenied(0)`, `permissionGranted(1)`.
    #[rasn(tag(context, 0))]
    pub verification_response: Option<Integer>,
    #[rasn(tag(context, 1))]
    pub location_privacy_indication: Option<Integer>,
    #[rasn(tag(context, 2))]
    pub valid_time_period: Option<Opaque>,
}
