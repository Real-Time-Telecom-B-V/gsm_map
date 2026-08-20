//! GPRS Location Management operations — 3GPP TS 29.002.
//!
//! - updateGprsLocation (op 23)
//! - sendRoutingInfoForGprs (op 24)
//! - failureReport (op 25)
//! - noteMsPresentForGprs (op 26)
//!
//! Every member TS 29.002 defines is modelled; see [`crate`] on why an
//! unmodelled member is fatal rather than merely absent.

use rasn::prelude::*;

use crate::types::{ExtensionContainer, Imsi, IsdnAddressString, Opaque};

pub use crate::operations::location::GsnAddress;

/// UpdateGprsLocation-Arg (op 23).
///
/// ```asn1
/// UpdateGprsLocationArg ::= SEQUENCE {
///     imsi                             IMSI,
///     sgsn-Number                      ISDN-AddressString,
///     sgsn-Address                     GSN-Address,
///     extensionContainer               ExtensionContainer OPTIONAL,
///     ...,
///     sgsn-Capability              [0] SGSN-Capability OPTIONAL,
///     informPreviousNetworkEntity  [1] NULL OPTIONAL,
///     ps-LCS-NotSupportedByUE      [2] NULL OPTIONAL,
///     v-gmlc-Address               [3] GSN-Address OPTIONAL,
///     add-info                     [4] ADD-Info OPTIONAL,
///     eps-info                     [5] EPS-Info OPTIONAL,
///     servingNodeTypeIndicator     [6] NULL OPTIONAL,
///     skipSubscriberDataUpdate     [7] NULL OPTIONAL,
///     usedRAT-Type                 [8] Used-RAT-Type OPTIONAL,
///     gprsSubscriptionDataNotNeeded [9] NULL OPTIONAL,
///     nodeTypeIndicator           [10] NULL OPTIONAL,
///     areaRestricted              [11] NULL OPTIONAL,
///     ue-reachableIndicator       [12] NULL OPTIONAL,
///     epsSubscriptionDataNotNeeded [13] NULL OPTIONAL,
///     ue-srvcc-Capability         [14] UE-SRVCC-Capability OPTIONAL,
///     eplmn-List                  [15] EPLMN-List OPTIONAL,
///     mmeNumberforMTSMS           [16] ISDN-AddressString OPTIONAL,
///     smsRegisterRequest          [17] SMSRegisterRequest OPTIONAL,
///     sms-Only                    [18] NULL OPTIONAL,
///     removalofMMERegistrationforSMS [22] NULL OPTIONAL,
///     sgsn-Name                   [19] DiameterIdentity OPTIONAL,
///     sgsn-Realm                  [20] DiameterIdentity OPTIONAL,
///     lgd-supportIndicator        [21] NULL OPTIONAL,
///     adjacentPLMN-List           [23] AdjacentPLMN-List OPTIONAL }
/// ```
///
/// `eps-info` is a CHOICE, so `[5]` is an **explicit** tag.
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct UpdateGprsLocationArg {
    pub imsi: Imsi,
    pub sgsn_number: IsdnAddressString,
    pub sgsn_address: GsnAddress,
    pub extension_container: Option<ExtensionContainer>,
    #[rasn(tag(context, 0))]
    pub sgsn_capability: Option<Opaque>,
    #[rasn(tag(context, 1))]
    pub inform_previous_network_entity: Option<()>,
    #[rasn(tag(context, 2))]
    pub ps_lcs_not_supported_by_ue: Option<()>,
    #[rasn(tag(context, 3))]
    pub v_gmlc_address: Option<GsnAddress>,
    #[rasn(tag(context, 4))]
    pub add_info: Option<Opaque>,
    #[rasn(tag(explicit(context, 5)))]
    pub eps_info: Option<Opaque>,
    #[rasn(tag(context, 6))]
    pub serving_node_type_indicator: Option<()>,
    #[rasn(tag(context, 7))]
    pub skip_subscriber_data_update: Option<()>,
    /// `Used-RAT-Type ::= ENUMERATED { utran(0), geran(1), gan(2),
    /// i-hspa-evolution(3), e-utran(4), nb-iot(5), ... }`.
    #[rasn(tag(context, 8))]
    pub used_rat_type: Option<Integer>,
    #[rasn(tag(context, 9))]
    pub gprs_subscription_data_not_needed: Option<()>,
    #[rasn(tag(context, 10))]
    pub node_type_indicator: Option<()>,
    #[rasn(tag(context, 11))]
    pub area_restricted: Option<()>,
    #[rasn(tag(context, 12))]
    pub ue_reachable_indicator: Option<()>,
    #[rasn(tag(context, 13))]
    pub eps_subscription_data_not_needed: Option<()>,
    #[rasn(tag(context, 14))]
    pub ue_srvcc_capability: Option<Integer>,
    #[rasn(tag(context, 15))]
    pub eplmn_list: Option<Opaque>,
    #[rasn(tag(context, 16))]
    pub mme_number_for_mt_sms: Option<IsdnAddressString>,
    #[rasn(tag(context, 17))]
    pub sms_register_request: Option<Integer>,
    #[rasn(tag(context, 18))]
    pub sms_only: Option<()>,
    /// Declared before `sgsn-Name` in the ASN.1, and BER encodes in declaration
    /// order, so `[22]` goes on the wire ahead of `[19]`.
    #[rasn(tag(context, 22))]
    pub removal_of_mme_registration_for_sms: Option<()>,
    #[rasn(tag(context, 19))]
    pub sgsn_name: Option<OctetString>,
    #[rasn(tag(context, 20))]
    pub sgsn_realm: Option<OctetString>,
    #[rasn(tag(context, 21))]
    pub lgd_support_indicator: Option<()>,
    #[rasn(tag(context, 23))]
    pub adjacent_plmn_list: Option<Opaque>,
}

impl UpdateGprsLocationArg {
    /// The three mandatory members; every optional member starts `None`.
    pub fn new(imsi: Imsi, sgsn_number: IsdnAddressString, sgsn_address: GsnAddress) -> Self {
        Self {
            imsi,
            sgsn_number,
            sgsn_address,
            extension_container: None,
            sgsn_capability: None,
            inform_previous_network_entity: None,
            ps_lcs_not_supported_by_ue: None,
            v_gmlc_address: None,
            add_info: None,
            eps_info: None,
            serving_node_type_indicator: None,
            skip_subscriber_data_update: None,
            used_rat_type: None,
            gprs_subscription_data_not_needed: None,
            node_type_indicator: None,
            area_restricted: None,
            ue_reachable_indicator: None,
            eps_subscription_data_not_needed: None,
            ue_srvcc_capability: None,
            eplmn_list: None,
            mme_number_for_mt_sms: None,
            sms_register_request: None,
            sms_only: None,
            removal_of_mme_registration_for_sms: None,
            sgsn_name: None,
            sgsn_realm: None,
            lgd_support_indicator: None,
            adjacent_plmn_list: None,
        }
    }
}

/// UpdateGprsLocation-Res (op 23).
///
/// ```asn1
/// UpdateGprsLocationRes ::= SEQUENCE {
///     hlr-Number                      ISDN-AddressString,
///     extensionContainer              ExtensionContainer OPTIONAL,
///     ...,
///     add-Capability                  NULL OPTIONAL,
///     sgsn-mmeSeparationSupported [0] NULL OPTIONAL,
///     mmeRegisteredforSMS         [1] NULL OPTIONAL }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct UpdateGprsLocationRes {
    pub hlr_number: IsdnAddressString,
    pub extension_container: Option<ExtensionContainer>,
    pub add_capability: Option<()>,
    #[rasn(tag(context, 0))]
    pub sgsn_mme_separation_supported: Option<()>,
    #[rasn(tag(context, 1))]
    pub mme_registered_for_sms: Option<()>,
}

impl UpdateGprsLocationRes {
    /// The one mandatory member; every optional member starts `None`.
    pub fn new(hlr_number: IsdnAddressString) -> Self {
        Self {
            hlr_number,
            extension_container: None,
            add_capability: None,
            sgsn_mme_separation_supported: None,
            mme_registered_for_sms: None,
        }
    }
}

/// SendRoutingInfoForGprs-Arg (op 24).
///
/// ```asn1
/// SendRoutingInfoForGprsArg ::= SEQUENCE {
///     imsi                [0] IMSI,
///     ggsn-Address        [1] GSN-Address OPTIONAL,
///     ggsn-Number         [2] ISDN-AddressString,
///     extensionContainer  [3] ExtensionContainer OPTIONAL,
///     ... }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct SendRoutingInfoForGprsArg {
    #[rasn(tag(context, 0))]
    pub imsi: Imsi,
    #[rasn(tag(context, 1))]
    pub ggsn_address: Option<GsnAddress>,
    #[rasn(tag(context, 2))]
    pub ggsn_number: IsdnAddressString,
    #[rasn(tag(context, 3))]
    pub extension_container: Option<ExtensionContainer>,
}

/// SendRoutingInfoForGprs-Res (op 24).
///
/// ```asn1
/// SendRoutingInfoForGprsRes ::= SEQUENCE {
///     sgsn-Address                [0] GSN-Address,
///     ggsn-Address                [1] GSN-Address OPTIONAL,
///     mobileNotReachableReason    [2] AbsentSubscriberDiagnosticSM OPTIONAL,
///     extensionContainer          [3] ExtensionContainer OPTIONAL,
///     ... }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct SendRoutingInfoForGprsRes {
    #[rasn(tag(context, 0))]
    pub sgsn_address: GsnAddress,
    #[rasn(tag(context, 1))]
    pub ggsn_address: Option<GsnAddress>,
    #[rasn(tag(context, 2))]
    pub mobile_not_reachable_reason: Option<Integer>,
    #[rasn(tag(context, 3))]
    pub extension_container: Option<ExtensionContainer>,
}

/// FailureReport-Arg (op 25).
///
/// ```asn1
/// FailureReportArg ::= SEQUENCE {
///     imsi                [0] IMSI,
///     ggsn-Number         [1] ISDN-AddressString,
///     ggsn-Address        [2] GSN-Address OPTIONAL,
///     extensionContainer  [3] ExtensionContainer OPTIONAL,
///     ... }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct FailureReportArg {
    #[rasn(tag(context, 0))]
    pub imsi: Imsi,
    #[rasn(tag(context, 1))]
    pub ggsn_number: IsdnAddressString,
    #[rasn(tag(context, 2))]
    pub ggsn_address: Option<GsnAddress>,
    #[rasn(tag(context, 3))]
    pub extension_container: Option<ExtensionContainer>,
}

/// FailureReport-Res (op 25).
///
/// ```asn1
/// FailureReportRes ::= SEQUENCE {
///     ggsn-Address        [0] GSN-Address OPTIONAL,
///     extensionContainer  [1] ExtensionContainer OPTIONAL,
///     ... }
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct FailureReportRes {
    #[rasn(tag(context, 0))]
    pub ggsn_address: Option<GsnAddress>,
    #[rasn(tag(context, 1))]
    pub extension_container: Option<ExtensionContainer>,
}

/// NoteMsPresentForGprs-Arg (op 26).
///
/// ```asn1
/// NoteMsPresentForGprsArg ::= SEQUENCE {
///     imsi                [0] IMSI,
///     sgsn-Address        [1] GSN-Address,
///     ggsn-Address        [2] GSN-Address OPTIONAL,
///     extensionContainer  [3] ExtensionContainer OPTIONAL,
///     ... }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct NoteMsPresentForGprsArg {
    #[rasn(tag(context, 0))]
    pub imsi: Imsi,
    #[rasn(tag(context, 1))]
    pub sgsn_address: GsnAddress,
    #[rasn(tag(context, 2))]
    pub ggsn_address: Option<GsnAddress>,
    #[rasn(tag(context, 3))]
    pub extension_container: Option<ExtensionContainer>,
}

/// NoteMsPresentForGprs-Res (op 26).
///
/// ```asn1
/// NoteMsPresentForGprsRes ::= SEQUENCE {
///     extensionContainer  [0] ExtensionContainer OPTIONAL,
///     ... }
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct NoteMsPresentForGprsRes {
    #[rasn(tag(context, 0))]
    pub extension_container: Option<ExtensionContainer>,
}

/// Operation codes for GPRS location management. Re-exported from
/// [`crate::types::op_codes`].
pub mod op_codes {
    pub use crate::types::op_codes::{
        FAILURE_REPORT, NOTE_MS_PRESENT_FOR_GPRS, SEND_ROUTING_INFO_FOR_GPRS, UPDATE_GPRS_LOCATION,
    };
}
