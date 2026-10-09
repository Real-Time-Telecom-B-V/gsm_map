//! sendRoutingInfoForSM (operation code 45) — 3GPP TS 29.002.
//!
//! Used by the SMS-GMSC to query the HLR for the IMSI and serving MSC/SGSN
//! address of the SMS recipient.
//!
//! Both types model **every** member TS 29.002 (Rel-18) defines, including the
//! ones this crate has no use for; members it does not interpret are carried
//! opaquely. Decode with [`crate::decode`]: a serving node that is on the wire
//! and cannot be read is then an error rather than a shorter answer, and a
//! member from a later release is skipped and reported.

use rasn::prelude::*;

use crate::types::{
    AddressString, ExtensionContainer, Imsi, IsdnAddressString, LocationInfoWithLmsi,
};

/// CorrelationID — shared with the ForwardSM / reportSM-DeliveryStatus /
/// alertServiceCentre arguments, so it lives in [`crate::types`].
pub use crate::types::CorrelationId;

crate::types::extensible_enumerated! {
    /// SM-DeliveryNotIntended — the GMSC only wants routing data, not a delivery.
    ///
    /// ```asn1
    /// SM-DeliveryNotIntended ::= ENUMERATED {
    ///     onlyIMSI-requested    (0),
    ///     onlyMCC-MNC-requested (1),
    ///     ... }
    /// ```
    ///
    /// Extensible, and TS 29.002 gives no exception handling for it: a value a
    /// later release adds arrives as `Unrecognised` and the receiver decides.
    pub enum SmDeliveryNotIntended {
        OnlyImsiRequested = 0,
        OnlyMccMncRequested = 1,
    }
}

/// IP-SM-GW-Guidance — delivery-timer guidance from an IP-SM-GW-served HLR.
///
/// ```asn1
/// IP-SM-GW-Guidance ::= SEQUENCE {
///     minimumDeliveryTimeValue      SM-DeliveryTimerValue,
///     recommendedDeliveryTimeValue  SM-DeliveryTimerValue,
///     extensionContainer            ExtensionContainer OPTIONAL,
///     ... }
///
/// SM-DeliveryTimerValue ::= INTEGER (30..600)
/// ```
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct IpSmGwGuidance {
    pub minimum_delivery_time_value: Integer,
    pub recommended_delivery_time_value: Integer,
    pub extension_container: Option<ExtensionContainer>,
}

/// RoutingInfoForSM-Arg — request parameters.
///
/// ```asn1
/// RoutingInfoForSM-Arg ::= SEQUENCE {
///     msisdn                     [0] ISDN-AddressString,
///     sm-RP-PRI                  [1] BOOLEAN,
///     serviceCentreAddress       [2] AddressString,
///     extensionContainer         [6] ExtensionContainer OPTIONAL,
///     ...,
///     gprsSupportIndicator       [7] NULL OPTIONAL,
///     sm-RP-MTI                  [8] SM-RP-MTI OPTIONAL,
///     sm-RP-SMEA                 [9] SM-RP-SMEA OPTIONAL,
///     sm-deliveryNotIntended    [10] SM-DeliveryNotIntended OPTIONAL,
///     ip-sm-gwGuidanceIndicator [11] NULL OPTIONAL,
///     imsi                      [12] IMSI OPTIONAL,
///     t4-Trigger-Indicator      [14] NULL OPTIONAL,
///     singleAttemptDelivery     [13] NULL OPTIONAL,
///     correlationID             [15] CorrelationID OPTIONAL,
///     smsf-supportIndicator     [16] NULL OPTIONAL }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct RoutingInfoForSmArg {
    #[rasn(tag(context, 0))]
    pub msisdn: IsdnAddressString,
    #[rasn(tag(context, 1))]
    pub sm_rp_pri: bool,
    #[rasn(tag(context, 2))]
    pub service_centre_address: AddressString,
    #[rasn(tag(context, 6))]
    pub extension_container: Option<ExtensionContainer>,
    #[rasn(tag(context, 7))]
    pub gprs_support_indicator: Option<()>,
    #[rasn(tag(context, 8))]
    pub sm_rp_mti: Option<Integer>,
    #[rasn(tag(context, 9))]
    pub sm_rp_smea: Option<OctetString>,
    #[rasn(tag(context, 10))]
    pub sm_delivery_not_intended: Option<SmDeliveryNotIntended>,
    #[rasn(tag(context, 11))]
    pub ip_sm_gw_guidance_indicator: Option<()>,
    #[rasn(tag(context, 12))]
    pub imsi: Option<Imsi>,
    #[rasn(tag(context, 14))]
    pub t4_trigger_indicator: Option<()>,
    #[rasn(tag(context, 13))]
    pub single_attempt_delivery: Option<()>,
    #[rasn(tag(context, 15))]
    pub correlation_id: Option<CorrelationId>,
    #[rasn(tag(context, 16))]
    pub smsf_support_indicator: Option<()>,
}

/// RoutingInfoForSM-Res — response parameters.
///
/// ```asn1
/// RoutingInfoForSM-Res ::= SEQUENCE {
///     imsi                  IMSI,
///     locationInfoWithLMSI  [0] LocationInfoWithLMSI,
///     extensionContainer    [4] ExtensionContainer OPTIONAL,
///     ...,
///     ip-sm-gwGuidance      [5] IP-SM-GW-Guidance OPTIONAL }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct RoutingInfoForSmRes {
    pub imsi: Imsi,
    #[rasn(tag(context, 0))]
    pub location_info_with_lmsi: LocationInfoWithLmsi,
    #[rasn(tag(context, 4))]
    pub extension_container: Option<ExtensionContainer>,
    #[rasn(tag(context, 5))]
    pub ip_sm_gw_guidance: Option<IpSmGwGuidance>,
}

impl RoutingInfoForSmArg {
    /// The three mandatory members; every optional member starts `None`.
    ///
    /// Use functional-record-update for the rest:
    /// `RoutingInfoForSmArg { sm_rp_mti: Some(0.into()), ..RoutingInfoForSmArg::new(..) }`.
    pub fn new(
        msisdn: IsdnAddressString,
        sm_rp_pri: bool,
        service_centre_address: AddressString,
    ) -> Self {
        Self {
            msisdn,
            sm_rp_pri,
            service_centre_address,
            extension_container: None,
            gprs_support_indicator: None,
            sm_rp_mti: None,
            sm_rp_smea: None,
            sm_delivery_not_intended: None,
            ip_sm_gw_guidance_indicator: None,
            imsi: None,
            t4_trigger_indicator: None,
            single_attempt_delivery: None,
            correlation_id: None,
            smsf_support_indicator: None,
        }
    }
}

impl RoutingInfoForSmRes {
    /// The two mandatory members; every optional member starts `None`.
    pub fn new(imsi: Imsi, location_info_with_lmsi: LocationInfoWithLmsi) -> Self {
        Self {
            imsi,
            location_info_with_lmsi,
            extension_container: None,
            ip_sm_gw_guidance: None,
        }
    }
}
