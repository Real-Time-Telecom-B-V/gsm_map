//! reportSM-DeliveryStatus (operation code 47) — 3GPP TS 29.002.
//!
//! The SMS-GMSC reports the outcome of an MT delivery attempt to the HLR, which
//! sets or clears the message-waiting flags accordingly. An IP-SM-GW reports the
//! IMS-leg outcome through the `ip-sm-gw-*` members, distinctly from the CS one.
//!
//! Every member TS 29.002 defines is modelled; see [`crate`] on why an
//! unmodelled member is fatal rather than merely absent.

use rasn::prelude::*;

use crate::types::{
    AbsentSubscriberDiagnosticSm, AddressString, CorrelationId, ExtensionContainer, Imsi,
    IsdnAddressString,
};

/// SM-DeliveryOutcome values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, AsnType, Decode, Encode)]
#[rasn(enumerated)]
pub enum SmDeliveryOutcome {
    MemoryCapacityExceeded = 0,
    AbsentSubscriber = 1,
    SuccessfulTransfer = 2,
}

/// ReportSM-DeliveryStatusArg — request parameters.
///
/// ```asn1
/// ReportSM-DeliveryStatusArg ::= SEQUENCE {
///     msisdn                                      ISDN-AddressString,
///     serviceCentreAddress                        AddressString,
///     sm-DeliveryOutcome                          SM-DeliveryOutcome,
///     absentSubscriberDiagnosticSM            [0] AbsentSubscriberDiagnosticSM OPTIONAL,
///     extensionContainer                      [1] ExtensionContainer OPTIONAL,
///     ...,
///     gprsSupportIndicator                    [2] NULL OPTIONAL,
///     deliveryOutcomeIndicator                [3] NULL OPTIONAL,
///     additionalSM-DeliveryOutcome            [4] SM-DeliveryOutcome OPTIONAL,
///     additionalAbsentSubscriberDiagnosticSM  [5] AbsentSubscriberDiagnosticSM OPTIONAL,
///     ip-sm-gw-Indicator                      [6] NULL OPTIONAL,
///     ip-sm-gw-sm-deliveryOutcome             [7] SM-DeliveryOutcome OPTIONAL,
///     ip-sm-gw-absentSubscriberDiagnosticSM   [8] AbsentSubscriberDiagnosticSM OPTIONAL,
///     imsi                                    [9] IMSI OPTIONAL,
///     singleAttemptDelivery                  [10] NULL OPTIONAL,
///     correlationID                          [11] CorrelationID OPTIONAL,
///     smsf-3gpp-deliveryOutcomeIndicator     [12] NULL OPTIONAL,
///     smsf-3gpp-deliveryOutcome              [13] SM-DeliveryOutcome OPTIONAL,
///     smsf-3gpp-absentSubscriberDiagSM       [14] AbsentSubscriberDiagnosticSM OPTIONAL,
///     smsf-non-3gpp-deliveryOutcomeIndicator [15] NULL OPTIONAL,
///     smsf-non-3gpp-deliveryOutcome          [16] SM-DeliveryOutcome OPTIONAL,
///     smsf-non-3gpp-absentSubscriberDiagSM   [17] AbsentSubscriberDiagnosticSM OPTIONAL }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct ReportSmDeliveryStatusArg {
    /// MSISDN of the SMS recipient.
    pub msisdn: IsdnAddressString,
    /// Address of the service centre.
    pub service_centre_address: AddressString,
    /// Delivery outcome over the CS/PS leg.
    pub sm_delivery_outcome: SmDeliveryOutcome,
    #[rasn(tag(context, 0))]
    pub absent_subscriber_diagnostic_sm: Option<AbsentSubscriberDiagnosticSm>,
    #[rasn(tag(context, 1))]
    pub extension_container: Option<ExtensionContainer>,
    #[rasn(tag(context, 2))]
    pub gprs_support_indicator: Option<()>,
    /// The outcome members that follow are meaningful (they may legitimately be
    /// absent, which is different from "not reported").
    #[rasn(tag(context, 3))]
    pub delivery_outcome_indicator: Option<()>,
    #[rasn(tag(context, 4))]
    pub additional_sm_delivery_outcome: Option<SmDeliveryOutcome>,
    #[rasn(tag(context, 5))]
    pub additional_absent_subscriber_diagnostic_sm: Option<AbsentSubscriberDiagnosticSm>,
    /// This report comes from an IP-SM-GW.
    #[rasn(tag(context, 6))]
    pub ip_sm_gw_indicator: Option<()>,
    /// Outcome of the IMS leg, reported distinctly from the CS one.
    #[rasn(tag(context, 7))]
    pub ip_sm_gw_sm_delivery_outcome: Option<SmDeliveryOutcome>,
    #[rasn(tag(context, 8))]
    pub ip_sm_gw_absent_subscriber_diagnostic_sm: Option<AbsentSubscriberDiagnosticSm>,
    #[rasn(tag(context, 9))]
    pub imsi: Option<Imsi>,
    #[rasn(tag(context, 10))]
    pub single_attempt_delivery: Option<()>,
    #[rasn(tag(context, 11))]
    pub correlation_id: Option<CorrelationId>,
    #[rasn(tag(context, 12))]
    pub smsf_3gpp_delivery_outcome_indicator: Option<()>,
    #[rasn(tag(context, 13))]
    pub smsf_3gpp_delivery_outcome: Option<SmDeliveryOutcome>,
    #[rasn(tag(context, 14))]
    pub smsf_3gpp_absent_subscriber_diag_sm: Option<AbsentSubscriberDiagnosticSm>,
    #[rasn(tag(context, 15))]
    pub smsf_non_3gpp_delivery_outcome_indicator: Option<()>,
    #[rasn(tag(context, 16))]
    pub smsf_non_3gpp_delivery_outcome: Option<SmDeliveryOutcome>,
    #[rasn(tag(context, 17))]
    pub smsf_non_3gpp_absent_subscriber_diag_sm: Option<AbsentSubscriberDiagnosticSm>,
}

impl ReportSmDeliveryStatusArg {
    /// The three mandatory members; every optional member starts `None`.
    pub fn new(
        msisdn: IsdnAddressString,
        service_centre_address: AddressString,
        sm_delivery_outcome: SmDeliveryOutcome,
    ) -> Self {
        Self {
            msisdn,
            service_centre_address,
            sm_delivery_outcome,
            absent_subscriber_diagnostic_sm: None,
            extension_container: None,
            gprs_support_indicator: None,
            delivery_outcome_indicator: None,
            additional_sm_delivery_outcome: None,
            additional_absent_subscriber_diagnostic_sm: None,
            ip_sm_gw_indicator: None,
            ip_sm_gw_sm_delivery_outcome: None,
            ip_sm_gw_absent_subscriber_diagnostic_sm: None,
            imsi: None,
            single_attempt_delivery: None,
            correlation_id: None,
            smsf_3gpp_delivery_outcome_indicator: None,
            smsf_3gpp_delivery_outcome: None,
            smsf_3gpp_absent_subscriber_diag_sm: None,
            smsf_non_3gpp_delivery_outcome_indicator: None,
            smsf_non_3gpp_delivery_outcome: None,
            smsf_non_3gpp_absent_subscriber_diag_sm: None,
        }
    }
}

/// ReportSM-DeliveryStatusRes — response parameters.
///
/// ```asn1
/// ReportSM-DeliveryStatusRes ::= SEQUENCE {
///     storedMSISDN        ISDN-AddressString OPTIONAL,
///     extensionContainer  ExtensionContainer OPTIONAL,
///     ... }
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct ReportSmDeliveryStatusRes {
    /// Stored MSISDN (if different from the request).
    pub stored_msisdn: Option<IsdnAddressString>,
    pub extension_container: Option<ExtensionContainer>,
}
