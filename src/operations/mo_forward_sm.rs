//! mo-ForwardSM (operation code 46) — 3GPP TS 29.002.
//!
//! Mobile-originated SMS forwarding from the MSC to the SMS-IWMSC/SMS-SC.
//!
//! Every member TS 29.002 defines is modelled; see [`crate`] on why an
//! unmodelled member is fatal rather than merely absent.

use rasn::prelude::*;

use crate::operations::report_sm::SmDeliveryOutcome;
use crate::types::{CorrelationId, ExtensionContainer, Imsi, SignalInfo, SmRpDa, SmRpOa};

/// MO-ForwardSM-Arg — request parameters.
///
/// ```asn1
/// MO-ForwardSM-Arg ::= SEQUENCE {
///     sm-RP-DA                SM-RP-DA,
///     sm-RP-OA                SM-RP-OA,
///     sm-RP-UI                SignalInfo,
///     extensionContainer      ExtensionContainer OPTIONAL,
///     ...,
///     imsi                    IMSI OPTIONAL,
///     correlationID       [0] CorrelationID OPTIONAL,
///     sm-DeliveryOutcome  [1] SM-DeliveryOutcome OPTIONAL }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct MoForwardSmArg {
    /// Destination address (usually the service centre address).
    pub sm_rp_da: SmRpDa,
    /// Originating address (MSISDN of the sender).
    pub sm_rp_oa: SmRpOa,
    /// SM-RP-UI (User Information — the SMS-SUBMIT TPDU).
    pub sm_rp_ui: SignalInfo,
    pub extension_container: Option<ExtensionContainer>,
    /// IMSI of the sender.
    pub imsi: Option<Imsi>,
    #[rasn(tag(context, 0))]
    pub correlation_id: Option<CorrelationId>,
    #[rasn(tag(context, 1))]
    pub sm_delivery_outcome: Option<SmDeliveryOutcome>,
}

impl MoForwardSmArg {
    /// The three mandatory members; every optional member starts `None`.
    pub fn new(sm_rp_da: SmRpDa, sm_rp_oa: SmRpOa, sm_rp_ui: SignalInfo) -> Self {
        Self {
            sm_rp_da,
            sm_rp_oa,
            sm_rp_ui,
            extension_container: None,
            imsi: None,
            correlation_id: None,
            sm_delivery_outcome: None,
        }
    }
}

/// MO-ForwardSM-Res — response parameters.
///
/// ```asn1
/// MO-ForwardSM-Res ::= SEQUENCE {
///     sm-RP-UI            SignalInfo OPTIONAL,
///     extensionContainer  ExtensionContainer OPTIONAL,
///     ... }
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct MoForwardSmRes {
    /// SM-RP-UI (User Information — the SMS-SUBMIT-REPORT TPDU).
    pub sm_rp_ui: Option<SignalInfo>,
    pub extension_container: Option<ExtensionContainer>,
}
