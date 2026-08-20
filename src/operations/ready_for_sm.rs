//! readyForSM (operation code 66) — 3GPP TS 29.002.
//!
//! The serving node tells the HLR a subscriber became reachable or freed memory,
//! which is what makes the HLR alert the queued service centres. This is the MAP
//! form of Alert-SC, so a store-and-forward gateway's queue drain depends on it.
//!
//! Every member TS 29.002 defines is modelled; see [`crate`] on why an
//! unmodelled member is fatal rather than merely absent.

use rasn::prelude::*;

use crate::types::{ExtensionContainer, Imsi, Time};

/// AlertReason — why the subscriber is now reachable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, AsnType, Decode, Encode)]
#[rasn(enumerated)]
pub enum AlertReason {
    MsPresent = 0,
    MemoryAvailable = 1,
}

/// ReadyForSM-Arg — request parameters.
///
/// ```asn1
/// ReadyForSM-Arg ::= SEQUENCE {
///     imsi                          [0] IMSI,
///     alertReason                       AlertReason,
///     alertReasonIndicator              NULL OPTIONAL,
///     extensionContainer                ExtensionContainer OPTIONAL,
///     ...,
///     additionalAlertReasonIndicator [1] NULL OPTIONAL,
///     maximumUeAvailabilityTime          Time OPTIONAL }
/// ```
///
/// `imsi` carries the context `[0]` tag; TS 29.002's modules are `IMPLICIT
/// TAGS`, so it encodes as `0x80`, not as a universal OCTET STRING `0x04`.
/// `alertReason` is untagged in the ASN.1 and stays untagged here.
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct ReadyForSmArg {
    /// IMSI of the now-reachable subscriber.
    #[rasn(tag(context, 0))]
    pub imsi: Imsi,
    /// Reason for the alert.
    pub alert_reason: AlertReason,
    /// The alert applies to the non-3GPP (untrusted) access as well.
    pub alert_reason_indicator: Option<()>,
    pub extension_container: Option<ExtensionContainer>,
    #[rasn(tag(context, 1))]
    pub additional_alert_reason_indicator: Option<()>,
    /// How long the UE is expected to stay reachable.
    pub maximum_ue_availability_time: Option<Time>,
}

impl ReadyForSmArg {
    /// The two mandatory members; every optional member starts `None`.
    pub fn new(imsi: Imsi, alert_reason: AlertReason) -> Self {
        Self {
            imsi,
            alert_reason,
            alert_reason_indicator: None,
            extension_container: None,
            additional_alert_reason_indicator: None,
            maximum_ue_availability_time: None,
        }
    }
}

/// ReadyForSM-Res — response parameters.
///
/// ```asn1
/// ReadyForSM-Res ::= SEQUENCE {
///     extensionContainer  ExtensionContainer OPTIONAL,
///     ... }
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct ReadyForSmRes {
    pub extension_container: Option<ExtensionContainer>,
}
