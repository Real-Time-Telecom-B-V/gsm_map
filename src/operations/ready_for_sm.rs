//! readyForSM (operation code 66) — 3GPP TS 29.002.
//!
//! Sent by the MSC/SGSN to the HLR to indicate that a subscriber
//! is now reachable and can receive SMS.

use rasn::prelude::*;

use crate::types::Imsi;

/// AlertReason — why the subscriber is now reachable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, AsnType, Decode, Encode)]
#[rasn(enumerated)]
pub enum AlertReason {
    MsPresent = 0,
    MemoryAvailable = 1,
}

/// ReadyForSM-Arg — request parameters.
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct ReadyForSmArg {
    /// IMSI of the now-reachable subscriber.
    pub imsi: Imsi,
    /// Reason for the alert.
    pub alert_reason: AlertReason,
}

/// ReadyForSM-Res — response (empty in most cases).
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct ReadyForSmRes {}
