//! mt-ForwardSM (operation code 44) — 3GPP TS 29.002.
//!
//! Mobile-terminated SMS forwarding from the SMS-SC/SMS-GMSC to the serving MSC/SGSN.

use rasn::prelude::*;

use crate::types::{SmRpDa, SmRpOa};

/// MT-ForwardSM-Arg — request parameters.
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct MtForwardSmArg {
    /// Destination address (IMSI or LMSI of the recipient).
    pub sm_rp_da: SmRpDa,
    /// Originating address (service centre address).
    pub sm_rp_oa: SmRpOa,
    /// SM-RP-UI (User Information — the SMS-DELIVER TPDU).
    pub sm_rp_ui: OctetString,
    /// More messages to send flag.
    pub more_messages_to_send: Option<bool>,
}

/// MT-ForwardSM-Res — response parameters.
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct MtForwardSmRes {
    /// SM-RP-UI (User Information — the SMS-DELIVER-REPORT TPDU).
    pub sm_rp_ui: Option<OctetString>,
}
