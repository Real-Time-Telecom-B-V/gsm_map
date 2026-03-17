//! mo-ForwardSM (operation code 46) — 3GPP TS 29.002.
//!
//! Mobile-originated SMS forwarding from the MSC to the SMS-IWMSC/SMS-SC.

use rasn::prelude::*;

use crate::types::{Imsi, SmRpDa, SmRpOa};

/// MO-ForwardSM-Arg — request parameters.
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct MoForwardSmArg {
    /// Destination address (usually the service centre address).
    pub sm_rp_da: SmRpDa,
    /// Originating address (MSISDN of the sender).
    pub sm_rp_oa: SmRpOa,
    /// SM-RP-UI (User Information — the SMS-SUBMIT TPDU).
    pub sm_rp_ui: OctetString,
    /// IMSI of the sender (optional).
    pub imsi: Option<Imsi>,
}

/// MO-ForwardSM-Res — response parameters.
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct MoForwardSmRes {
    /// SM-RP-UI (User Information — the SMS-SUBMIT-REPORT TPDU).
    pub sm_rp_ui: Option<OctetString>,
}
