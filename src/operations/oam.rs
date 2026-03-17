//! OAM (Operation, Administration, Maintenance) operations — 3GPP TS 29.002.
//!
//! - activateTraceMode (op 50)
//! - deactivateTraceMode (op 51)
//! - sendIMSI (op 58)

use rasn::prelude::*;

use crate::types::{Imsi, IsdnAddressString};

/// TraceReference.
pub type TraceReference = OctetString;

/// TraceType.
pub type TraceType = Integer;

/// ActivateTraceMode-Arg (op 50).
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct ActivateTraceModeArg {
    #[rasn(tag(context, 0))]
    pub imsi: Option<Imsi>,
    #[rasn(tag(context, 1))]
    pub trace_reference: TraceReference,
    #[rasn(tag(context, 2))]
    pub trace_type: TraceType,
    #[rasn(tag(context, 3))]
    pub omc_id: Option<OctetString>,
}

/// ActivateTraceMode-Res (op 50).
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct ActivateTraceModeRes {}

/// DeactivateTraceMode-Arg (op 51).
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct DeactivateTraceModeArg {
    #[rasn(tag(context, 0))]
    pub imsi: Option<Imsi>,
    #[rasn(tag(context, 1))]
    pub trace_reference: TraceReference,
}

/// DeactivateTraceMode-Res (op 51).
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct DeactivateTraceModeRes {}

/// SendIMSI-Arg (op 58).
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct SendImsiArg {
    pub msisdn: IsdnAddressString,
}

/// SendIMSI-Res (op 58).
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct SendImsiRes {
    pub imsi: Imsi,
}

pub mod op_codes {
    pub const ACTIVATE_TRACE_MODE: i64 = 50;
    pub const DEACTIVATE_TRACE_MODE: i64 = 51;
    pub const SEND_IMSI: i64 = 58;
}
