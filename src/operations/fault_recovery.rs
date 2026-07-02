//! Fault Recovery operations — 3GPP TS 29.002.
//!
//! - reset (op 37)
//! - restoreData (op 57)

use rasn::prelude::*;

use crate::types::{Imsi, IsdnAddressString};

/// Reset-Arg (op 37).
/// Sent by the HLR to VLRs after HLR restart.
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct ResetArg {
    /// HLR number.
    pub hlr_number: IsdnAddressString,
    /// List of HLR IDs (IMSI prefixes) affected.
    pub hlr_list: Option<Vec<OctetString>>,
}

/// RestoreData-Arg (op 57).
/// Sent by the VLR to the HLR to restore subscriber data after VLR restart.
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct RestoreDataArg {
    /// IMSI of the subscriber.
    pub imsi: Imsi,
    /// LMSI.
    pub lmsi: Option<OctetString>,
}

/// RestoreData-Res (op 57).
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct RestoreDataRes {
    /// HLR number.
    pub hlr_number: IsdnAddressString,
}

pub mod op_codes {
    pub const RESET: i64 = 37;
    pub const RESTORE_DATA: i64 = 57;
}
