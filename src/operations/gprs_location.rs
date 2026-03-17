//! GPRS Location Management operations — 3GPP TS 29.002.
//!
//! - updateGprsLocation (op 23)
//! - sendRoutingInfoForGprs (op 24)
//! - failureReport (op 25)
//! - noteMsPresentForGprs (op 26)

use rasn::prelude::*;

use crate::types::{Imsi, IsdnAddressString};

/// GSN-Address (IP address of SGSN/GGSN).
pub type GsnAddress = OctetString;

/// UpdateGprsLocation-Arg (op 23).
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct UpdateGprsLocationArg {
    pub imsi: Imsi,
    pub sgsn_number: IsdnAddressString,
    pub sgsn_address: GsnAddress,
    #[rasn(tag(context, 0))]
    pub sgsn_capability: Option<OctetString>,
    #[rasn(tag(context, 1))]
    pub informprevious_network_entity: Option<()>,
    #[rasn(tag(context, 2))]
    pub ps_lcs_not_supported_by_ue: Option<()>,
    #[rasn(tag(context, 4))]
    pub eps_info: Option<OctetString>,
}

/// UpdateGprsLocation-Res (op 23).
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct UpdateGprsLocationRes {
    pub hlr_number: IsdnAddressString,
    #[rasn(tag(context, 0))]
    pub add_capability: Option<()>,
    #[rasn(tag(context, 1))]
    pub sgsn_mm_separation_supported: Option<()>,
}

/// SendRoutingInfoForGprs-Arg (op 24).
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct SendRoutingInfoForGprsArg {
    #[rasn(tag(context, 0))]
    pub imsi: Imsi,
    #[rasn(tag(context, 1))]
    pub ggsn_address: Option<GsnAddress>,
    #[rasn(tag(context, 2))]
    pub ggsn_number: IsdnAddressString,
}

/// SendRoutingInfoForGprs-Res (op 24).
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct SendRoutingInfoForGprsRes {
    #[rasn(tag(context, 0))]
    pub sgsn_address: GsnAddress,
    #[rasn(tag(context, 1))]
    pub ggsn_address: Option<GsnAddress>,
    #[rasn(tag(context, 2))]
    pub mobile_not_reachable_reason: Option<Integer>,
}

/// FailureReport-Arg (op 25).
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct FailureReportArg {
    #[rasn(tag(context, 0))]
    pub imsi: Imsi,
    #[rasn(tag(context, 1))]
    pub ggsn_number: IsdnAddressString,
    #[rasn(tag(context, 2))]
    pub ggsn_address: Option<GsnAddress>,
}

/// FailureReport-Res (op 25).
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct FailureReportRes {
    #[rasn(tag(context, 0))]
    pub ggsn_address: Option<GsnAddress>,
}

/// NoteMsPresentForGprs-Arg (op 26).
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct NoteMsPresentForGprsArg {
    #[rasn(tag(context, 0))]
    pub imsi: Imsi,
    #[rasn(tag(context, 1))]
    pub sgsn_address: GsnAddress,
    #[rasn(tag(context, 2))]
    pub ggsn_address: Option<GsnAddress>,
}

/// NoteMsPresentForGprs-Res (op 26).
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct NoteMsPresentForGprsRes {}

pub mod op_codes {
    pub const UPDATE_GPRS_LOCATION: i64 = 23;
    pub const SEND_ROUTING_INFO_FOR_GPRS: i64 = 24;
    pub const FAILURE_REPORT: i64 = 25;
    pub const NOTE_MS_PRESENT_FOR_GPRS: i64 = 26;
}
