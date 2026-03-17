//! Supplementary Service operations — 3GPP TS 29.002.
//!
//! - registerSS (op 10)
//! - eraseSS (op 11)
//! - activateSS (op 12)
//! - deactivateSS (op 13)
//! - interrogateSS (op 14)

use rasn::prelude::*;

use crate::types::IsdnAddressString;

/// SS-Code — supplementary service code (1 byte).
pub type SsCode = OctetString;

/// Basic Service Code — teleservice or bearer service.
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
#[rasn(choice)]
pub enum BasicServiceCode {
    #[rasn(tag(context, 2))]
    BearerService(OctetString),
    #[rasn(tag(context, 3))]
    Teleservice(OctetString),
}

/// SS-Status — supplementary service status (1 byte bit field).
/// Bit 0: A (Active), Bit 1: R (Registered), Bit 2: P (Provisioned), Bit 3: Q (Quiescent).
pub type SsStatus = OctetString;

/// ForwardingInfo — call forwarding parameters.
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct ForwardingFeature {
    /// Basic service this forwarding applies to.
    pub basic_service: Option<BasicServiceCode>,
    /// SS status.
    #[rasn(tag(context, 4))]
    pub ss_status: Option<SsStatus>,
    /// Forwarded-to number.
    #[rasn(tag(context, 5))]
    pub forwarded_to_number: Option<IsdnAddressString>,
    /// No-reply condition timer (seconds).
    #[rasn(tag(context, 7))]
    pub no_reply_condition_time: Option<Integer>,
}

/// RegisterSS-Arg (op 10).
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct RegisterSsArg {
    /// SS code.
    pub ss_code: SsCode,
    /// Basic service group.
    pub basic_service: Option<BasicServiceCode>,
    /// Forwarded-to number.
    pub forwarded_to_number: Option<IsdnAddressString>,
    /// No-reply condition timer.
    #[rasn(tag(context, 4))]
    pub no_reply_condition_time: Option<Integer>,
}

/// EraseSS-Arg (op 11).
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct EraseSsArg {
    pub ss_code: SsCode,
    pub basic_service: Option<BasicServiceCode>,
}

/// ActivateSS-Arg (op 12).
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct ActivateSsArg {
    pub ss_code: SsCode,
    pub basic_service: Option<BasicServiceCode>,
}

/// DeactivateSS-Arg (op 13).
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct DeactivateSsArg {
    pub ss_code: SsCode,
    pub basic_service: Option<BasicServiceCode>,
}

/// InterrogateSS-Arg (op 14).
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct InterrogateSsArg {
    pub ss_code: SsCode,
    pub basic_service: Option<BasicServiceCode>,
}

/// InterrogateSS-Res (op 14) — response containing SS info.
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
#[rasn(choice)]
pub enum InterrogateSsRes {
    #[rasn(tag(context, 0))]
    SsStatus(SsStatus),
    #[rasn(tag(context, 2))]
    ForwardingFeatureList(Vec<ForwardingFeature>),
    #[rasn(tag(context, 3))]
    GenericServiceInfo(OctetString),
}

pub mod op_codes {
    pub const REGISTER_SS: i64 = 10;
    pub const ERASE_SS: i64 = 11;
    pub const ACTIVATE_SS: i64 = 12;
    pub const DEACTIVATE_SS: i64 = 13;
    pub const INTERROGATE_SS: i64 = 14;
}
