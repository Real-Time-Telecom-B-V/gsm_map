//! Call Handling operations — 3GPP TS 29.002.
//!
//! - sendRoutingInfo (op 22)
//! - provideRoamingNumber (op 4)

use rasn::prelude::*;

use crate::types::{Imsi, IsdnAddressString, Lmsi};

/// InterrogationType — used in sendRoutingInfo.
#[derive(Debug, Clone, Copy, PartialEq, Eq, AsnType, Decode, Encode)]
#[rasn(enumerated)]
pub enum InterrogationType {
    BasicCall = 0,
    Forwarding = 1,
}

/// SendRoutingInfo-Arg (op 22).
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct SendRoutingInfoArg {
    /// MSISDN of the called subscriber.
    pub msisdn: IsdnAddressString,
    /// CUG (Closed User Group) check info (optional).
    #[rasn(tag(context, 0))]
    pub cug_check_info: Option<OctetString>,
    /// Number of forwarding.
    #[rasn(tag(context, 1))]
    pub number_of_forwarding: Option<Integer>,
    /// Interrogation type.
    #[rasn(tag(context, 3))]
    pub interrogation_type: Option<InterrogationType>,
    /// GMSC address.
    #[rasn(tag(context, 6))]
    pub gmsc_or_gmscs_address: Option<IsdnAddressString>,
}

/// SendRoutingInfo-Res (op 22).
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct SendRoutingInfoRes {
    /// IMSI of the subscriber.
    pub imsi: Imsi,
    /// Roaming number.
    #[rasn(tag(context, 0))]
    pub roaming_number: Option<IsdnAddressString>,
}

/// ProvideRoamingNumber-Arg (op 4).
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct ProvideRoamingNumberArg {
    /// IMSI.
    pub imsi: Imsi,
    /// MSC number.
    pub msc_number: IsdnAddressString,
    /// MSISDN (optional).
    #[rasn(tag(context, 0))]
    pub msisdn: Option<IsdnAddressString>,
    /// LMSI (optional).
    #[rasn(tag(context, 1))]
    pub lmsi: Option<Lmsi>,
    /// GMSC address.
    #[rasn(tag(context, 2))]
    pub gsm_bearer_capability: Option<OctetString>,
}

/// ProvideRoamingNumber-Res (op 4).
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct ProvideRoamingNumberRes {
    /// Roaming number assigned by the VLR.
    pub roaming_number: IsdnAddressString,
}

pub mod op_codes {
    pub const SEND_ROUTING_INFO: i64 = 22;
    pub const PROVIDE_ROAMING_NUMBER: i64 = 4;
}
