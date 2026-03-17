//! Location Management operations — 3GPP TS 29.002.
//!
//! - updateLocation (op 2)
//! - cancelLocation (op 3)
//! - purgeMS (op 67)
//! - sendIdentification (op 55)

use rasn::prelude::*;

use crate::types::{Imsi, IsdnAddressString, Lmsi};

/// UpdateLocation-Arg (op 2).
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct UpdateLocationArg {
    /// IMSI of the subscriber.
    pub imsi: Imsi,
    /// ISDN number of the MSC/VLR.
    #[rasn(tag(context, 1))]
    pub msc_number: IsdnAddressString,
    /// VLR number.
    pub vlr_number: IsdnAddressString,
    /// LMSI assigned by the VLR.
    #[rasn(tag(context, 10))]
    pub lmsi: Option<Lmsi>,
    /// VLR capability (v3).
    #[rasn(tag(context, 6))]
    pub vlr_capability: Option<OctetString>,
}

/// UpdateLocation-Res (op 2).
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct UpdateLocationRes {
    /// HLR number.
    pub hlr_number: IsdnAddressString,
}

/// CancellationType for cancelLocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, AsnType, Decode, Encode)]
#[rasn(enumerated)]
pub enum CancellationType {
    UpdateProcedure = 0,
    SubscriptionWithdraw = 1,
    InitialAttachProcedure = 2,
}

/// CancelLocation-Arg (op 3).
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct CancelLocationArg {
    /// IMSI of the subscriber.
    pub identity: Imsi,
    /// Cancellation type.
    pub cancellation_type: Option<CancellationType>,
}

/// CancelLocation-Res (op 3).
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct CancelLocationRes {}

/// PurgeMS-Arg (op 67).
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct PurgeMsArg {
    /// IMSI of the subscriber.
    pub imsi: Imsi,
    /// VLR number.
    #[rasn(tag(context, 0))]
    pub vlr_number: Option<IsdnAddressString>,
    /// SGSN number.
    #[rasn(tag(context, 1))]
    pub sgsn_number: Option<IsdnAddressString>,
}

/// PurgeMS-Res (op 67).
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct PurgeMsRes {
    /// Freeze TMSI flag.
    #[rasn(tag(context, 0))]
    pub freeze_tmsi: Option<()>,
    /// Freeze P-TMSI flag.
    #[rasn(tag(context, 1))]
    pub freeze_p_tmsi: Option<()>,
}

/// SendIdentification-Arg (op 55).
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct SendIdentificationArg {
    /// TMSI.
    pub tmsi: OctetString,
    /// Number of requested authentication vectors.
    pub number_of_requested_vectors: Option<Integer>,
}

/// SendIdentification-Res (op 55).
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct SendIdentificationRes {
    /// IMSI of the subscriber.
    pub imsi: Imsi,
    /// Authentication set list (opaque).
    #[rasn(tag(context, 0))]
    pub authentication_set_list: Option<OctetString>,
}

/// Operation codes for location management.
pub mod op_codes {
    pub const UPDATE_LOCATION: i64 = 2;
    pub const CANCEL_LOCATION: i64 = 3;
    pub const PURGE_MS: i64 = 67;
    pub const SEND_IDENTIFICATION: i64 = 55;
}
