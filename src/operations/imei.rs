//! IMEI Check operations — 3GPP TS 29.002.
//!
//! - checkIMEI (op 43)

use rasn::prelude::*;

/// IMEI — International Mobile Equipment Identity (8 bytes TBCD).
pub type Imei = OctetString;

/// EquipmentStatus.
#[derive(Debug, Clone, Copy, PartialEq, Eq, AsnType, Decode, Encode)]
#[rasn(enumerated)]
pub enum EquipmentStatus {
    Whitelist = 0,
    Blacklist = 1,
    Greylist = 2,
}

/// CheckIMEI-Arg (op 43).
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct CheckImeiArg {
    pub imei: Imei,
    #[rasn(tag(context, 0))]
    pub requested_equipment_info: Option<OctetString>,
}

/// CheckIMEI-Res (op 43).
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct CheckImeiRes {
    pub equipment_status: Option<EquipmentStatus>,
}

pub mod op_codes {
    pub const CHECK_IMEI: i64 = 43;
}
