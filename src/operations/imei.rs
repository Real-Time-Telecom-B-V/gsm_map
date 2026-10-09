//! IMEI check (checkIMEI, operation code 43) — 3GPP TS 29.002.
//!
//! Every member TS 29.002 defines is modelled; see [`crate`] on what
//! happens to a member that is not.

use rasn::prelude::*;

use crate::types::ExtensionContainer;

/// EquipmentStatus — the EIR's verdict on the IMEI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, AsnType, Decode, Encode)]
#[rasn(enumerated)]
pub enum EquipmentStatus {
    WhiteListed = 0,
    BlackListed = 1,
    GreyListed = 2,
}

/// CheckIMEI-Arg (op 43).
///
/// ```asn1
/// CheckIMEI-Arg ::= SEQUENCE {
///     imei                    IMEI,
///     requestedEquipmentInfo  RequestedEquipmentInfo,
///     extensionContainer      ExtensionContainer OPTIONAL,
///     ... }
///
/// RequestedEquipmentInfo ::= BIT STRING { equipmentStatus(0), bmuef(1) } (SIZE (2..8))
/// ```
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct CheckImeiArg {
    /// IMEI to check (TBCD, 8 bytes).
    pub imei: OctetString,
    /// Which pieces of information the requester wants back.
    pub requested_equipment_info: BitString,
    pub extension_container: Option<ExtensionContainer>,
}

impl CheckImeiArg {
    /// The two mandatory members; every optional member starts `None`.
    pub fn new(imei: OctetString, requested_equipment_info: BitString) -> Self {
        Self {
            imei,
            requested_equipment_info,
            extension_container: None,
        }
    }

    /// The usual request: just the equipment status (bit 0).
    pub fn equipment_status_only(imei: OctetString) -> Self {
        let mut bits = BitString::new();
        bits.push(true);
        bits.push(false);
        Self::new(imei, bits)
    }
}

/// UESBI-Iu — the UE Security-Behaviour Information the EIR returns.
///
/// ```asn1
/// UESBI-Iu ::= SEQUENCE {
///     uesbi-IuA  [0] UESBI-IuA OPTIONAL,
///     uesbi-IuB  [1] UESBI-IuB OPTIONAL,
///     ... }
/// ```
///
/// Modelled rather than carried opaquely because it sits at an **untagged**
/// optional position, where an opaque value would swallow whatever follows.
#[derive(Debug, Clone, Default, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct UesbiIu {
    #[rasn(tag(context, 0))]
    pub uesbi_iu_a: Option<BitString>,
    #[rasn(tag(context, 1))]
    pub uesbi_iu_b: Option<BitString>,
}

/// CheckIMEI-Res (op 43).
///
/// ```asn1
/// CheckIMEI-Res ::= SEQUENCE {
///     equipmentStatus         EquipmentStatus OPTIONAL,
///     bmuef                   UESBI-Iu OPTIONAL,
///     extensionContainer  [0] ExtensionContainer OPTIONAL,
///     ... }
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct CheckImeiRes {
    pub equipment_status: Option<EquipmentStatus>,
    /// UE Security-Behaviour Information.
    pub bmuef: Option<UesbiIu>,
    #[rasn(tag(context, 0))]
    pub extension_container: Option<ExtensionContainer>,
}

/// Operation code for the IMEI check. Re-exported from
/// [`crate::types::op_codes`].
pub mod op_codes {
    pub use crate::types::op_codes::CHECK_IMEI;
}
