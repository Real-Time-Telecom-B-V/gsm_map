//! sendRoutingInfoForSM (operation code 45) — 3GPP TS 29.002.
//!
//! Used by the SMS-SC to query the HLR for the IMSI and serving MSC/SGSN
//! address of the SMS recipient.

use rasn::prelude::*;

use crate::types::{AddressString, Imsi, IsdnAddressString, LocationInfoWithLmsi};

/// RoutingInfoForSM-Arg — request parameters.
///
/// ```asn1
/// RoutingInfoForSM-Arg ::= SEQUENCE {
///     msisdn                  [0] ISDN-AddressString,
///     sm-RP-PRI               [1] BOOLEAN,
///     serviceCentreAddress    [2] AddressString,
///     extensionContainer      [6] ExtensionContainer OPTIONAL,
///     gprsSupportIndicator    [7] NULL OPTIONAL,
///     sm-RP-MTI               [8] INTEGER (0..10) OPTIONAL,
///     sm-RP-SMEA              [9] OCTET STRING OPTIONAL
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct RoutingInfoForSmArg {
    #[rasn(tag(context, 0))]
    pub msisdn: IsdnAddressString,
    #[rasn(tag(context, 1))]
    pub sm_rp_pri: bool,
    #[rasn(tag(context, 2))]
    pub service_centre_address: AddressString,
    #[rasn(tag(context, 7))]
    pub gprs_support_indicator: Option<()>,
    #[rasn(tag(context, 8))]
    pub sm_rp_mti: Option<Integer>,
    #[rasn(tag(context, 9))]
    pub sm_rp_smea: Option<OctetString>,
}

/// RoutingInfoForSM-Res — response parameters.
///
/// ```asn1
/// RoutingInfoForSM-Res ::= SEQUENCE {
///     imsi                    IMSI,
///     locationInfoWithLMSI    [0] LocationInfoWithLMSI,
///     extensionContainer      [4] ExtensionContainer OPTIONAL
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct RoutingInfoForSmRes {
    pub imsi: Imsi,
    #[rasn(tag(context, 0))]
    pub location_info_with_lmsi: LocationInfoWithLmsi,
}
