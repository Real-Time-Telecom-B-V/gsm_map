//! Authentication operations — 3GPP TS 29.002.
//!
//! - sendAuthenticationInfo (op 56)
//!
//! v3 arg uses a named wrapper:
//! ```asn1
//! SendAuthenticationInfoArg ::= SEQUENCE {
//!     imsi                        [0] IMSI,
//!     numberOfRequestedVectors    INTEGER,
//!     ...
//!     re-synchronisationInfo      [1] Re-SynchronisationInfo OPTIONAL,
//!     requestingNodeType          [2] RequestingNodeType OPTIONAL
//! }
//! ```

use rasn::prelude::*;

use crate::types::Imsi;

/// SendAuthenticationInfo-Arg (op 56).
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct SendAuthenticationInfoArg {
    #[rasn(tag(context, 0))]
    pub imsi: Imsi,
    pub number_of_requested_vectors: Integer,
    #[rasn(tag(context, 1))]
    pub re_synchronisation_info: Option<OctetString>,
    #[rasn(tag(context, 2))]
    pub requesting_node_type: Option<Integer>,
}

/// AuthenticationTriplet — GSM authentication vector.
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct AuthenticationTriplet {
    pub rand: OctetString,
    pub sres: OctetString,
    pub kc: OctetString,
}

/// AuthenticationQuintuplet — UMTS authentication vector.
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct AuthenticationQuintuplet {
    pub rand: OctetString,
    pub xres: OctetString,
    pub ck: OctetString,
    pub ik: OctetString,
    pub autn: OctetString,
}

/// AuthenticationSetList — CHOICE between triplets and quintuplets.
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
#[rasn(choice)]
pub enum AuthenticationSetList {
    #[rasn(tag(context, 0))]
    TripletList(Vec<AuthenticationTriplet>),
    #[rasn(tag(context, 1))]
    QuintupletList(Vec<AuthenticationQuintuplet>),
}

/// SendAuthenticationInfo-Res (op 56) — v3.
/// The response is tagged `[3] SEQUENCE` per the ASN.1 spec.
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
#[rasn(tag(context, 3))]
pub struct SendAuthenticationInfoRes {
    pub authentication_set_list: Option<AuthenticationSetList>,
}

pub mod op_codes {
    pub const SEND_AUTHENTICATION_INFO: i64 = 56;
}
