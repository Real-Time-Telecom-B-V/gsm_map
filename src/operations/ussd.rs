//! USSD operations — 3GPP TS 29.002.
//!
//! - processUnstructuredSS-Request (op 59)
//! - unstructuredSS-Request (op 60)
//! - unstructuredSS-Notify (op 61)
//!
//! All three arguments share the same `USSD-Arg` shape and all members
//! TS 29.002 defines are modelled; see [`crate`] on why an unmodelled member is
//! fatal rather than merely absent.

use rasn::prelude::*;

use crate::types::IsdnAddressString;

/// USSD-DataCodingScheme — one byte, per TS 23.038.
pub type UssdDataCodingScheme = OctetString;

/// USSD-String — the (packed) USSD text, up to 160 bytes.
pub type UssdString = OctetString;

/// ProcessUnstructuredSS-Request-Arg (op 59).
///
/// ```asn1
/// ProcessUnstructuredSS-RequestArg ::= SEQUENCE {
///     ussd-DataCodingScheme     USSD-DataCodingScheme,
///     ussd-String               USSD-String,
///     ...,
///     alertingPattern           AlertingPattern OPTIONAL,
///     msisdn                [0] ISDN-AddressString OPTIONAL }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct ProcessUnstructuredSsRequestArg {
    pub ussd_data_coding_scheme: UssdDataCodingScheme,
    pub ussd_string: UssdString,
    pub alerting_pattern: Option<OctetString>,
    #[rasn(tag(context, 0))]
    pub msisdn: Option<IsdnAddressString>,
}

impl ProcessUnstructuredSsRequestArg {
    /// The two mandatory members; every optional member starts `None`.
    pub fn new(ussd_data_coding_scheme: UssdDataCodingScheme, ussd_string: UssdString) -> Self {
        Self {
            ussd_data_coding_scheme,
            ussd_string,
            alerting_pattern: None,
            msisdn: None,
        }
    }
}

/// ProcessUnstructuredSS-Request-Res (op 59).
///
/// ```asn1
/// ProcessUnstructuredSS-RequestRes ::= SEQUENCE {
///     ussd-DataCodingScheme  USSD-DataCodingScheme,
///     ussd-String            USSD-String,
///     ... }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct ProcessUnstructuredSsRequestRes {
    pub ussd_data_coding_scheme: UssdDataCodingScheme,
    pub ussd_string: UssdString,
}

/// UnstructuredSS-Request-Arg (op 60).
///
/// ```asn1
/// UnstructuredSS-RequestArg ::= SEQUENCE {
///     ussd-DataCodingScheme     USSD-DataCodingScheme,
///     ussd-String               USSD-String,
///     ...,
///     alertingPattern           AlertingPattern OPTIONAL,
///     msisdn                [0] ISDN-AddressString OPTIONAL }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct UnstructuredSsRequestArg {
    pub ussd_data_coding_scheme: UssdDataCodingScheme,
    pub ussd_string: UssdString,
    pub alerting_pattern: Option<OctetString>,
    #[rasn(tag(context, 0))]
    pub msisdn: Option<IsdnAddressString>,
}

impl UnstructuredSsRequestArg {
    /// The two mandatory members; every optional member starts `None`.
    pub fn new(ussd_data_coding_scheme: UssdDataCodingScheme, ussd_string: UssdString) -> Self {
        Self {
            ussd_data_coding_scheme,
            ussd_string,
            alerting_pattern: None,
            msisdn: None,
        }
    }
}

/// UnstructuredSS-Request-Res (op 60).
///
/// ```asn1
/// UnstructuredSS-RequestRes ::= SEQUENCE {
///     ussd-DataCodingScheme  USSD-DataCodingScheme OPTIONAL,
///     ussd-String            USSD-String OPTIONAL,
///     ... }
/// ```
///
/// Both members are modelled as **mandatory** even though the ASN.1 marks them
/// OPTIONAL. They are two adjacent untagged OCTET STRINGs, so BER cannot tell
/// which one is present when only one is — the ASN.1 is only unambiguous because
/// TS 29.002 requires them together or not at all. An answer that carries
/// neither is expressed by a TCAP `ReturnResult` with no parameter, not by an
/// empty SEQUENCE.
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct UnstructuredSsRequestRes {
    pub ussd_data_coding_scheme: UssdDataCodingScheme,
    pub ussd_string: UssdString,
}

/// UnstructuredSS-Notify-Arg (op 61).
///
/// ```asn1
/// UnstructuredSS-NotifyArg ::= SEQUENCE {
///     ussd-DataCodingScheme     USSD-DataCodingScheme,
///     ussd-String               USSD-String,
///     ...,
///     alertingPattern           AlertingPattern OPTIONAL,
///     msisdn                [0] ISDN-AddressString OPTIONAL }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct UnstructuredSsNotifyArg {
    pub ussd_data_coding_scheme: UssdDataCodingScheme,
    pub ussd_string: UssdString,
    pub alerting_pattern: Option<OctetString>,
    #[rasn(tag(context, 0))]
    pub msisdn: Option<IsdnAddressString>,
}

impl UnstructuredSsNotifyArg {
    /// The two mandatory members; every optional member starts `None`.
    pub fn new(ussd_data_coding_scheme: UssdDataCodingScheme, ussd_string: UssdString) -> Self {
        Self {
            ussd_data_coding_scheme,
            ussd_string,
            alerting_pattern: None,
            msisdn: None,
        }
    }
}

/// UnstructuredSS-Notify-Res (op 61) — the operation has no result parameter.
#[derive(Debug, Clone, Default, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct UnstructuredSsNotifyRes {}

/// Operation codes for USSD. Re-exported from [`crate::types::op_codes`].
pub mod op_codes {
    pub use crate::types::op_codes::{
        PROCESS_UNSTRUCTURED_SS_REQUEST, UNSTRUCTURED_SS_NOTIFY, UNSTRUCTURED_SS_REQUEST,
    };
}
