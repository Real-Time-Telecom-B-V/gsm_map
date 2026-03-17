//! USSD (Unstructured Supplementary Service Data) operations — 3GPP TS 29.002.
//!
//! - processUnstructuredSS-Request (op 59)
//! - unstructuredSS-Request (op 60)
//! - unstructuredSS-Notify (op 61)

use rasn::prelude::*;

use crate::types::IsdnAddressString;

/// USSD Data Coding Scheme (CBS encoding per 3GPP TS 23.038).
pub type UssdDataCodingScheme = OctetString;

/// USSD String — the actual USSD text, encoded per the data coding scheme.
pub type UssdString = OctetString;

/// ProcessUnstructuredSS-Request-Arg (op 59).
/// Sent by the MSC to the HLR/gsmSCF to initiate a USSD dialogue.
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct ProcessUnstructuredSsRequestArg {
    /// Data coding scheme (e.g., 0x0F for default GSM 7-bit).
    pub ussd_data_coding_scheme: UssdDataCodingScheme,
    /// USSD string (the USSD code, e.g., *100#).
    pub ussd_string: UssdString,
    /// MSISDN of the subscriber (optional, v3).
    #[rasn(tag(context, 0))]
    pub msisdn: Option<IsdnAddressString>,
}

/// ProcessUnstructuredSS-Request-Res (op 59).
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct ProcessUnstructuredSsRequestRes {
    /// Data coding scheme for the response.
    pub ussd_data_coding_scheme: UssdDataCodingScheme,
    /// USSD response string.
    pub ussd_string: UssdString,
}

/// UnstructuredSS-Request-Arg (op 60).
/// Sent by the HLR/gsmSCF to the MSC to request input from the subscriber.
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct UnstructuredSsRequestArg {
    /// Data coding scheme.
    pub ussd_data_coding_scheme: UssdDataCodingScheme,
    /// USSD string (prompt text).
    pub ussd_string: UssdString,
}

/// UnstructuredSS-Request-Res (op 60).
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct UnstructuredSsRequestRes {
    /// Data coding scheme for the response.
    pub ussd_data_coding_scheme: UssdDataCodingScheme,
    /// USSD response string (user input).
    pub ussd_string: UssdString,
}

/// UnstructuredSS-Notify-Arg (op 61).
/// Sent by the HLR/gsmSCF to the MSC to display a notification to the subscriber.
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct UnstructuredSsNotifyArg {
    /// Data coding scheme.
    pub ussd_data_coding_scheme: UssdDataCodingScheme,
    /// USSD string (notification text).
    pub ussd_string: UssdString,
}

/// UnstructuredSS-Notify-Res (op 61) — empty.
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct UnstructuredSsNotifyRes {}

pub mod op_codes {
    pub const PROCESS_UNSTRUCTURED_SS_REQUEST: i64 = 59;
    pub const UNSTRUCTURED_SS_REQUEST: i64 = 60;
    pub const UNSTRUCTURED_SS_NOTIFY: i64 = 61;
}
