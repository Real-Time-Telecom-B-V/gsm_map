//! Operation and Maintenance operations — 3GPP TS 29.002.
//!
//! - activateTraceMode (op 50)
//! - deactivateTraceMode (op 51)
//! - sendIMSI (op 58)
//!
//! Every member TS 29.002 defines is modelled; see [`crate`] on why an
//! unmodelled member is fatal rather than merely absent.

use rasn::prelude::*;

use crate::types::{ExtensionContainer, Imsi, IsdnAddressString, Opaque};

/// ActivateTraceMode-Arg (op 50).
///
/// ```asn1
/// ActivateTraceModeArg ::= SEQUENCE {
///     imsi                    [0] IMSI OPTIONAL,
///     traceReference          [1] TraceReference,
///     traceType               [2] TraceType,
///     omc-Id                  [3] AddressString OPTIONAL,
///     extensionContainer      [4] ExtensionContainer OPTIONAL,
///     ...,
///     traceReference2         [5] TraceReference2 OPTIONAL,
///     traceDepthList          [6] TraceDepthList OPTIONAL,
///     traceNE-TypeList        [7] TraceNE-TypeList OPTIONAL,
///     traceInterfaceList      [8] TraceInterfaceList OPTIONAL,
///     traceEventList          [9] TraceEventList OPTIONAL,
///     traceCollectionEntity  [10] GSN-Address OPTIONAL,
///     mdt-Configuration      [11] MDT-Configuration OPTIONAL }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct ActivateTraceModeArg {
    #[rasn(tag(context, 0))]
    pub imsi: Option<Imsi>,
    #[rasn(tag(context, 1))]
    pub trace_reference: OctetString,
    #[rasn(tag(context, 2))]
    pub trace_type: Integer,
    #[rasn(tag(context, 3))]
    pub omc_id: Option<OctetString>,
    #[rasn(tag(context, 4))]
    pub extension_container: Option<ExtensionContainer>,
    #[rasn(tag(context, 5))]
    pub trace_reference2: Option<OctetString>,
    #[rasn(tag(context, 6))]
    pub trace_depth_list: Option<Opaque>,
    #[rasn(tag(context, 7))]
    pub trace_ne_type_list: Option<BitString>,
    #[rasn(tag(context, 8))]
    pub trace_interface_list: Option<Opaque>,
    #[rasn(tag(context, 9))]
    pub trace_event_list: Option<Opaque>,
    #[rasn(tag(context, 10))]
    pub trace_collection_entity: Option<OctetString>,
    #[rasn(tag(context, 11))]
    pub mdt_configuration: Option<Opaque>,
}

impl ActivateTraceModeArg {
    /// The two mandatory members; every optional member starts `None`.
    pub fn new(trace_reference: OctetString, trace_type: Integer) -> Self {
        Self {
            imsi: None,
            trace_reference,
            trace_type,
            omc_id: None,
            extension_container: None,
            trace_reference2: None,
            trace_depth_list: None,
            trace_ne_type_list: None,
            trace_interface_list: None,
            trace_event_list: None,
            trace_collection_entity: None,
            mdt_configuration: None,
        }
    }
}

/// ActivateTraceMode-Res (op 50).
///
/// ```asn1
/// ActivateTraceModeRes ::= SEQUENCE {
///     extensionContainer      [0] ExtensionContainer OPTIONAL,
///     ...,
///     traceSupportIndicator   [1] NULL OPTIONAL }
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct ActivateTraceModeRes {
    #[rasn(tag(context, 0))]
    pub extension_container: Option<ExtensionContainer>,
    #[rasn(tag(context, 1))]
    pub trace_support_indicator: Option<()>,
}

/// DeactivateTraceMode-Arg (op 51).
///
/// ```asn1
/// DeactivateTraceModeArg ::= SEQUENCE {
///     imsi                [0] IMSI OPTIONAL,
///     traceReference      [1] TraceReference,
///     extensionContainer  [2] ExtensionContainer OPTIONAL,
///     ...,
///     traceReference2     [3] TraceReference2 OPTIONAL }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct DeactivateTraceModeArg {
    #[rasn(tag(context, 0))]
    pub imsi: Option<Imsi>,
    #[rasn(tag(context, 1))]
    pub trace_reference: OctetString,
    #[rasn(tag(context, 2))]
    pub extension_container: Option<ExtensionContainer>,
    #[rasn(tag(context, 3))]
    pub trace_reference2: Option<OctetString>,
}

impl DeactivateTraceModeArg {
    /// The one mandatory member; every optional member starts `None`.
    pub fn new(trace_reference: OctetString) -> Self {
        Self {
            imsi: None,
            trace_reference,
            extension_container: None,
            trace_reference2: None,
        }
    }
}

/// DeactivateTraceMode-Res (op 51).
///
/// ```asn1
/// DeactivateTraceModeRes ::= SEQUENCE {
///     extensionContainer  [0] ExtensionContainer OPTIONAL,
///     ... }
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct DeactivateTraceModeRes {
    #[rasn(tag(context, 0))]
    pub extension_container: Option<ExtensionContainer>,
}

/// sendIMSI (op 58) argument — a bare `ISDN-AddressString`, **not** a SEQUENCE.
pub type SendImsiArg = IsdnAddressString;

/// sendIMSI (op 58) result — a bare `IMSI`, **not** a SEQUENCE.
pub type SendImsiRes = Imsi;

/// Operation codes for OAM. Re-exported from [`crate::types::op_codes`].
pub mod op_codes {
    pub use crate::types::op_codes::{ACTIVATE_TRACE_MODE, DEACTIVATE_TRACE_MODE, SEND_IMSI};
}
