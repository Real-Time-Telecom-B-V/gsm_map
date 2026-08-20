//! Handover operations — 3GPP TS 29.002.
//!
//! - prepareHandover (op 68)
//! - sendEndSignal (op 29)
//! - processAccessSignalling (op 33)
//! - forwardAccessSignalling (op 34)
//! - prepareSubsequentHandover (op 69)
//!
//! These carry BSSMAP/RANAP in an `ExternalSignalInfo`, so the interesting
//! content is opaque to MAP by design. Every member TS 29.002 defines is
//! modelled; see [`crate`] on why an unmodelled member is fatal rather than
//! merely absent.

use rasn::prelude::*;

use crate::types::{ExtensionContainer, IsdnAddressString, Opaque, OpenEnumerated};

/// ExternalSignalInfo — a foreign protocol's message carried through MAP.
///
/// ```asn1
/// ExternalSignalInfo ::= SEQUENCE {
///     protocolId          ProtocolId,
///     signalInfo          SignalInfo,
///     extensionContainer  ExtensionContainer OPTIONAL,
///     ... }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct ExternalSignalInfo {
    /// `ProtocolId ::= ENUMERATED { gsm-0408(1), gsm-0806(2), gsm-BSSMAP(3),
    /// ets-300102-1(4) }` — untagged, so it carries the ENUMERATED universal
    /// tag, not INTEGER's.
    pub protocol_id: OpenEnumerated,
    /// The encapsulated message.
    pub signal_info: OctetString,
    pub extension_container: Option<ExtensionContainer>,
}

impl ExternalSignalInfo {
    /// The two mandatory members; the extension container starts `None`.
    pub fn new(protocol_id: OpenEnumerated, signal_info: OctetString) -> Self {
        Self {
            protocol_id,
            signal_info,
            extension_container: None,
        }
    }
}

/// PrepareHandover-Arg (op 68).
///
/// ```asn1
/// PrepareHO-Arg ::= SEQUENCE {
///     targetCellId            TargetCellId OPTIONAL,
///     ho-NumberNotRequired    NULL OPTIONAL,
///     bss-APDU                ExternalSignalInfo OPTIONAL,
///     ... }
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct PrepareHandoverArg {
    pub target_cell_id: Option<OctetString>,
    pub ho_number_not_required: Option<()>,
    pub bss_apdu: Option<ExternalSignalInfo>,
}

/// PrepareHandover-Res (op 68).
///
/// ```asn1
/// PrepareHO-Res ::= SEQUENCE {
///     handoverNumber  ISDN-AddressString OPTIONAL,
///     bss-APDU        ExternalSignalInfo OPTIONAL,
///     ... }
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct PrepareHandoverRes {
    pub handover_number: Option<IsdnAddressString>,
    pub bss_apdu: Option<ExternalSignalInfo>,
}

/// SendEndSignal-Arg (op 29) — a bare `ExternalSignalInfo` carrying the BSSMAP
/// or RANAP message.
pub type SendEndSignalArg = ExternalSignalInfo;

/// SendEndSignal-Res (op 29).
///
/// ```asn1
/// SendEndSignal-Res ::= SEQUENCE {
///     extensionContainer [0] ExtensionContainer OPTIONAL,
///     ... }
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct SendEndSignalRes {
    #[rasn(tag(context, 0))]
    pub extension_container: Option<ExtensionContainer>,
}

/// ProcessAccessSignalling-Arg (op 33) — a bare `ExternalSignalInfo`.
pub type ProcessAccessSignallingArg = ExternalSignalInfo;

/// ForwardAccessSignalling-Arg (op 34) — a bare `ExternalSignalInfo`.
pub type ForwardAccessSignallingArg = ExternalSignalInfo;

/// AccessNetworkSignalInfo — RANAP/BSSAP carried between MSCs.
///
/// ```asn1
/// AccessNetworkSignalInfo ::= SEQUENCE {
///     accessNetworkProtocolId  AccessNetworkProtocolId,
///     signalInfo               LongSignalInfo,
///     extensionContainer       ExtensionContainer OPTIONAL,
///     ... }
/// ```
///
/// Modelled rather than carried opaquely because it sits at an **untagged**
/// optional position on the result, where an opaque value would swallow
/// whatever follows.
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct AccessNetworkSignalInfo {
    /// `AccessNetworkProtocolId ::= ENUMERATED { ts3G-48006(1), ts3G-25413(2) }`
    /// — untagged, so it carries the ENUMERATED universal tag.
    pub access_network_protocol_id: OpenEnumerated,
    pub signal_info: OctetString,
    pub extension_container: Option<ExtensionContainer>,
}

impl AccessNetworkSignalInfo {
    /// The two mandatory members; the extension container starts `None`.
    pub fn new(access_network_protocol_id: OpenEnumerated, signal_info: OctetString) -> Self {
        Self {
            access_network_protocol_id,
            signal_info,
            extension_container: None,
        }
    }
}

/// PrepareSubsequentHandover-Arg (op 69).
///
/// The argument as a whole carries context tag `[3]`.
///
/// ```asn1
/// PrepareSubsequentHO-Arg ::= [3] SEQUENCE {
///     targetCellId        [0] GlobalCellId OPTIONAL,
///     targetMSC-Number    [1] ISDN-AddressString,
///     targetRNCId         [2] RNCId OPTIONAL,
///     an-APDU             [3] AccessNetworkSignalInfo OPTIONAL,
///     selectedRab-Id      [4] RAB-Id OPTIONAL,
///     extensionContainer  [5] ExtensionContainer OPTIONAL,
///     ...,
///     geran-classmark     [6] GERAN-Classmark OPTIONAL,
///     rab-ConfigurationIndicator [7] NULL OPTIONAL }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
#[rasn(tag(context, 3))]
pub struct PrepareSubsequentHandoverArg {
    #[rasn(tag(context, 0))]
    pub target_cell_id: Option<OctetString>,
    #[rasn(tag(context, 1))]
    pub target_msc_number: IsdnAddressString,
    #[rasn(tag(context, 2))]
    pub target_rnc_id: Option<OctetString>,
    #[rasn(tag(context, 3))]
    pub an_apdu: Option<Opaque>,
    #[rasn(tag(context, 4))]
    pub selected_rab_id: Option<Integer>,
    #[rasn(tag(context, 5))]
    pub extension_container: Option<ExtensionContainer>,
    #[rasn(tag(context, 6))]
    pub geran_classmark: Option<OctetString>,
    #[rasn(tag(context, 7))]
    pub rab_configuration_indicator: Option<()>,
}

impl PrepareSubsequentHandoverArg {
    /// The one mandatory member; every optional member starts `None`.
    pub fn new(target_msc_number: IsdnAddressString) -> Self {
        Self {
            target_cell_id: None,
            target_msc_number,
            target_rnc_id: None,
            an_apdu: None,
            selected_rab_id: None,
            extension_container: None,
            geran_classmark: None,
            rab_configuration_indicator: None,
        }
    }
}

/// PrepareSubsequentHandover-Res (op 69).
///
/// The result as a whole carries context tag `[3]`.
///
/// ```asn1
/// PrepareSubsequentHO-Res ::= [3] SEQUENCE {
///     an-APDU                 AccessNetworkSignalInfo OPTIONAL,
///     extensionContainer  [0] ExtensionContainer OPTIONAL,
///     ... }
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, AsnType, Decode, Encode)]
#[rasn(tag(context, 3))]
pub struct PrepareSubsequentHandoverRes {
    pub an_apdu: Option<AccessNetworkSignalInfo>,
    #[rasn(tag(context, 0))]
    pub extension_container: Option<ExtensionContainer>,
}

/// Operation codes for handover. Re-exported from [`crate::types::op_codes`].
pub mod op_codes {
    pub use crate::types::op_codes::{
        FORWARD_ACCESS_SIGNALLING, PREPARE_HANDOVER, PREPARE_SUBSEQUENT_HANDOVER,
        PROCESS_ACCESS_SIGNALLING, SEND_END_SIGNAL,
    };
}
