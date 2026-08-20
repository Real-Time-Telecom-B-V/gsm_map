//! Fault Recovery operations — 3GPP TS 29.002.
//!
//! - reset (op 37)
//! - restoreData (op 57)
//!
//! Every member TS 29.002 defines is modelled; see [`crate`] on why an
//! unmodelled member is fatal rather than merely absent.

use rasn::prelude::*;

use crate::types::{ExtensionContainer, Imsi, IsdnAddressString, Lmsi, Opaque};

/// Reset-Arg (op 37).
///
/// ```asn1
/// ResetArg ::= SEQUENCE {
///     sendingNodenumber           SendingNode-Number,
///     hlr-List                    HLR-List OPTIONAL,
///     ...,
///     extensionContainer      [0] ExtensionContainer OPTIONAL,
///     reset-Id-List           [1] Reset-IDs OPTIONAL,
///     subscriptionData        [2] InsertSubscriberDataArg OPTIONAL,
///     subscriptionDataDeletion [3] DeleteSubscriberDataArg OPTIONAL }
///
/// SendingNode-Number ::= CHOICE {
///     hlr-Number       ISDN-AddressString,
///     css-Number   [1] ISDN-AddressString }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct ResetArg {
    pub sending_node_number: SendingNodeNumber,
    /// `HLR-List ::= SEQUENCE OF HLR-Id` — the HLR identities being reset.
    pub hlr_list: Option<Vec<OctetString>>,
    #[rasn(tag(context, 0))]
    pub extension_container: Option<ExtensionContainer>,
    #[rasn(tag(context, 1))]
    pub reset_id_list: Option<Opaque>,
    #[rasn(tag(context, 2))]
    pub subscription_data: Option<Opaque>,
    #[rasn(tag(context, 3))]
    pub subscription_data_deletion: Option<Opaque>,
}

impl ResetArg {
    /// The one mandatory member; every optional member starts `None`.
    pub fn new(sending_node_number: SendingNodeNumber) -> Self {
        Self {
            sending_node_number,
            hlr_list: None,
            extension_container: None,
            reset_id_list: None,
            subscription_data: None,
            subscription_data_deletion: None,
        }
    }
}

/// SendingNode-Number — which node is resetting.
///
/// ```asn1
/// SendingNode-Number ::= CHOICE {
///     hlr-Number      ISDN-AddressString,
///     css-Number  [1] ISDN-AddressString }
/// ```
///
/// `hlr-Number` is **untagged**, so on the wire it is a universal
/// OCTET STRING; only `css-Number` carries a context tag.
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
#[rasn(choice)]
pub enum SendingNodeNumber {
    HlrNumber(IsdnAddressString),
    #[rasn(tag(context, 1))]
    CssNumber(IsdnAddressString),
}

/// RestoreData-Arg (op 57).
///
/// ```asn1
/// RestoreDataArg ::= SEQUENCE {
///     imsi                    IMSI,
///     lmsi                    LMSI OPTIONAL,
///     extensionContainer      ExtensionContainer OPTIONAL,
///     ...,
///     vlr-Capability      [6] VLR-Capability OPTIONAL,
///     restorationIndicator [7] NULL OPTIONAL }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct RestoreDataArg {
    pub imsi: Imsi,
    pub lmsi: Option<Lmsi>,
    pub extension_container: Option<ExtensionContainer>,
    #[rasn(tag(context, 6))]
    pub vlr_capability: Option<Opaque>,
    #[rasn(tag(context, 7))]
    pub restoration_indicator: Option<()>,
}

impl RestoreDataArg {
    /// The one mandatory member; every optional member starts `None`.
    pub fn new(imsi: Imsi) -> Self {
        Self {
            imsi,
            lmsi: None,
            extension_container: None,
            vlr_capability: None,
            restoration_indicator: None,
        }
    }
}

/// RestoreData-Res (op 57).
///
/// ```asn1
/// RestoreDataRes ::= SEQUENCE {
///     hlr-Number          ISDN-AddressString,
///     msNotReachable      NULL OPTIONAL,
///     extensionContainer  ExtensionContainer OPTIONAL,
///     ... }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct RestoreDataRes {
    pub hlr_number: IsdnAddressString,
    pub ms_not_reachable: Option<()>,
    pub extension_container: Option<ExtensionContainer>,
}

impl RestoreDataRes {
    /// The one mandatory member; every optional member starts `None`.
    pub fn new(hlr_number: IsdnAddressString) -> Self {
        Self {
            hlr_number,
            ms_not_reachable: None,
            extension_container: None,
        }
    }
}

/// Operation codes for fault recovery. Re-exported from
/// [`crate::types::op_codes`].
pub mod op_codes {
    pub use crate::types::op_codes::{RESET, RESTORE_DATA};
}
