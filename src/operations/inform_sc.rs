//! informServiceCentre (operation code 63) — 3GPP TS 29.002.
//!
//! The HLR tells the SMS-GMSC, inside the SRI-SM dialogue, what it already knows
//! about the subscriber's message-waiting state, so the service centre does not
//! attempt a delivery the HLR knows will fail.
//!
//! Every member TS 29.002 defines is modelled; see [`crate`] on what
//! happens to a member that is not.

use rasn::prelude::*;

use crate::types::{AbsentSubscriberDiagnosticSm, ExtensionContainer, IsdnAddressString, MwStatus};

/// InformServiceCentreArg — request parameters.
///
/// ```asn1
/// InformServiceCentreArg ::= SEQUENCE {
///     storedMSISDN                                ISDN-AddressString OPTIONAL,
///     mw-Status                                   MW-Status OPTIONAL,
///     extensionContainer                          ExtensionContainer OPTIONAL,
///     ...,
///     absentSubscriberDiagnosticSM                AbsentSubscriberDiagnosticSM OPTIONAL,
///     additionalAbsentSubscriberDiagnosticSM  [0] AbsentSubscriberDiagnosticSM OPTIONAL,
///     smsf3gppAbsentSubscriberDiagnosticSM    [1] AbsentSubscriberDiagnosticSM OPTIONAL,
///     smsfNon3gppAbsentSubscriberDiagnosticSM [2] AbsentSubscriberDiagnosticSM OPTIONAL }
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct InformServiceCentreArg {
    /// Stored MSISDN (if different from the one the service centre used).
    pub stored_msisdn: Option<IsdnAddressString>,
    /// Message-waiting flags. Build with
    /// [`MwStatusFlags::to_bits`](crate::types::MwStatusFlags::to_bits) — this is
    /// a BIT STRING numbered from the most significant bit, not a packed byte.
    pub mw_status: Option<MwStatus>,
    pub extension_container: Option<ExtensionContainer>,
    pub absent_subscriber_diagnostic_sm: Option<AbsentSubscriberDiagnosticSm>,
    #[rasn(tag(context, 0))]
    pub additional_absent_subscriber_diagnostic_sm: Option<AbsentSubscriberDiagnosticSm>,
    #[rasn(tag(context, 1))]
    pub smsf_3gpp_absent_subscriber_diagnostic_sm: Option<AbsentSubscriberDiagnosticSm>,
    #[rasn(tag(context, 2))]
    pub smsf_non_3gpp_absent_subscriber_diagnostic_sm: Option<AbsentSubscriberDiagnosticSm>,
}
