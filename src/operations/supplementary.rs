//! Supplementary Service operations — 3GPP TS 29.002.
//!
//! - registerSS (op 10), eraseSS (op 11), activateSS (op 12),
//!   deactivateSS (op 13), interrogateSS (op 14)
//!
//! Every member TS 29.002 defines is modelled; see [`crate`] on why an
//! unmodelled member is fatal rather than merely absent.

use rasn::prelude::*;

use crate::types::{IsdnAddressString, Opaque};

/// SS-Code — one byte identifying the supplementary service (TS 29.002 §17.7.5).
pub type SsCode = OctetString;

/// BasicServiceCode — a CHOICE between a bearer service and a teleservice.
///
/// ```asn1
/// BasicServiceCode ::= CHOICE {
///     bearerService  [2] BearerServiceCode,
///     teleservice    [3] TeleserviceCode }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
#[rasn(choice)]
pub enum BasicServiceCode {
    #[rasn(tag(context, 2))]
    BearerService(OctetString),
    #[rasn(tag(context, 3))]
    Teleservice(OctetString),
}

/// RegisterSS-Arg (op 10).
///
/// ```asn1
/// RegisterSS-Arg ::= SEQUENCE {
///     ss-Code                     SS-Code,
///     basicService                BasicServiceCode OPTIONAL,
///     forwardedToNumber       [4] AddressString OPTIONAL,
///     forwardedToSubaddress   [6] ISDN-SubaddressString OPTIONAL,
///     noReplyConditionTime    [5] NoReplyConditionTime OPTIONAL,
///     -- note [6] precedes [5]: BER encodes in declaration order, so this is
///     -- what goes on the wire
///     ...,
///     defaultPriority         [7] EMLPP-Priority OPTIONAL,
///     nbrUser                 [8] MC-Bearers OPTIONAL,
///     longFTN-Supported       [9] NULL OPTIONAL }
/// ```
///
/// `basicService` is an **untagged optional CHOICE**, which `rasn` cannot decode
/// in place: with no tag of its own there is nothing to test before committing,
/// so an absent service would swallow the next member. Its two alternatives are
/// therefore separate fields carrying their own `[2]` / `[3]` tags — identical
/// on the wire, since only one may be present.
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct RegisterSsArg {
    pub ss_code: SsCode,
    #[rasn(tag(context, 2))]
    pub bearer_service: Option<OctetString>,
    #[rasn(tag(context, 3))]
    pub teleservice: Option<OctetString>,
    #[rasn(tag(context, 4))]
    pub forwarded_to_number: Option<IsdnAddressString>,
    #[rasn(tag(context, 6))]
    pub forwarded_to_subaddress: Option<OctetString>,
    #[rasn(tag(context, 5))]
    pub no_reply_condition_time: Option<Integer>,
    #[rasn(tag(context, 7))]
    pub default_priority: Option<Integer>,
    #[rasn(tag(context, 8))]
    pub nbr_user: Option<Integer>,
    #[rasn(tag(context, 9))]
    pub long_ftn_supported: Option<()>,
}

impl RegisterSsArg {
    /// The one mandatory member; every optional member starts `None`.
    pub fn new(ss_code: SsCode) -> Self {
        Self {
            ss_code,
            bearer_service: None,
            teleservice: None,
            forwarded_to_number: None,
            forwarded_to_subaddress: None,
            no_reply_condition_time: None,
            default_priority: None,
            nbr_user: None,
            long_ftn_supported: None,
        }
    }
}

/// SS-Info — the result of registerSS / eraseSS / activateSS / deactivateSS.
///
/// ```asn1
/// SS-Info ::= CHOICE {
///     forwardingInfo   [0] ForwardingInfo,
///     callBarringInfo  [1] CallBarringInfo,
///     ss-Data          [3] SS-Data }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
#[rasn(choice)]
pub enum SsInfo {
    #[rasn(tag(context, 0))]
    ForwardingInfo(Opaque),
    #[rasn(tag(context, 1))]
    CallBarringInfo(Opaque),
    #[rasn(tag(context, 3))]
    SsData(Opaque),
}

/// SS-ForBS-Code — the argument shape shared by eraseSS, activateSS,
/// deactivateSS and interrogateSS.
///
/// ```asn1
/// SS-ForBS-Code ::= SEQUENCE {
///     ss-Code            SS-Code,
///     basicService       BasicServiceCode OPTIONAL,
///     ...,
///     longFTN-Supported  [4] NULL OPTIONAL }
/// ```
///
/// `basicService` is split into its two alternatives for the same reason as on
/// [`RegisterSsArg`].
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct SsForBsCode {
    pub ss_code: SsCode,
    #[rasn(tag(context, 2))]
    pub bearer_service: Option<OctetString>,
    #[rasn(tag(context, 3))]
    pub teleservice: Option<OctetString>,
    #[rasn(tag(context, 4))]
    pub long_ftn_supported: Option<()>,
}

impl SsForBsCode {
    /// The one mandatory member; every optional member starts `None`.
    pub fn new(ss_code: SsCode) -> Self {
        Self {
            ss_code,
            bearer_service: None,
            teleservice: None,
            long_ftn_supported: None,
        }
    }
}

/// EraseSS-Arg (op 11).
pub type EraseSsArg = SsForBsCode;
/// ActivateSS-Arg (op 12).
pub type ActivateSsArg = SsForBsCode;
/// DeactivateSS-Arg (op 13).
pub type DeactivateSsArg = SsForBsCode;
/// InterrogateSS-Arg (op 14).
pub type InterrogateSsArg = SsForBsCode;

/// InterrogateSS-Res (op 14) — a CHOICE, not a SEQUENCE.
///
/// ```asn1
/// InterrogateSS-Res ::= CHOICE {
///     ss-Status              [0] SS-Status,
///     basicServiceGroupList  [2] BasicServiceGroupList,
///     forwardingFeatureList  [3] ForwardingFeatureList,
///     genericServiceInfo     [4] GenericServiceInfo }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
#[rasn(choice)]
pub enum InterrogateSsRes {
    #[rasn(tag(context, 0))]
    SsStatus(OctetString),
    #[rasn(tag(context, 2))]
    BasicServiceGroupList(Vec<BasicServiceCode>),
    #[rasn(tag(context, 3))]
    ForwardingFeatureList(Opaque),
    #[rasn(tag(context, 4))]
    GenericServiceInfo(Opaque),
}

/// Operation codes for supplementary services. Re-exported from
/// [`crate::types::op_codes`].
pub mod op_codes {
    pub use crate::types::op_codes::{
        ACCESS_REGISTER_CC_ENTRY, ACTIVATE_SS, CALL_DEFLECTION, DEACTIVATE_SS, ERASE_CC_ENTRY,
        ERASE_SS, INTERROGATE_SS, NOTIFY_SS, REGISTER_CC_ENTRY, REGISTER_SS, USER_USER_SERVICE,
    };
}

/// NotifySS-Arg (op 16) — the network telling the MS that a supplementary
/// service fired. The operation has **no result**.
///
/// ```asn1
/// NotifySS-Arg ::= SEQUENCE {
///     ss-Code                  [1] SS-Code OPTIONAL,
///     ss-Status                [4] SS-Status OPTIONAL,
///     ss-Notification          [5] SS-Notification OPTIONAL,
///     callIsWaiting-Indicator [14] NULL OPTIONAL,
///     callOnHold-Indicator    [15] CallOnHold-Indicator OPTIONAL,
///     mpty-Indicator          [16] NULL OPTIONAL,
///     cug-Index               [17] CUG-Index OPTIONAL,
///     clirSuppressionRejected [18] NULL OPTIONAL,
///     ...,
///     ect-Indicator           [19] ECT-Indicator OPTIONAL,
///     nameIndicator           [20] NameIndicator OPTIONAL,
///     ccbs-Feature            [21] CCBS-Feature OPTIONAL,
///     alertingPattern         [22] AlertingPattern OPTIONAL,
///     multicall-Indicator     [23] Multicall-Indicator OPTIONAL }
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct NotifySsArg {
    #[rasn(tag(context, 1))]
    pub ss_code: Option<SsCode>,
    #[rasn(tag(context, 4))]
    pub ss_status: Option<OctetString>,
    #[rasn(tag(context, 5))]
    pub ss_notification: Option<BitString>,
    #[rasn(tag(context, 14))]
    pub call_is_waiting_indicator: Option<()>,
    /// `callRetrieved(0)`, `callOnHold(1)`.
    #[rasn(tag(context, 15))]
    pub call_on_hold_indicator: Option<Integer>,
    #[rasn(tag(context, 16))]
    pub mpty_indicator: Option<()>,
    #[rasn(tag(context, 17))]
    pub cug_index: Option<Integer>,
    #[rasn(tag(context, 18))]
    pub clir_suppression_rejected: Option<()>,
    #[rasn(tag(context, 19))]
    pub ect_indicator: Option<Opaque>,
    #[rasn(tag(context, 20))]
    pub name_indicator: Option<Opaque>,
    #[rasn(tag(context, 21))]
    pub ccbs_feature: Option<Opaque>,
    #[rasn(tag(context, 22))]
    pub alerting_pattern: Option<OctetString>,
    /// `nbr-SNexceeded(0)`, `nbr-Userexceeded(1)`, `nbr-SN-and-Userexceeded(2)`.
    #[rasn(tag(context, 23))]
    pub multicall_indicator: Option<Integer>,
}

/// RegisterCC-Entry-Arg (op 76) — register a call-completion (CCBS) request.
///
/// ```asn1
/// RegisterCC-EntryArg ::= SEQUENCE {
///     ss-Code   [0] SS-Code,
///     ccbs-Data [1] CCBS-Data OPTIONAL,
///     ... }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct RegisterCcEntryArg {
    #[rasn(tag(context, 0))]
    pub ss_code: SsCode,
    #[rasn(tag(context, 1))]
    pub ccbs_data: Option<Opaque>,
}

/// RegisterCC-Entry-Res (op 76).
///
/// ```asn1
/// RegisterCC-EntryRes ::= SEQUENCE {
///     ccbs-Feature [0] CCBS-Feature OPTIONAL,
///     ... }
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct RegisterCcEntryRes {
    #[rasn(tag(context, 0))]
    pub ccbs_feature: Option<Opaque>,
}

/// EraseCC-Entry-Arg (op 77).
///
/// ```asn1
/// EraseCC-EntryArg ::= SEQUENCE {
///     ss-Code    [0] SS-Code,
///     ccbs-Index [1] CCBS-Index OPTIONAL,
///     ... }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct EraseCcEntryArg {
    #[rasn(tag(context, 0))]
    pub ss_code: SsCode,
    #[rasn(tag(context, 1))]
    pub ccbs_index: Option<Integer>,
}

/// EraseCC-Entry-Res (op 77).
///
/// ```asn1
/// EraseCC-EntryRes ::= SEQUENCE {
///     ss-Code   [0] SS-Code OPTIONAL,
///     ss-Status [1] SS-Status OPTIONAL,
///     ... }
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct EraseCcEntryRes {
    #[rasn(tag(context, 0))]
    pub ss_code: Option<SsCode>,
    #[rasn(tag(context, 1))]
    pub ss_status: Option<OctetString>,
}

/// AccessRegisterCCEntry-Arg (op 119) — no argument members are defined.
#[derive(Debug, Clone, Default, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct AccessRegisterCcEntryArg {}

/// AccessRegisterCCEntry-Res (op 119).
///
/// ```asn1
/// RegisterCC-EntryRes ::= SEQUENCE {
///     ccbs-Feature [0] CCBS-Feature OPTIONAL,
///     ... }
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct AccessRegisterCcEntryRes {
    #[rasn(tag(context, 0))]
    pub ccbs_feature: Option<Opaque>,
}

/// CallDeflection-Arg (op 117) — the MS deflecting an incoming call. The
/// operation has **no result**.
///
/// ```asn1
/// CallDeflectionArg ::= SEQUENCE {
///     deflectedToNumber     [0] AddressString,
///     deflectedToSubaddress [1] ISDN-SubaddressString OPTIONAL,
///     ... }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct CallDeflectionArg {
    #[rasn(tag(context, 0))]
    pub deflected_to_number: IsdnAddressString,
    #[rasn(tag(context, 1))]
    pub deflected_to_subaddress: Option<OctetString>,
}

/// UserUserService-Arg (op 118) — request a user-to-user signalling service.
/// The operation has **no result**.
///
/// ```asn1
/// UserUserServiceArg ::= SEQUENCE {
///     uUS-Service  [0] UUS-Service,
///     uUS-Required [1] BOOLEAN,
///     ... }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct UserUserServiceArg {
    /// `uUS1(1)`, `uUS2(2)`, `uUS3(3)`.
    #[rasn(tag(context, 0))]
    pub uus_service: Integer,
    #[rasn(tag(context, 1))]
    pub uus_required: bool,
}
