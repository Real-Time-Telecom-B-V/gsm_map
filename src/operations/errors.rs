//! MAP error codes — 3GPP TS 29.002 `MAP-Errors`.
//!
//! A MAP failure comes back as a TCAP `ReturnError` whose `errorCode` is one of
//! these. Every code and name below was read back from an independent decoder
//! (see [`scripts/wireshark_check.sh`](../scripts/wireshark_check.sh)), and
//! [`error_name`] resolves every code this module defines — a registry that
//! answers `"unknown"` for its own constants is worse than no registry.
//!
//! Errors carry an optional parameter (a diagnostic, an alternative address,
//! a retry timer). This crate models the code and the name; the parameter, when
//! a peer sends one, is the TCAP `ReturnError`'s own `parameter` field.

/// Define the code constants and the name lookup from one list, so a code
/// cannot exist without a name — `error_name` returning `"unknown"` for one of
/// this module's own constants is the bug this shape prevents.
macro_rules! error_registry {
    ($( $(#[$meta:meta])* $konst:ident = $code:literal => $name:literal ),* $(,)?) => {
        /// MAP error codes.
        pub mod error_codes {
            $( $(#[$meta])* pub const $konst: i64 = $code; )*
        }

        /// The MAP error name for an error code.
        ///
        /// Every constant in [`error_codes`] resolves; anything else is
        /// `"unknown"`.
        pub fn error_name(code: i64) -> &'static str {
            match code {
                $( error_codes::$konst => $name, )*
                _ => "unknown",
            }
        }

        /// Every `(code, name)` pair this module knows, for tests and for a
        /// caller that wants to enumerate the registry.
        pub const ERROR_REGISTRY: &[(i64, &str)] = &[
            $( (error_codes::$konst, $name), )*
        ];
    };
}

error_registry! {
    // Identification and numbering
    UNKNOWN_SUBSCRIBER = 1 => "unknownSubscriber",
    UNKNOWN_BASE_STATION = 2 => "unknownBaseStation",
    UNKNOWN_MSC = 3 => "unknownMSC",
    SECURE_TRANSPORT_ERROR = 4 => "secureTransportError",
    UNIDENTIFIED_SUBSCRIBER = 5 => "unidentifiedSubscriber",
    ABSENT_SUBSCRIBER_SM = 6 => "absentSubscriberSM",
    UNKNOWN_EQUIPMENT = 7 => "unknownEquipment",

    // Subscription
    ROAMING_NOT_ALLOWED = 8 => "roamingNotAllowed",
    ILLEGAL_SUBSCRIBER = 9 => "illegalSubscriber",
    BEARER_SERVICE_NOT_PROVISIONED = 10 => "bearerServiceNotProvisioned",
    TELESERVICE_NOT_PROVISIONED = 11 => "teleserviceNotProvisioned",
    ILLEGAL_EQUIPMENT = 12 => "illegalEquipment",
    CALL_BARRED = 13 => "callBarred",
    FORWARDING_VIOLATION = 14 => "forwardingViolation",
    CUG_REJECT = 15 => "cug-Reject",

    // Supplementary services
    ILLEGAL_SS_OPERATION = 16 => "illegalSS-Operation",
    SS_ERROR_STATUS = 17 => "ss-ErrorStatus",
    SS_NOT_AVAILABLE = 18 => "ss-NotAvailable",
    SS_SUBSCRIPTION_VIOLATION = 19 => "ss-SubscriptionViolation",
    SS_INCOMPATIBILITY = 20 => "ss-Incompatibility",
    FACILITY_NOT_SUPPORTED = 21 => "facilityNotSupported",

    // Group call and radio resources
    ONGOING_GROUP_CALL = 22 => "ongoingGroupCall",
    INVALID_TARGET_BASE_STATION = 23 => "invalidTargetBaseStation",
    NO_RADIO_RESOURCE_AVAILABLE = 24 => "noRadioResourceAvailable",
    NO_HANDOVER_NUMBER_AVAILABLE = 25 => "noHandoverNumberAvailable",
    SUBSEQUENT_HANDOVER_FAILURE = 26 => "subsequentHandoverFailure",

    // Reachability
    ABSENT_SUBSCRIBER = 27 => "absentSubscriber",
    INCOMPATIBLE_TERMINAL = 28 => "incompatibleTerminal",
    SHORT_TERM_DENIAL = 29 => "shortTermDenial",
    LONG_TERM_DENIAL = 30 => "longTermDenial",

    // Short message service
    SUBSCRIBER_BUSY_FOR_MT_SMS = 31 => "subscriberBusyForMT-SMS",
    SM_DELIVERY_FAILURE = 32 => "sm-DeliveryFailure",
    MESSAGE_WAITING_LIST_FULL = 33 => "messageWaitingListFull",

    // Generic
    SYSTEM_FAILURE = 34 => "systemFailure",
    DATA_MISSING = 35 => "dataMissing",
    UNEXPECTED_DATA_VALUE = 36 => "unexpectedDataValue",

    // Password and call handling
    PW_REGISTRATION_FAILURE = 37 => "pw-RegistrationFailure",
    NEGATIVE_PW_CHECK = 38 => "negativePW-Check",
    NO_ROAMING_NUMBER_AVAILABLE = 39 => "noRoamingNumberAvailable",
    TRACING_BUFFER_FULL = 40 => "tracingBufferFull",
    TARGET_CELL_OUTSIDE_GROUP_CALL_AREA = 42 => "targetCellOutsideGroupCallArea",
    NUMBER_OF_PW_ATTEMPTS_VIOLATION = 43 => "numberOfPW-AttemptsViolation",
    NUMBER_CHANGED = 44 => "numberChanged",
    BUSY_SUBSCRIBER = 45 => "busySubscriber",
    NO_SUBSCRIBER_REPLY = 46 => "noSubscriberReply",
    FORWARDING_FAILED = 47 => "forwardingFailed",
    OR_NOT_ALLOWED = 48 => "or-NotAllowed",
    ATI_NOT_ALLOWED = 49 => "ati-NotAllowed",
    NO_GROUP_CALL_NUMBER_AVAILABLE = 50 => "noGroupCallNumberAvailable",
    RESOURCE_LIMITATION = 51 => "resourceLimitation",

    // Location services
    UNAUTHORIZED_REQUESTING_NETWORK = 52 => "unauthorizedRequestingNetwork",
    UNAUTHORIZED_LCS_CLIENT = 53 => "unauthorizedLCSClient",
    POSITION_METHOD_FAILURE = 54 => "positionMethodFailure",
    UNKNOWN_OR_UNREACHABLE_LCS_CLIENT = 58 => "unknownOrUnreachableLCSClient",

    // Any-time interrogation and modification
    MM_EVENT_NOT_SUPPORTED = 59 => "mm-EventNotSupported",
    ATSI_NOT_ALLOWED = 60 => "atsi-NotAllowed",
    /// anyTimeSubscriberDataModification is not allowed for this subscriber —
    /// what an HLR returns when it refuses an IP-SM-GW registration.
    ATM_NOT_ALLOWED = 61 => "atm-NotAllowed",
    INFORMATION_NOT_AVAILABLE = 62 => "informationNotAvailable",

    // USSD
    UNKNOWN_ALPHABET = 71 => "unknownAlphabet",
    USSD_BUSY = 72 => "ussd-Busy",
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_code_has_a_name_and_every_name_is_distinct() {
        let mut codes = std::collections::HashSet::new();
        let mut names = std::collections::HashSet::new();
        for (code, name) in ERROR_REGISTRY {
            assert_eq!(error_name(*code), *name);
            assert_ne!(*name, "unknown");
            assert!(codes.insert(code), "duplicate error code {code}");
            assert!(names.insert(name), "duplicate error name {name}");
        }
    }

    #[test]
    fn unknown_codes_resolve_to_unknown() {
        assert_eq!(error_name(0), "unknown");
        assert_eq!(error_name(41), "unknown");
        assert_eq!(error_name(9999), "unknown");
    }
}

// ── Error parameters ────────────────────────────────────────────────────────
//
// Most MAP errors carry a parameter, and for the SMS path it is the parameter
// that decides what a gateway does next: whether to queue, when to retry, and
// which of several failure modes it hit. The types below are the parameters for
// the errors that carry information a caller acts on. Every member was read
// back from an independent decoder; see `scripts/wireshark_check.sh`.
//
// The parameter travels as the TCAP `ReturnError`'s own `parameter` field, so
// decode it with `gsm_map::decode::<UnknownSubscriberParam>(bytes)` once the
// error code says which type to expect.

use rasn::prelude::*;

use crate::types::{
    AbsentSubscriberDiagnosticSm, ExtensionContainer, Imsi, OpenEnumerated, SignalInfo, Time,
};

/// `SEQUENCE { extensionContainer OPTIONAL, ... }` — the parameter shape shared
/// by `dataMissing`, `ati-NotAllowed`, `atm-NotAllowed`,
/// `informationNotAvailable`, `resourceLimitation` and
/// `unauthorizedRequestingNetwork`.
///
/// An IP-SM-GW that gets `atm-NotAllowed` back from an HLR is being told its
/// registration was refused outright; there is nothing further in the parameter
/// to inspect.
#[derive(Debug, Clone, Default, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct ExtensionContainerOnlyParam {
    pub extension_container: Option<ExtensionContainer>,
}

/// `unknownSubscriber` (1).
///
/// ```asn1
/// UnknownSubscriberParam ::= SEQUENCE {
///     extensionContainer          ExtensionContainer OPTIONAL,
///     ...,
///     unknownSubscriberDiagnostic UnknownSubscriberDiagnostic OPTIONAL }
/// ```
///
/// `unknownSubscriberDiagnostic` is `imsiUnknown(0)`,
/// `gprs-eps-SubscriptionUnknown(1)`, then the marker and `npdbMismatch(2)`. "If
/// unknown values are received in UnknownSubscriberDiagnostic they shall be
/// discarded."
#[derive(Debug, Clone, Default, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct UnknownSubscriberParam {
    pub extension_container: Option<ExtensionContainer>,
    pub unknown_subscriber_diagnostic: Option<OpenEnumerated>,
}

/// `absentSubscriberSM` (6) — the one an SMS-GMSC reads to decide whether to
/// queue the message and what to wait for.
///
/// ```asn1
/// AbsentSubscriberSM-Param ::= SEQUENCE {
///     absentSubscriberDiagnosticSM               AbsentSubscriberDiagnosticSM OPTIONAL,
///     extensionContainer                         ExtensionContainer OPTIONAL,
///     ...,
///     additionalAbsentSubscriberDiagnosticSM [0] AbsentSubscriberDiagnosticSM OPTIONAL,
///     imsi                                   [1] IMSI OPTIONAL,
///     requestedRetransmissionTime            [2] Time OPTIONAL,
///     userIdentifierAlert                    [3] IMSI OPTIONAL }
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct AbsentSubscriberSmParam {
    /// The TS 23.040 absent reason: why the subscriber could not be reached.
    pub absent_subscriber_diagnostic_sm: Option<AbsentSubscriberDiagnosticSm>,
    pub extension_container: Option<ExtensionContainer>,
    #[rasn(tag(context, 0))]
    pub additional_absent_subscriber_diagnostic_sm: Option<AbsentSubscriberDiagnosticSm>,
    #[rasn(tag(context, 1))]
    pub imsi: Option<Imsi>,
    /// When the HLR suggests the service centre tries again.
    #[rasn(tag(context, 2))]
    pub requested_retransmission_time: Option<Time>,
    /// The identity under which the HLR will alert the service centre once
    /// the subscriber is reachable again.
    #[rasn(tag(context, 3))]
    pub user_identifier_alert: Option<Imsi>,
}

/// `absentSubscriber` (27).
///
/// ```asn1
/// AbsentSubscriberParam ::= SEQUENCE {
///     extensionContainer       ExtensionContainer OPTIONAL,
///     ...,
///     absentSubscriberReason [0] AbsentSubscriberReason OPTIONAL }
/// ```
///
/// `absentSubscriberReason` is `imsiDetach(0)`, `restrictedArea(1)`,
/// `noPageResponse(2)`, `purgedMS(3)`, `mtRoamingRetry(4)`,
/// `busySubscriber(5)`; carried as `Integer` because the type is extensible.
#[derive(Debug, Clone, Default, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct AbsentSubscriberParam {
    pub extension_container: Option<ExtensionContainer>,
    #[rasn(tag(context, 0))]
    pub absent_subscriber_reason: Option<Integer>,
}

/// `subscriberBusyForMT-SMS` (31).
///
/// ```asn1
/// SubBusyForMT-SMS-Param ::= SEQUENCE {
///     extensionContainer      ExtensionContainer OPTIONAL,
///     ...,
///     gprsConnectionSuspended NULL OPTIONAL }
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct SubBusyForMtSmsParam {
    pub extension_container: Option<ExtensionContainer>,
    pub gprs_connection_suspended: Option<()>,
}

/// SM-EnumeratedDeliveryFailureCause — why an MT delivery attempt failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, AsnType, Decode, Encode)]
#[rasn(enumerated)]
pub enum SmEnumeratedDeliveryFailureCause {
    MemoryCapacityExceeded = 0,
    EquipmentProtocolError = 1,
    EquipmentNotSmEquipped = 2,
    UnknownServiceCentre = 3,
    ScCongestion = 4,
    InvalidSmeAddress = 5,
    SubscriberNotScSubscriber = 6,
}

/// `sm-DeliveryFailure` (32) — the MT-SMS failure detail.
///
/// ```asn1
/// SM-DeliveryFailureCause ::= SEQUENCE {
///     sm-EnumeratedDeliveryFailureCause SM-EnumeratedDeliveryFailureCause,
///     diagnosticInfo                    SignalInfo OPTIONAL,
///     extensionContainer                ExtensionContainer OPTIONAL,
///     ... }
/// ```
///
/// `diagnosticInfo` carries the SMS-DELIVER-REPORT TPDU the MS returned, which
/// is where the TP-FCS cause lives.
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct SmDeliveryFailureCause {
    pub sm_enumerated_delivery_failure_cause: SmEnumeratedDeliveryFailureCause,
    pub diagnostic_info: Option<SignalInfo>,
    pub extension_container: Option<ExtensionContainer>,
}

impl SmDeliveryFailureCause {
    /// The one mandatory member; every optional member starts `None`.
    pub fn new(cause: SmEnumeratedDeliveryFailureCause) -> Self {
        Self {
            sm_enumerated_delivery_failure_cause: cause,
            diagnostic_info: None,
            extension_container: None,
        }
    }
}

/// `roamingNotAllowed` (8).
///
/// ```asn1
/// RoamingNotAllowedParam ::= SEQUENCE {
///     roamingNotAllowedCause             RoamingNotAllowedCause,
///     extensionContainer                 ExtensionContainer OPTIONAL,
///     ...,
///     additionalRoamingNotAllowedCause [0] AdditionalRoamingNotAllowedCause OPTIONAL }
/// ```
///
/// `roamingNotAllowedCause` is `plmnRoamingNotAllowed(0)`,
/// `operatorDeterminedBarring(3)`; carried as `Integer` because the type is
/// extensible.
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct RoamingNotAllowedParam {
    pub roaming_not_allowed_cause: OpenEnumerated,
    pub extension_container: Option<ExtensionContainer>,
    #[rasn(tag(context, 0))]
    pub additional_roaming_not_allowed_cause: Option<Integer>,
}

/// `callBarred` (13) — the extensible alternative of `CallBarredParam`.
///
/// ```asn1
/// CallBarredParam ::= CHOICE {
///     callBarringCause          CallBarringCause,
///     extensibleCallBarredParam ExtensibleCallBarredParam }
///
/// ExtensibleCallBarredParam ::= SEQUENCE {
///     callBarringCause               CallBarringCause OPTIONAL,
///     extensionContainer             ExtensionContainer OPTIONAL,
///     ...,
///     unauthorisedMessageOriginator  [1] NULL OPTIONAL,
///     anonymousCallRejection         [2] NULL OPTIONAL }
/// ```
///
/// `unauthorisedMessageOriginator` is what an HLR returns when it refuses an MT
/// message from a service centre the subscriber has barred.
#[derive(Debug, Clone, Default, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct ExtensibleCallBarredParam {
    /// `barringServiceActive(0)`, `operatorBarring(1)`.
    pub call_barring_cause: Option<OpenEnumerated>,
    pub extension_container: Option<ExtensionContainer>,
    #[rasn(tag(context, 1))]
    pub unauthorised_message_originator: Option<()>,
    #[rasn(tag(context, 2))]
    pub anonymous_call_rejection: Option<()>,
}

/// `systemFailure` (34) — the extensible alternative of `SystemFailureParam`.
///
/// ```asn1
/// SystemFailureParam ::= CHOICE {
///     networkResource               NetworkResource,
///     extensibleSystemFailureParam  ExtensibleSystemFailureParam }
///
/// ExtensibleSystemFailureParam ::= SEQUENCE {
///     networkResource              NetworkResource OPTIONAL,
///     extensionContainer           ExtensionContainer OPTIONAL,
///     ...,
///     additionalNetworkResource [0] AdditionalNetworkResource OPTIONAL,
///     failureCauseParam         [1] FailureCauseParam OPTIONAL }
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct ExtensibleSystemFailureParam {
    /// `plmn(0)`, `hlr(1)`, `vlr(2)`, `pvlr(3)`, `controllingMSC(4)`,
    /// `vmsc(5)`, `eir(6)`, `rss(7)`.
    pub network_resource: Option<OpenEnumerated>,
    pub extension_container: Option<ExtensionContainer>,
    #[rasn(tag(context, 0))]
    pub additional_network_resource: Option<Integer>,
    #[rasn(tag(context, 1))]
    pub failure_cause_param: Option<Integer>,
}

/// `unexpectedDataValue` (36).
///
/// ```asn1
/// UnexpectedDataParam ::= SEQUENCE {
///     extensionContainer      ExtensionContainer OPTIONAL,
///     ...,
///     unexpectedSubscriber [0] NULL OPTIONAL }
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct UnexpectedDataParam {
    pub extension_container: Option<ExtensionContainer>,
    #[rasn(tag(context, 0))]
    pub unexpected_subscriber: Option<()>,
}

/// `busySubscriber` (45).
///
/// ```asn1
/// BusySubscriberParam ::= SEQUENCE {
///     extensionContainer ExtensionContainer OPTIONAL,
///     ...,
///     ccbs-Possible  [0] NULL OPTIONAL,
///     ccbs-Busy      [1] NULL OPTIONAL }
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct BusySubscriberParam {
    pub extension_container: Option<ExtensionContainer>,
    #[rasn(tag(context, 0))]
    pub ccbs_possible: Option<()>,
    #[rasn(tag(context, 1))]
    pub ccbs_busy: Option<()>,
}

/// `facilityNotSupported` (21).
///
/// ```asn1
/// FacilityNotSupParam ::= SEQUENCE {
///     extensionContainer                              ExtensionContainer OPTIONAL,
///     ...,
///     shapeOfLocationEstimateNotSupported         [0] NULL OPTIONAL,
///     neededLcsCapabilityNotSupportedInServingNode [1] NULL OPTIONAL }
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct FacilityNotSupParam {
    pub extension_container: Option<ExtensionContainer>,
    #[rasn(tag(context, 0))]
    pub shape_of_location_estimate_not_supported: Option<()>,
    #[rasn(tag(context, 1))]
    pub needed_lcs_capability_not_supported_in_serving_node: Option<()>,
}

/// `positionMethodFailure` (54).
///
/// ```asn1
/// PositionMethodFailure-Param ::= SEQUENCE {
///     positionMethodFailure-Diagnostic [0] PositionMethodFailure-Diagnostic OPTIONAL,
///     extensionContainer               [1] ExtensionContainer OPTIONAL,
///     ... }
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct PositionMethodFailureParam {
    #[rasn(tag(context, 0))]
    pub position_method_failure_diagnostic: Option<Integer>,
    #[rasn(tag(context, 1))]
    pub extension_container: Option<ExtensionContainer>,
}
