//! MAP Error codes — 3GPP TS 29.002 Section 17.6.
//!
//! Error codes returned in TCAP ReturnError components.

/// MAP Error Codes.
pub mod error_codes {
    // General errors
    pub const SYSTEM_FAILURE: i64 = 34;
    pub const DATA_MISSING: i64 = 35;
    pub const UNEXPECTED_DATA_VALUE: i64 = 36;
    pub const RESOURCE_LIMITATION: i64 = 51;
    pub const INITIATING_RELEASE: i64 = 20;
    pub const FACILITY_NOT_SUPPORTED: i64 = 21;
    pub const INCOMPATIBLE_TERMINAL: i64 = 28;

    // Identity / subscriber errors
    pub const UNKNOWN_SUBSCRIBER: i64 = 1;
    pub const UNKNOWN_MSC: i64 = 3;
    pub const UNIDENTIFIED_SUBSCRIBER: i64 = 5;
    pub const UNKNOWN_EQUIPMENT: i64 = 7;

    // Location errors
    pub const ROAMING_NOT_ALLOWED: i64 = 8;
    pub const ILLEGAL_SUBSCRIBER: i64 = 9;
    pub const ILLEGAL_EQUIPMENT: i64 = 12;
    pub const ABSENT_SUBSCRIBER: i64 = 27;

    // Call handling errors
    pub const BEARER_SERVICE_NOT_PROVISIONED: i64 = 10;
    pub const TELESERVICE_NOT_PROVISIONED: i64 = 11;
    pub const CALL_BARRED: i64 = 13;
    pub const FORWARDING_VIOLATION: i64 = 14;
    pub const CUG_REJECT: i64 = 15;
    pub const NUMBER_CHANGED: i64 = 44;
    pub const BUSY_SUBSCRIBER: i64 = 45;
    pub const NO_SUBSCRIBER_REPLY: i64 = 46;
    pub const OR_NOT_ALLOWED: i64 = 48;
    pub const NO_ROAMING_NUMBER_AVAILABLE: i64 = 39;

    // Supplementary service errors
    pub const SS_ERROR_STATUS: i64 = 17;
    pub const SS_INCOMPATIBILITY: i64 = 20;
    pub const SS_NOT_AVAILABLE: i64 = 18;
    pub const SS_SUBSCRIPTION_VIOLATION: i64 = 19;
    pub const NEGATIVE_PW_CHECK: i64 = 38;
    pub const PW_REGISTRATION_FAILURE: i64 = 37;
    pub const NUMBER_OF_PW_ATTEMPTS_VIOLATION: i64 = 43;
    pub const SHORT_TERM_DENIAL: i64 = 29;
    pub const LONG_TERM_DENIAL: i64 = 30;
    pub const USSD_BUSY: i64 = 72;

    // SMS errors
    pub const SM_DELIVERY_FAILURE: i64 = 32;
    pub const MESSAGE_WAITING_LIST_FULL: i64 = 33;
    pub const ABSENT_SUBSCRIBER_SM: i64 = 6;

    // Position errors
    pub const UNAUTHORIZED_REQUESTING_NETWORK: i64 = 52;
    pub const UNAUTHORIZED_LCS_CLIENT: i64 = 53;
    pub const POSITION_METHOD_FAILURE: i64 = 54;

    // Authentication errors
    pub const ATI_NOT_ALLOWED: i64 = 49;
    pub const NO_HANDOVER_NUMBER_AVAILABLE: i64 = 25;
    pub const SUBSEQUENT_HANDOVER_FAILURE: i64 = 26;
    pub const TARGET_CELL_OUTSIDE_GROUP_CALL_AREA: i64 = 42;
}

/// Get the name of a MAP error code.
pub fn error_name(code: i64) -> &'static str {
    match code {
        error_codes::SYSTEM_FAILURE => "systemFailure",
        error_codes::DATA_MISSING => "dataMissing",
        error_codes::UNEXPECTED_DATA_VALUE => "unexpectedDataValue",
        error_codes::RESOURCE_LIMITATION => "resourceLimitation",
        error_codes::FACILITY_NOT_SUPPORTED => "facilityNotSupported",
        error_codes::INCOMPATIBLE_TERMINAL => "incompatibleTerminal",
        error_codes::UNKNOWN_SUBSCRIBER => "unknownSubscriber",
        error_codes::UNKNOWN_MSC => "unknownMSC",
        error_codes::UNIDENTIFIED_SUBSCRIBER => "unidentifiedSubscriber",
        error_codes::UNKNOWN_EQUIPMENT => "unknownEquipment",
        error_codes::ROAMING_NOT_ALLOWED => "roamingNotAllowed",
        error_codes::ILLEGAL_SUBSCRIBER => "illegalSubscriber",
        error_codes::ILLEGAL_EQUIPMENT => "illegalEquipment",
        error_codes::ABSENT_SUBSCRIBER => "absentSubscriber",
        error_codes::BEARER_SERVICE_NOT_PROVISIONED => "bearerServiceNotProvisioned",
        error_codes::TELESERVICE_NOT_PROVISIONED => "teleserviceNotProvisioned",
        error_codes::CALL_BARRED => "callBarred",
        error_codes::FORWARDING_VIOLATION => "forwardingViolation",
        error_codes::CUG_REJECT => "cug-Reject",
        error_codes::NUMBER_CHANGED => "numberChanged",
        error_codes::BUSY_SUBSCRIBER => "busySubscriber",
        error_codes::NO_SUBSCRIBER_REPLY => "noSubscriberReply",
        error_codes::OR_NOT_ALLOWED => "or-NotAllowed",
        error_codes::NO_ROAMING_NUMBER_AVAILABLE => "noRoamingNumberAvailable",
        error_codes::SS_ERROR_STATUS => "ss-ErrorStatus",
        error_codes::SS_NOT_AVAILABLE => "ss-NotAvailable",
        error_codes::SS_SUBSCRIPTION_VIOLATION => "ss-SubscriptionViolation",
        error_codes::NEGATIVE_PW_CHECK => "negativePW-Check",
        error_codes::PW_REGISTRATION_FAILURE => "pw-RegistrationFailure",
        error_codes::NUMBER_OF_PW_ATTEMPTS_VIOLATION => "numberOfPW-AttemptsViolation",
        error_codes::SHORT_TERM_DENIAL => "shortTermDenial",
        error_codes::LONG_TERM_DENIAL => "longTermDenial",
        error_codes::USSD_BUSY => "ussd-Busy",
        error_codes::SM_DELIVERY_FAILURE => "sm-DeliveryFailure",
        error_codes::MESSAGE_WAITING_LIST_FULL => "messageWaitingListFull",
        error_codes::ABSENT_SUBSCRIBER_SM => "absentSubscriberSM",
        error_codes::UNAUTHORIZED_REQUESTING_NETWORK => "unauthorizedRequestingNetwork",
        error_codes::UNAUTHORIZED_LCS_CLIENT => "unauthorizedLCSClient",
        error_codes::POSITION_METHOD_FAILURE => "positionMethodFailure",
        error_codes::ATI_NOT_ALLOWED => "ati-NotAllowed",
        error_codes::NO_HANDOVER_NUMBER_AVAILABLE => "noHandoverNumberAvailable",
        error_codes::SUBSEQUENT_HANDOVER_FAILURE => "subsequentHandoverFailure",
        _ => "unknown",
    }
}
