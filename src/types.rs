use std::fmt;

use rasn::prelude::*;

/// IMSI — International Mobile Subscriber Identity.
/// Encoded as TBCD string in an OCTET STRING (3-8 bytes).
pub type Imsi = OctetString;

/// ISDN-AddressString — a phone number as an OCTET STRING: a leading octet
/// (ext bit, 3-bit nature of address, 4-bit numbering plan) then TBCD digits.
/// Build one from a digit string with [`crate::address`].
pub type IsdnAddressString = OctetString;

/// AddressString — same format as ISDN-AddressString.
pub type AddressString = OctetString;

/// LMSI — Local Mobile Subscriber Identity (4 bytes).
pub type Lmsi = OctetString;

/// SM-RP-DA — Short Message Relay Protocol Destination Address.
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
#[rasn(choice)]
pub enum SmRpDa {
    #[rasn(tag(context, 0))]
    Imsi(Imsi),
    #[rasn(tag(context, 1))]
    Lmsi(Lmsi),
    #[rasn(tag(context, 4))]
    ServiceCentreAddressDa(AddressString),
    #[rasn(tag(context, 5))]
    NoSmRpDa(()),
}

/// SM-RP-OA — Short Message Relay Protocol Originating Address.
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
#[rasn(choice)]
pub enum SmRpOa {
    #[rasn(tag(context, 2))]
    MsIsdn(IsdnAddressString),
    #[rasn(tag(context, 4))]
    ServiceCentreAddressOa(AddressString),
    #[rasn(tag(context, 5))]
    NoSmRpOa(()),
}

/// LocationInfoWithLMSI — returned by SRI-SM.
///
/// ```asn1
/// LocationInfoWithLMSI ::= SEQUENCE {
///     networkNode-Number  [1] ISDN-AddressString,
///     lmsi                LMSI OPTIONAL,
///     extensionContainer  ExtensionContainer OPTIONAL,
///     gprsNodeIndicator   [5] NULL OPTIONAL,
///     additional-Number   [6] Additional-Number OPTIONAL
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct LocationInfoWithLmsi {
    #[rasn(tag(context, 1))]
    pub network_node_number: IsdnAddressString,
    pub lmsi: Option<Lmsi>,
    #[rasn(tag(context, 5))]
    pub gprs_node_indicator: Option<()>,
    #[rasn(tag(context, 6))]
    pub additional_number: Option<IsdnAddressString>,
}

/// MAP Operation Codes — all groups.
pub mod op_codes {
    // SMS
    pub const SEND_ROUTING_INFO_FOR_SM: i64 = 45;
    pub const MO_FORWARD_SM: i64 = 46;
    pub const MT_FORWARD_SM: i64 = 44;
    pub const REPORT_SM_DELIVERY_STATUS: i64 = 47;
    pub const ALERT_SERVICE_CENTRE: i64 = 64;
    pub const INFORM_SERVICE_CENTRE: i64 = 63;
    pub const READY_FOR_SM: i64 = 66;

    // Location management
    pub const UPDATE_LOCATION: i64 = 2;
    pub const CANCEL_LOCATION: i64 = 3;
    pub const PURGE_MS: i64 = 67;
    pub const SEND_IDENTIFICATION: i64 = 55;

    // Authentication
    pub const SEND_AUTHENTICATION_INFO: i64 = 56;

    // Subscriber data
    pub const INSERT_SUBSCRIBER_DATA: i64 = 7;
    pub const DELETE_SUBSCRIBER_DATA: i64 = 8;

    // USSD
    pub const PROCESS_UNSTRUCTURED_SS_REQUEST: i64 = 59;
    pub const UNSTRUCTURED_SS_REQUEST: i64 = 60;
    pub const UNSTRUCTURED_SS_NOTIFY: i64 = 61;

    // Call handling
    pub const SEND_ROUTING_INFO: i64 = 22;
    pub const PROVIDE_ROAMING_NUMBER: i64 = 4;

    // Supplementary services
    pub const REGISTER_SS: i64 = 10;
    pub const ERASE_SS: i64 = 11;
    pub const ACTIVATE_SS: i64 = 12;
    pub const DEACTIVATE_SS: i64 = 13;
    pub const INTERROGATE_SS: i64 = 14;

    // Fault recovery
    pub const RESET: i64 = 37;
    pub const RESTORE_DATA: i64 = 57;
}

/// MAP operation name from operation code.
pub fn operation_name(op_code: i64) -> &'static str {
    match op_code {
        op_codes::SEND_ROUTING_INFO_FOR_SM => "sendRoutingInfoForSM",
        op_codes::MO_FORWARD_SM => "mo-ForwardSM",
        op_codes::MT_FORWARD_SM => "mt-ForwardSM",
        op_codes::REPORT_SM_DELIVERY_STATUS => "reportSM-DeliveryStatus",
        op_codes::ALERT_SERVICE_CENTRE => "alertServiceCentre",
        op_codes::INFORM_SERVICE_CENTRE => "informServiceCentre",
        op_codes::READY_FOR_SM => "readyForSM",
        op_codes::UPDATE_LOCATION => "updateLocation",
        op_codes::CANCEL_LOCATION => "cancelLocation",
        op_codes::PURGE_MS => "purgeMS",
        op_codes::SEND_IDENTIFICATION => "sendIdentification",
        op_codes::SEND_AUTHENTICATION_INFO => "sendAuthenticationInfo",
        op_codes::INSERT_SUBSCRIBER_DATA => "insertSubscriberData",
        op_codes::DELETE_SUBSCRIBER_DATA => "deleteSubscriberData",
        op_codes::PROCESS_UNSTRUCTURED_SS_REQUEST => "processUnstructuredSS-Request",
        op_codes::UNSTRUCTURED_SS_REQUEST => "unstructuredSS-Request",
        op_codes::UNSTRUCTURED_SS_NOTIFY => "unstructuredSS-Notify",
        op_codes::SEND_ROUTING_INFO => "sendRoutingInfo",
        op_codes::PROVIDE_ROAMING_NUMBER => "provideRoamingNumber",
        op_codes::REGISTER_SS => "registerSS",
        op_codes::ERASE_SS => "eraseSS",
        op_codes::ACTIVATE_SS => "activateSS",
        op_codes::DEACTIVATE_SS => "deactivateSS",
        op_codes::INTERROGATE_SS => "interrogateSS",
        op_codes::RESET => "reset",
        op_codes::RESTORE_DATA => "restoreData",
        _ => "unknown",
    }
}

impl fmt::Display for SmRpDa {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Imsi(imsi) => write!(f, "IMSI({})", hex::encode(imsi)),
            Self::Lmsi(lmsi) => write!(f, "LMSI({})", hex::encode(lmsi)),
            Self::ServiceCentreAddressDa(addr) => write!(f, "SC-Addr({})", hex::encode(addr)),
            Self::NoSmRpDa(()) => write!(f, "NoSmRpDa"),
        }
    }
}

impl fmt::Display for SmRpOa {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MsIsdn(msisdn) => write!(f, "MSISDN({})", hex::encode(msisdn)),
            Self::ServiceCentreAddressOa(addr) => write!(f, "SC-Addr({})", hex::encode(addr)),
            Self::NoSmRpOa(()) => write!(f, "NoSmRpOa"),
        }
    }
}
