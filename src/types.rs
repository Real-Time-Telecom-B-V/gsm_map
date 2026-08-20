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

/// An ASN.1 element this crate carries but does not interpret.
///
/// Modelling a member at all is what keeps the operation decodable: BER decoding
/// is not tolerant of unmodelled members, so a peer that sends one we skipped
/// makes the **whole operation** fail rather than just that member come back
/// empty.
///
/// Use it only for a **constructed** member at a context tag — a `SEQUENCE`,
/// a `SEQUENCE OF`, or an explicitly tagged `CHOICE`. Those round-trip byte for
/// byte. It is the wrong model elsewhere:
///
/// * a *primitive* member (`OCTET STRING`, `INTEGER`, `ENUMERATED`) must use its
///   own Rust type, because re-encoding an opaque value takes the
///   primitive/constructed bit from the first content byte and would flip it for
///   a value like `0x25`;
/// * a `NULL` member must be `Option<()>`, because an opaque value with empty
///   content re-encodes to nothing at all;
/// * an *untagged optional* member must be modelled properly, because an opaque
///   value at an untagged position has no tag to check against and swallows
///   whatever comes next. (An untagged **mandatory** member is fine: it is
///   positional, and the whole TLV including its tag is preserved.)
///
/// One documented limit: an uninterpreted constructed member that arrives
/// **empty** decodes without error but is dropped if the value is re-encoded.
pub type Opaque = Any;

/// An `ENUMERATED` this crate carries as an integer rather than a closed Rust
/// enum, because TS 29.002 keeps extending the type and a value added in a later
/// release must not make the whole operation undecodable.
///
/// The distinction matters at an **untagged** position, which most of these are:
/// there the universal tag *is* the type, and `ENUMERATED` is `0x0A` while
/// `INTEGER` is `0x02`. A plain `Integer` there produces bytes a peer walks
/// straight past. (At a context-tagged position the implicit tag replaces the
/// universal one, so either works — this type is still clearer.)
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
#[rasn(delegate, tag(universal, 10))]
pub struct OpenEnumerated(pub Integer);

impl From<i64> for OpenEnumerated {
    fn from(value: i64) -> Self {
        Self(value.into())
    }
}

/// SignalInfo — an opaque protocol payload, e.g. the SMS TPDU in `sm-RP-UI`.
pub type SignalInfo = OctetString;

/// Time — TS 29.002 MAP-CommonDataTypes, an encoded UTC timestamp.
pub type Time = OctetString;

/// AbsentSubscriberDiagnosticSM — `INTEGER (0..255)`, the TS 23.040 absent
/// reason the HLR/serving node recorded.
pub type AbsentSubscriberDiagnosticSm = Integer;

/// DiameterIdentity — `OCTET STRING (SIZE(9..255))`, a Diameter Name or Realm
/// whose content is a DiameterIdentity per RFC 6733 (TS 29.002
/// MAP-CommonDataTypes).
pub type DiameterIdentity = OctetString;

/// ExtensionContainer — TS 29.002 MAP-ExtensionDataTypes.
///
/// ```asn1
/// ExtensionContainer ::= SEQUENCE {
///     privateExtensionList  [0] PrivateExtensionList OPTIONAL,
///     pcs-Extensions        [1] PCS-Extensions OPTIONAL,
///     ... }
/// ```
///
/// Both members are carried **opaquely** — the crate never generates private
/// extensions and does not interpret an inbound one. Modelling the container at
/// all is what matters: BER decoding is not tolerant of unmodelled members, so
/// a peer that sends an `extensionContainer` we have not modelled makes the
/// **whole operation** fail to decode, not just that member.
#[derive(Debug, Clone, Default, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct ExtensionContainer {
    #[rasn(tag(context, 0))]
    pub private_extension_list: Option<Any>,
    #[rasn(tag(context, 1))]
    pub pcs_extensions: Option<Any>,
}

/// NetworkNodeDiameterAddress — TS 29.002 MAP-CommonDataTypes.
///
/// ```asn1
/// NetworkNodeDiameterAddress ::= SEQUENCE {
///     diameter-Name   [0] DiameterIdentity,
///     diameter-Realm  [1] DiameterIdentity }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct NetworkNodeDiameterAddress {
    #[rasn(tag(context, 0))]
    pub diameter_name: DiameterIdentity,
    #[rasn(tag(context, 1))]
    pub diameter_realm: DiameterIdentity,
}

/// CorrelationID — ties a MAP SMS operation to the IMS leg that triggered it.
///
/// ```asn1
/// CorrelationID ::= SEQUENCE {
///     hlr-id     [0] HLR-Id OPTIONAL,
///     sip-uri-A  [1] SIP-URI OPTIONAL,
///     sip-uri-B  [2] SIP-URI }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct CorrelationId {
    #[rasn(tag(context, 0))]
    pub hlr_id: Option<OctetString>,
    #[rasn(tag(context, 1))]
    pub sip_uri_a: Option<OctetString>,
    #[rasn(tag(context, 2))]
    pub sip_uri_b: OctetString,
}

/// MW-Status — the message-waiting flags informServiceCentre carries.
///
/// ```asn1
/// MW-Status ::= BIT STRING {
///     sc-AddressNotIncluded (0),
///     mnrf-Set              (1),
///     mcef-Set              (2),
///     mnrg-Set              (3),
///     mnr5g-Set             (4),
///     mnr5gn3g-Set          (5) } (SIZE (6..16))
/// ```
///
/// A **BIT STRING**, numbered from the most significant bit of the first octet.
/// Build one with [`MwStatusFlags::to_bits`] rather than packing a byte by hand.
pub type MwStatus = BitString;

/// The [`MwStatus`] bits as named booleans.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MwStatusFlags {
    /// The service-centre address is not included in the MWD.
    pub sc_address_not_included: bool,
    /// Mobile Not Reachable Flag.
    pub mnrf_set: bool,
    /// Memory Capacity Exceeded Flag.
    pub mcef_set: bool,
    /// Mobile Not Reachable for GPRS.
    pub mnrg_set: bool,
    /// Mobile Not Reachable for 5G.
    pub mnr5g_set: bool,
    /// Mobile Not Reachable for non-3GPP access to 5G.
    pub mnr5gn3g_set: bool,
}

impl MwStatusFlags {
    /// Encode as the six-bit `MW-Status` BIT STRING the ASN.1 requires.
    pub fn to_bits(self) -> MwStatus {
        let mut bits = MwStatus::new();
        for flag in [
            self.sc_address_not_included,
            self.mnrf_set,
            self.mcef_set,
            self.mnrg_set,
            self.mnr5g_set,
            self.mnr5gn3g_set,
        ] {
            bits.push(flag);
        }
        bits
    }

    /// Read the flags back. Bits beyond the six named ones are ignored, and a
    /// BIT STRING shorter than six bits reads the missing ones as `false`.
    pub fn from_bits(bits: &MwStatus) -> Self {
        let at = |i: usize| bits.get(i).map(|b| *b).unwrap_or(false);
        Self {
            sc_address_not_included: at(0),
            mnrf_set: at(1),
            mcef_set: at(2),
            mnrg_set: at(3),
            mnr5g_set: at(4),
            mnr5gn3g_set: at(5),
        }
    }
}

/// Additional-Number — the second serving node returned by SRI-SM.
///
/// ```asn1
/// Additional-Number ::= CHOICE {
///     msc-Number   [0] ISDN-AddressString,
///     sgsn-Number  [1] ISDN-AddressString }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
#[rasn(choice)]
pub enum AdditionalNumber {
    #[rasn(tag(context, 0))]
    MscNumber(IsdnAddressString),
    #[rasn(tag(context, 1))]
    SgsnNumber(IsdnAddressString),
}

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

/// LocationInfoWithLMSI — the serving node(s) returned by SRI-SM.
///
/// ```asn1
/// LocationInfoWithLMSI ::= SEQUENCE {
///     networkNode-Number                   [1] ISDN-AddressString,
///     lmsi                                     LMSI OPTIONAL,
///     extensionContainer                       ExtensionContainer OPTIONAL,
///     ...,
///     gprsNodeIndicator                    [5] NULL OPTIONAL,
///     additional-Number                    [6] Additional-Number OPTIONAL,
///     networkNodeDiameterAddress           [7] NetworkNodeDiameterAddress OPTIONAL,
///     additionalNetworkNodeDiameterAddress [8] NetworkNodeDiameterAddress OPTIONAL,
///     thirdNumber                          [9] Additional-Number OPTIONAL,
///     thirdNetworkNodeDiameterAddress     [10] NetworkNodeDiameterAddress OPTIONAL,
///     imsNodeIndicator                    [11] NULL OPTIONAL,
///     smsf-3gpp-Number                    [12] ISDN-AddressString OPTIONAL,
///     smsf-3gpp-DiameterAddress           [13] NetworkNodeDiameterAddress OPTIONAL,
///     smsf-non-3gpp-Number                [14] ISDN-AddressString OPTIONAL,
///     smsf-non-3gpp-DiameterAddress       [15] NetworkNodeDiameterAddress OPTIONAL,
///     smsf-3gpp-address-indicator         [16] NULL OPTIONAL,
///     smsf-non-3gpp-address-indicator     [17] NULL OPTIONAL }
/// ```
///
/// Every member the Rel-18 type defines is modelled, including the ones this
/// crate has no use for: an HLR that sends one we skipped would make the whole
/// `RoutingInfoForSM-Res` fail to decode.
///
/// `additional-Number` and `thirdNumber` are CHOICEs, so TS 29.002's
/// `IMPLICIT TAGS` does not apply to them and `[6]` / `[9]` are **explicit**.
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct LocationInfoWithLmsi {
    #[rasn(tag(context, 1))]
    pub network_node_number: IsdnAddressString,
    pub lmsi: Option<Lmsi>,
    pub extension_container: Option<ExtensionContainer>,
    #[rasn(tag(context, 5))]
    pub gprs_node_indicator: Option<()>,
    #[rasn(tag(explicit(context, 6)))]
    pub additional_number: Option<AdditionalNumber>,
    #[rasn(tag(context, 7))]
    pub network_node_diameter_address: Option<NetworkNodeDiameterAddress>,
    #[rasn(tag(context, 8))]
    pub additional_network_node_diameter_address: Option<NetworkNodeDiameterAddress>,
    #[rasn(tag(explicit(context, 9)))]
    pub third_number: Option<AdditionalNumber>,
    #[rasn(tag(context, 10))]
    pub third_network_node_diameter_address: Option<NetworkNodeDiameterAddress>,
    #[rasn(tag(context, 11))]
    pub ims_node_indicator: Option<()>,
    #[rasn(tag(context, 12))]
    pub smsf_3gpp_number: Option<IsdnAddressString>,
    #[rasn(tag(context, 13))]
    pub smsf_3gpp_diameter_address: Option<NetworkNodeDiameterAddress>,
    #[rasn(tag(context, 14))]
    pub smsf_non_3gpp_number: Option<IsdnAddressString>,
    #[rasn(tag(context, 15))]
    pub smsf_non_3gpp_diameter_address: Option<NetworkNodeDiameterAddress>,
    #[rasn(tag(context, 16))]
    pub smsf_3gpp_address_indicator: Option<()>,
    #[rasn(tag(context, 17))]
    pub smsf_non_3gpp_address_indicator: Option<()>,
}

impl LocationInfoWithLmsi {
    /// The one mandatory member; every optional member starts `None`.
    ///
    /// Use functional-record-update for the rest:
    /// `LocationInfoWithLmsi { lmsi: Some(l), ..LocationInfoWithLmsi::new(n) }`.
    pub fn new(network_node_number: IsdnAddressString) -> Self {
        Self {
            network_node_number,
            lmsi: None,
            extension_container: None,
            gprs_node_indicator: None,
            additional_number: None,
            network_node_diameter_address: None,
            additional_network_node_diameter_address: None,
            third_number: None,
            third_network_node_diameter_address: None,
            ims_node_indicator: None,
            smsf_3gpp_number: None,
            smsf_3gpp_diameter_address: None,
            smsf_non_3gpp_number: None,
            smsf_non_3gpp_diameter_address: None,
            smsf_3gpp_address_indicator: None,
            smsf_non_3gpp_address_indicator: None,
        }
    }
}

/// Define the operation-code constants and the name lookup from one list, so a
/// code cannot exist without a name — `operation_name` returning `"unknown"` for
/// one of `op_codes`' own constants is the bug this shape prevents.
macro_rules! operation_registry {
    ($( $(#[$meta:meta])* $konst:ident = $code:literal => $name:literal ),* $(,)?) => {
        /// MAP operation codes — every group this crate models.
        ///
        /// Each `operations::*::op_codes` module re-exports its own group's
        /// codes from here rather than repeating the numbers.
        pub mod op_codes {
            $( $(#[$meta])* pub const $konst: i64 = $code; )*
        }

        /// The MAP operation name for an operation code.
        ///
        /// Every constant in [`op_codes`] resolves; anything else is
        /// `"unknown"`.
        pub fn operation_name(op_code: i64) -> &'static str {
            match op_code {
                $( op_codes::$konst => $name, )*
                _ => "unknown",
            }
        }

        /// Every `(code, name)` pair this crate knows, for tests and for a
        /// caller that wants to enumerate the registry.
        pub const OPERATION_REGISTRY: &[(i64, &str)] = &[
            $( (op_codes::$konst, $name), )*
        ];
    };
}

operation_registry! {
    // Short message service
    SEND_ROUTING_INFO_FOR_SM = 45 => "sendRoutingInfoForSM",
    MO_FORWARD_SM = 46 => "mo-forwardSM",
    MT_FORWARD_SM = 44 => "mt-forwardSM",
    MT_FORWARD_SM_VGCS = 21 => "mt-ForwardSM-VGCS",
    REPORT_SM_DELIVERY_STATUS = 47 => "reportSM-DeliveryStatus",
    ALERT_SERVICE_CENTRE = 64 => "alertServiceCentre",
    ALERT_SERVICE_CENTRE_WITHOUT_RESULT = 49 => "alertServiceCentreWithoutResult",
    INFORM_SERVICE_CENTRE = 63 => "informServiceCentre",
    READY_FOR_SM = 66 => "readyForSM",

    // Location management
    UPDATE_LOCATION = 2 => "updateLocation",
    CANCEL_LOCATION = 3 => "cancelLocation",
    PURGE_MS = 67 => "purgeMS",
    SEND_IDENTIFICATION = 55 => "sendIdentification",
    UPDATE_VCSG_LOCATION = 53 => "updateVcsgLocation",
    CANCEL_VCSG_LOCATION = 36 => "cancelVcsgLocation",
    /// v1 only; TS 29.002 dropped it and no argument type is defined any more.
    NOTE_SUBSCRIBER_PRESENT = 48 => "noteSubscriberPresent",

    // Authentication
    SEND_AUTHENTICATION_INFO = 56 => "sendAuthenticationInfo",
    AUTHENTICATION_FAILURE_REPORT = 15 => "authenticationFailureReport",
    /// v1 only.
    SEND_PARAMETERS = 9 => "sendParameters",

    // Subscriber data
    INSERT_SUBSCRIBER_DATA = 7 => "insertSubscriberData",
    DELETE_SUBSCRIBER_DATA = 8 => "deleteSubscriberData",
    NOTE_SUBSCRIBER_DATA_MODIFIED = 5 => "noteSubscriberDataModified",

    // Subscriber information / any-time
    ANY_TIME_MODIFICATION = 65 => "anyTimeModification",
    PROVIDE_SUBSCRIBER_INFO = 70 => "provideSubscriberInfo",
    ANY_TIME_INTERROGATION = 71 => "anyTimeInterrogation",
    ANY_TIME_SUBSCRIPTION_INTERROGATION = 62 => "anyTimeSubscriptionInterrogation",
    NOTE_MM_EVENT = 89 => "noteMM-Event",

    // USSD
    PROCESS_UNSTRUCTURED_SS_REQUEST = 59 => "processUnstructuredSS-Request",
    UNSTRUCTURED_SS_REQUEST = 60 => "unstructuredSS-Request",
    UNSTRUCTURED_SS_NOTIFY = 61 => "unstructuredSS-Notify",
    /// v1 only.
    PROCESS_UNSTRUCTURED_SS_DATA = 19 => "processUnstructuredSS-Data",

    // Call handling
    SEND_ROUTING_INFO = 22 => "sendRoutingInfo",
    PROVIDE_ROAMING_NUMBER = 4 => "provideRoamingNumber",
    RESUME_CALL_HANDLING = 6 => "resumeCallHandling",
    RELEASE_RESOURCES = 20 => "releaseResources",
    SET_REPORTING_STATE = 73 => "setReportingState",
    STATUS_REPORT = 74 => "statusReport",
    REMOTE_USER_FREE = 75 => "remoteUserFree",
    IST_ALERT = 87 => "ist-Alert",
    IST_COMMAND = 88 => "ist-Command",

    // Supplementary services
    REGISTER_SS = 10 => "registerSS",
    ERASE_SS = 11 => "eraseSS",
    ACTIVATE_SS = 12 => "activateSS",
    DEACTIVATE_SS = 13 => "deactivateSS",
    INTERROGATE_SS = 14 => "interrogateSS",
    NOTIFY_SS = 16 => "notifySS",
    SS_INVOCATION_NOTIFICATION = 72 => "ss-InvocationNotification",
    REGISTER_CC_ENTRY = 76 => "registerCC-Entry",
    ERASE_CC_ENTRY = 77 => "eraseCC-Entry",
    ACCESS_REGISTER_CC_ENTRY = 119 => "accessRegisterCCEntry",
    CALL_DEFLECTION = 117 => "callDeflection",
    USER_USER_SERVICE = 118 => "userUserService",
    /// v1 only.
    REGISTER_PASSWORD = 17 => "registerPassword",
    /// v1 only.
    GET_PASSWORD = 18 => "getPassword",
    /// v1 only.
    FORWARD_CHECK_SS = 38 => "forwardCheckSS",

    // Fault recovery
    RESET = 37 => "reset",
    RESTORE_DATA = 57 => "restoreData",

    // GPRS location management
    UPDATE_GPRS_LOCATION = 23 => "updateGprsLocation",
    SEND_ROUTING_INFO_FOR_GPRS = 24 => "sendRoutingInfoForGprs",
    FAILURE_REPORT = 25 => "failureReport",
    NOTE_MS_PRESENT_FOR_GPRS = 26 => "noteMsPresentForGprs",

    // Handover
    PREPARE_HANDOVER = 68 => "prepareHandover",
    SEND_END_SIGNAL = 29 => "sendEndSignal",
    PROCESS_ACCESS_SIGNALLING = 33 => "processAccessSignalling",
    FORWARD_ACCESS_SIGNALLING = 34 => "forwardAccessSignalling",
    PREPARE_SUBSEQUENT_HANDOVER = 69 => "prepareSubsequentHandover",
    /// v1 only.
    PERFORM_HANDOVER = 28 => "performHandover",
    /// v1 only.
    PERFORM_SUBSEQUENT_HANDOVER = 30 => "performSubsequentHandover",
    /// v1 only.
    NOTE_INTERNAL_HANDOVER = 35 => "noteInternalHandover",

    // Group call (VGCS / VBS)
    PREPARE_GROUP_CALL = 39 => "prepareGroupCall",
    SEND_GROUP_CALL_END_SIGNAL = 40 => "sendGroupCallEndSignal",
    PROCESS_GROUP_CALL_SIGNALLING = 41 => "processGroupCallSignalling",
    FORWARD_GROUP_CALL_SIGNALLING = 42 => "forwardGroupCallSignalling",
    SEND_GROUP_CALL_INFO = 84 => "sendGroupCallInfo",

    // Equipment identity
    CHECK_IMEI = 43 => "checkIMEI",

    // Operation and maintenance
    ACTIVATE_TRACE_MODE = 50 => "activateTraceMode",
    DEACTIVATE_TRACE_MODE = 51 => "deactivateTraceMode",
    SEND_IMSI = 58 => "sendIMSI",
    /// v1 only.
    TRACE_SUBSCRIBER_ACTIVITY = 52 => "traceSubscriberActivity",
    /// v1 only.
    BEGIN_SUBSCRIBER_ACTIVITY = 54 => "beginSubscriberActivity",

    // Location services (LCS)
    PROVIDE_SUBSCRIBER_LOCATION = 83 => "provideSubscriberLocation",
    SEND_ROUTING_INFO_FOR_LCS = 85 => "sendRoutingInfoForLCS",
    SUBSCRIBER_LOCATION_REPORT = 86 => "subscriberLocationReport",
    LCS_PERIODIC_LOCATION_CANCELLATION = 109 => "lcs-PeriodicLocationCancellation",
    LCS_LOCATION_UPDATE = 110 => "lcs-LocationUpdate",
    LCS_PERIODIC_LOCATION_REQUEST = 111 => "lcs-PeriodicLocationRequest",
    LCS_AREA_EVENT_CANCELLATION = 112 => "lcs-AreaEventCancellation",
    LCS_AREA_EVENT_REPORT = 113 => "lcs-AreaEventReport",
    LCS_AREA_EVENT_REQUEST = 114 => "lcs-AreaEventRequest",
    LCS_MOLR = 115 => "lcs-MOLR",
    LCS_LOCATION_NOTIFICATION = 116 => "lcs-LocationNotification",

    // Secure transport (TS 29.002 clause 7.6.13)
    SECURE_TRANSPORT_CLASS1 = 78 => "secureTransportClass1",
    SECURE_TRANSPORT_CLASS2 = 79 => "secureTransportClass2",
    SECURE_TRANSPORT_CLASS3 = 80 => "secureTransportClass3",
    SECURE_TRANSPORT_CLASS4 = 81 => "secureTransportClass4",

    // SIWFS (v3, rarely deployed)
    PROVIDE_SIWFS_NUMBER = 31 => "provideSIWFSNumber",
    SIWFS_SIGNALLING_MODIFY = 32 => "sIWFSSignallingModify",
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
