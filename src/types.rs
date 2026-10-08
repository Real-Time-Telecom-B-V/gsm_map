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

/// A constructed ASN.1 element this crate carries but does not interpret: a
/// `SEQUENCE`, a `SEQUENCE OF`, or the alternative inside an explicitly tagged
/// `CHOICE`.
///
/// What it holds depends on where it sits, as the tag does in BER:
///
/// * at a **tagged** position (`[n] SomeSequence`) it holds the *content* of
///   the element, the encodings of its members one after the other. The
///   element is always emitted constructed, and has to be constructed to be
///   accepted (X.690 8.9.1), with content that splits into well-formed
///   elements;
/// * at an **untagged** position, or behind an explicit tag, it holds the
///   *whole element* including its own identifier and length.
///
/// It is the wrong model for three things:
///
/// * a *primitive* member (`OCTET STRING`, `INTEGER`, `ENUMERATED`, `NULL`),
///   which must use its own Rust type;
/// * an *untagged optional* member, because an opaque value at an untagged
///   position has no tag to check against and swallows whatever comes next.
///   (An untagged **mandatory** member is fine: it is positional.)
///
/// `rasn::types::Any` is not a substitute at a tagged position: its encoder
/// takes the primitive / constructed bit from the first octet of the content,
/// so a SEQUENCE whose first member is primitive, which is most of them, goes
/// out with a primitive identifier, and an empty SEQUENCE is not emitted at
/// all.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Opaque(Any);

impl Opaque {
    /// Wrap the octets described on the type: the content of the element at
    /// a tagged position, the whole element at an untagged one.
    pub fn new(contents: Vec<u8>) -> Self {
        Self(Any::new(contents))
    }

    /// The octets carried.
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    /// The octets carried, by value.
    pub fn into_bytes(self) -> Vec<u8> {
        self.0.into_bytes()
    }
}

impl From<Vec<u8>> for Opaque {
    fn from(contents: Vec<u8>) -> Self {
        Self::new(contents)
    }
}

impl AsnType for Opaque {
    // As for an open type: no tag of its own.
    const TAG: Tag = Tag::EOC;
}

impl Encode for Opaque {
    fn encode_with_tag_and_constraints<'b, E: Encoder<'b>>(
        &self,
        encoder: &mut E,
        tag: Tag,
        _: Constraints,
        identifier: Identifier,
    ) -> Result<(), E::Error> {
        if tag == Tag::EOC {
            encoder.encode_any(tag, &self.0, identifier).map(drop)
        } else {
            // `[n]` constructed, around the content exactly as carried.
            encoder
                .encode_explicit_prefix(tag, &self.0, identifier)
                .map(drop)
        }
    }
}

impl Decode for Opaque {
    fn decode_with_tag_and_constraints<D: Decoder>(
        decoder: &mut D,
        tag: Tag,
        _: Constraints,
    ) -> Result<Self, D::Error> {
        if tag == Tag::EOC {
            return decoder.decode_any(tag).map(Self);
        }
        // Read as a SEQUENCE OF open types: the element has to be
        // constructed and every element inside it well formed.
        let members: Vec<Any> = decoder.decode_sequence_of(tag, Constraints::default())?;
        let mut contents = Vec::new();
        for member in &members {
            contents.extend_from_slice(member.as_bytes());
        }
        Ok(Self::new(contents))
    }
}

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

/// Define an extensible `ENUMERATED` as a Rust enum that keeps a value it
/// has no name for.
///
/// TS 29.002 clause 17.1.4: "An entity supporting a version greater than 1
/// shall not reject an unsupported extension following "..." of that SEQUENCE
/// or ENUMERATED data type." A closed Rust enum rejects it, and with it the
/// whole operation. What a receiver then *does* with the unknown value is laid
/// down type by type in the ASN.1 comments (discard it, map it onto a named
/// value, answer with `unexpectedDataValue`), so the value has to reach the
/// caller: it arrives as `Unrecognised`.
///
/// On the wire this is an ordinary ENUMERATED. `Unrecognised` holding the
/// number of a named value encodes as that value and decodes as the name.
macro_rules! extensible_enumerated {
    (
        $(#[$meta:meta])*
        pub enum $name:ident {
            $( $(#[$variant_meta:meta])* $variant:ident = $value:literal ),+ $(,)?
        }
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub enum $name {
            $( $(#[$variant_meta])* $variant, )+
            /// A value this crate has no name for: one added after the
            /// extension marker in a later release. Never constructed by the
            /// decoder for a value that has a name.
            Unrecognised(i64),
        }

        impl $name {
            /// The number on the wire.
            pub fn value(self) -> i64 {
                match self {
                    $( Self::$variant => $value, )+
                    Self::Unrecognised(value) => value,
                }
            }

            /// The named value for a number, or `Unrecognised`.
            pub fn from_value(value: i64) -> Self {
                match value {
                    $( $value => Self::$variant, )+
                    other => Self::Unrecognised(other),
                }
            }

            /// `false` for a value this crate has no name for.
            pub fn is_recognised(self) -> bool {
                !matches!(self.normalised(), Self::Unrecognised(_))
            }

            fn normalised(self) -> Self {
                Self::from_value(self.value())
            }
        }

        impl rasn::AsnType for $name {
            const TAG: rasn::types::Tag = rasn::types::Tag::ENUMERATED;
        }

        impl rasn::Encode for $name {
            fn encode_with_tag_and_constraints<'b, E: rasn::Encoder<'b>>(
                &self,
                encoder: &mut E,
                tag: rasn::types::Tag,
                constraints: rasn::types::Constraints,
                identifier: rasn::types::Identifier,
            ) -> Result<(), E::Error> {
                encoder
                    .encode_integer(tag, constraints, &self.value(), identifier)
                    .map(drop)
            }
        }

        impl rasn::Decode for $name {
            fn decode_with_tag_and_constraints<D: rasn::Decoder>(
                decoder: &mut D,
                tag: rasn::types::Tag,
                constraints: rasn::types::Constraints,
            ) -> Result<Self, D::Error> {
                decoder
                    .decode_integer::<i64>(tag, constraints)
                    .map(Self::from_value)
            }
        }
    };
}
pub(crate) use extensible_enumerated;

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
    pub private_extension_list: Option<Opaque>,
    #[rasn(tag(context, 1))]
    pub pcs_extensions: Option<Opaque>,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, PartialEq, Eq, AsnType, Decode, Encode)]
    struct Holder {
        #[rasn(tag(context, 3))]
        tagged: Option<Opaque>,
        #[rasn(tag(explicit(context, 4)))]
        choice: Option<Opaque>,
    }

    fn round_trip(value: &Holder, expected: &[u8]) {
        assert_eq!(crate::encode(value).unwrap(), expected);
        assert_eq!(&crate::decode::<Holder>(expected).unwrap(), value);
    }

    #[test]
    fn an_opaque_member_is_constructed_whatever_its_content_starts_with() {
        // Content starting with a primitive element, a constructed one, and
        // no content at all.
        for (content, expected) in [
            (
                vec![0x80, 0x01, 0x2a],
                vec![0x30, 0x05, 0xa3, 0x03, 0x80, 0x01, 0x2a],
            ),
            (vec![0x30, 0x00], vec![0x30, 0x04, 0xa3, 0x02, 0x30, 0x00]),
            (vec![], vec![0x30, 0x02, 0xa3, 0x00]),
        ] {
            let value = Holder {
                tagged: Some(Opaque::new(content)),
                choice: None,
            };
            round_trip(&value, &expected);
        }
    }

    #[test]
    fn an_opaque_member_keeps_several_elements_and_long_lengths() {
        // [0], then [1] holding 128 octets, which needs the long length form.
        let mut content = vec![0x80, 0x01, 0x01, 0xa1, 0x81, 0x80];
        for _ in 0..64 {
            content.extend_from_slice(&[0x05, 0x00]);
        }
        let value = Holder {
            tagged: Some(Opaque::new(content.clone())),
            choice: None,
        };
        let encoded = crate::encode(&value).unwrap();
        assert_eq!(&encoded[..6], [0x30, 0x81, 0x89, 0xa3, 0x81, 0x86]);
        let decoded = crate::decode::<Holder>(&encoded).unwrap();
        assert_eq!(decoded.tagged.unwrap().into_bytes(), content);
    }

    #[test]
    fn a_primitive_element_is_refused_for_an_opaque_member() {
        assert!(crate::decode::<Holder>(&[0x30, 0x05, 0x83, 0x03, 0x80, 0x01, 0x2a]).is_err());
        // Content that is not a run of well-formed elements.
        assert!(crate::decode::<Holder>(&[0x30, 0x05, 0xa3, 0x03, 0x80, 0x05, 0x2a]).is_err());
    }

    #[test]
    fn behind_an_explicit_tag_an_opaque_value_is_the_whole_element() {
        let value = Holder {
            tagged: None,
            choice: Some(Opaque::new(vec![0x81, 0x01, 0x07])),
        };
        round_trip(&value, &[0x30, 0x05, 0xa4, 0x03, 0x81, 0x01, 0x07]);
        // Two elements behind an explicit tag are one too many.
        assert!(crate::decode::<Holder>(&[
            0x30, 0x08, 0xa4, 0x06, 0x81, 0x01, 0x07, 0x82, 0x01, 0x08
        ])
        .is_err());
    }

    #[test]
    fn an_indefinite_length_opaque_member_is_carried_without_its_end_marker() {
        // a3 80 80 01 2a 00 00
        let wire = [
            0x30, 0x80, 0xa3, 0x80, 0x80, 0x01, 0x2a, 0x00, 0x00, 0x00, 0x00,
        ];
        let decoded = crate::decode::<Holder>(&wire).unwrap();
        assert_eq!(decoded.tagged.unwrap().as_bytes(), [0x80, 0x01, 0x2a]);
    }
}
