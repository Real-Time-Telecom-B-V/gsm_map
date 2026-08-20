//! Voice Group Call and Voice Broadcast Call operations — 3GPP TS 29.002.
//!
//! - prepareGroupCall (op 39)
//! - sendGroupCallEndSignal (op 40)
//! - processGroupCallSignalling (op 41)
//! - forwardGroupCallSignalling (op 42)
//! - sendGroupCallInfo (op 84)
//!
//! Every member TS 29.002 defines is modelled; see [`crate`] on why an
//! unmodelled member is fatal rather than merely absent.

use rasn::prelude::*;

use crate::types::{ExtensionContainer, Imsi, IsdnAddressString, Opaque};

/// PrepareGroupCall-Arg (op 39).
///
/// ```asn1
/// PrepareGroupCallArg ::= SEQUENCE {
///     teleservice                  TeleserviceCode,
///     asciCallReference            ASCI-CallReference,
///     codec-Info                   CODEC-Info,
///     cipheringAlgorithm           CipheringAlgorithm,
///     groupKeyNumber-Vk-Id     [0] GroupKeyNumber OPTIONAL,
///     groupKey                 [1] Kc OPTIONAL,
///     priority                 [2] EMLPP-Priority OPTIONAL,
///     uplinkFree               [3] NULL OPTIONAL,
///     extensionContainer       [4] ExtensionContainer OPTIONAL,
///     ...,
///     vstk                     [5] VSTK OPTIONAL,
///     vstk-rand                [6] VSTK-RAND OPTIONAL,
///     talkerChannelParameter   [7] NULL OPTIONAL,
///     uplinkReplyIndicator     [8] NULL OPTIONAL }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct PrepareGroupCallArg {
    pub teleservice: OctetString,
    pub asci_call_reference: OctetString,
    pub codec_info: OctetString,
    pub ciphering_algorithm: OctetString,
    #[rasn(tag(context, 0))]
    pub group_key_number_vk_id: Option<Integer>,
    #[rasn(tag(context, 1))]
    pub group_key: Option<OctetString>,
    #[rasn(tag(context, 2))]
    pub priority: Option<Integer>,
    #[rasn(tag(context, 3))]
    pub uplink_free: Option<()>,
    #[rasn(tag(context, 4))]
    pub extension_container: Option<ExtensionContainer>,
    #[rasn(tag(context, 5))]
    pub vstk: Option<OctetString>,
    #[rasn(tag(context, 6))]
    pub vstk_rand: Option<BitString>,
    #[rasn(tag(context, 7))]
    pub talker_channel_parameter: Option<()>,
    #[rasn(tag(context, 8))]
    pub uplink_reply_indicator: Option<()>,
}

impl PrepareGroupCallArg {
    /// The four mandatory members; every optional member starts `None`.
    pub fn new(
        teleservice: OctetString,
        asci_call_reference: OctetString,
        codec_info: OctetString,
        ciphering_algorithm: OctetString,
    ) -> Self {
        Self {
            teleservice,
            asci_call_reference,
            codec_info,
            ciphering_algorithm,
            group_key_number_vk_id: None,
            group_key: None,
            priority: None,
            uplink_free: None,
            extension_container: None,
            vstk: None,
            vstk_rand: None,
            talker_channel_parameter: None,
            uplink_reply_indicator: None,
        }
    }
}

/// PrepareGroupCall-Res (op 39).
///
/// ```asn1
/// PrepareGroupCallRes ::= SEQUENCE {
///     groupCallNumber     ISDN-AddressString,
///     extensionContainer  ExtensionContainer OPTIONAL,
///     ... }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct PrepareGroupCallRes {
    pub group_call_number: IsdnAddressString,
    pub extension_container: Option<ExtensionContainer>,
}

/// SendGroupCallEndSignal-Arg (op 40).
///
/// ```asn1
/// SendGroupCallEndSignalArg ::= SEQUENCE {
///     imsi                    IMSI OPTIONAL,
///     extensionContainer      ExtensionContainer OPTIONAL,
///     ...,
///     talkerPriority      [0] TalkerPriority OPTIONAL,
///     additionalInfo      [1] AdditionalInfo OPTIONAL }
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct SendGroupCallEndSignalArg {
    pub imsi: Option<Imsi>,
    pub extension_container: Option<ExtensionContainer>,
    /// `TalkerPriority ::= ENUMERATED { normal(0), privileged(1), emergency(2) }`.
    #[rasn(tag(context, 0))]
    pub talker_priority: Option<Integer>,
    #[rasn(tag(context, 1))]
    pub additional_info: Option<BitString>,
}

/// SendGroupCallEndSignal-Res (op 40).
#[derive(Debug, Clone, Default, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct SendGroupCallEndSignalRes {
    pub extension_container: Option<ExtensionContainer>,
}

/// ProcessGroupCallSignalling-Arg (op 41). The operation has no result.
///
/// ```asn1
/// ProcessGroupCallSignallingArg ::= SEQUENCE {
///     extensionContainer                ExtensionContainer OPTIONAL,
///     ...,
///     uplinkRequest                 [0] NULL OPTIONAL,
///     uplinkReleaseIndication       [1] NULL OPTIONAL,
///     releaseGroupCall              [2] NULL OPTIONAL,
///     talkerPriority                [3] TalkerPriority OPTIONAL,
///     additionalInfo                [4] AdditionalInfo OPTIONAL,
///     emergencyModeResetCommandFlag [5] NULL OPTIONAL,
///     an-APDU                       [6] AccessNetworkSignalInfo OPTIONAL }
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct ProcessGroupCallSignallingArg {
    #[rasn(tag(context, 0))]
    pub uplink_request: Option<()>,
    #[rasn(tag(context, 1))]
    pub uplink_release_indication: Option<()>,
    #[rasn(tag(context, 2))]
    pub release_group_call: Option<()>,
    /// Declared after `[2]`, and BER encodes in declaration order.
    pub extension_container: Option<ExtensionContainer>,
    #[rasn(tag(context, 3))]
    pub talker_priority: Option<Integer>,
    #[rasn(tag(context, 4))]
    pub additional_info: Option<BitString>,
    #[rasn(tag(context, 5))]
    pub emergency_mode_reset_command_flag: Option<()>,
    #[rasn(tag(context, 6))]
    pub an_apdu: Option<Opaque>,
}

/// ForwardGroupCallSignalling-Arg (op 42). The operation has no result.
///
/// ```asn1
/// ForwardGroupCallSignallingArg ::= SEQUENCE {
///     imsi                              IMSI OPTIONAL,
///     extensionContainer                ExtensionContainer OPTIONAL,
///     ...,
///     uplinkRequestAck              [0] NULL OPTIONAL,
///     uplinkReleaseIndication       [1] NULL OPTIONAL,
///     uplinkRejectCommand           [2] NULL OPTIONAL,
///     uplinkSeizedCommand           [3] NULL OPTIONAL,
///     uplinkReleaseCommand          [4] NULL OPTIONAL,
///     stateAttributes               [5] StateAttributes OPTIONAL,
///     talkerPriority                [6] TalkerPriority OPTIONAL,
///     additionalInfo                [7] AdditionalInfo OPTIONAL,
///     emergencyModeResetCommandFlag [8] NULL OPTIONAL,
///     sm-RP-UI                      [9] SignalInfo OPTIONAL,
///     an-APDU                      [10] AccessNetworkSignalInfo OPTIONAL }
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct ForwardGroupCallSignallingArg {
    pub imsi: Option<Imsi>,
    #[rasn(tag(context, 0))]
    pub uplink_request_ack: Option<()>,
    #[rasn(tag(context, 1))]
    pub uplink_release_indication: Option<()>,
    #[rasn(tag(context, 2))]
    pub uplink_reject_command: Option<()>,
    #[rasn(tag(context, 3))]
    pub uplink_seized_command: Option<()>,
    #[rasn(tag(context, 4))]
    pub uplink_release_command: Option<()>,
    /// Declared after `[4]`, and BER encodes in declaration order.
    pub extension_container: Option<ExtensionContainer>,
    #[rasn(tag(context, 5))]
    pub state_attributes: Option<Opaque>,
    #[rasn(tag(context, 6))]
    pub talker_priority: Option<Integer>,
    #[rasn(tag(context, 7))]
    pub additional_info: Option<BitString>,
    #[rasn(tag(context, 8))]
    pub emergency_mode_reset_command_flag: Option<()>,
    #[rasn(tag(context, 9))]
    pub sm_rp_ui: Option<OctetString>,
    #[rasn(tag(context, 10))]
    pub an_apdu: Option<Opaque>,
}

/// SendGroupCallInfo-Arg (op 84).
///
/// ```asn1
/// SendGroupCallInfoArg ::= SEQUENCE {
///     requestedInfo           RequestedInfoForASCI,
///     groupId                 Long-GroupId,
///     teleservice             Ext-TeleserviceCode,
///     cellId              [0] GlobalCellId OPTIONAL,
///     imsi                [1] IMSI OPTIONAL,
///     tmsi                [2] TMSI OPTIONAL,
///     additionalInfo      [3] AdditionalInfo OPTIONAL,
///     talkerPriority      [4] TalkerPriority OPTIONAL,
///     cksn                [5] Cksn OPTIONAL,
///     extensionContainer  [6] ExtensionContainer OPTIONAL,
///     ... }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct SendGroupCallInfoArg {
    /// `RequestedInfoForASCI ::= ENUMERATED { anchorMSC-AddressAndASCI-CallReference(0),
    /// imsiAndAdditionalInfoAndAdditionalSubscription(1) }` — untagged, so it
    /// carries the ENUMERATED universal tag.
    pub requested_info: crate::types::OpenEnumerated,
    pub group_id: OctetString,
    pub teleservice: OctetString,
    #[rasn(tag(context, 0))]
    pub cell_id: Option<OctetString>,
    #[rasn(tag(context, 1))]
    pub imsi: Option<Imsi>,
    #[rasn(tag(context, 2))]
    pub tmsi: Option<OctetString>,
    #[rasn(tag(context, 3))]
    pub additional_info: Option<BitString>,
    #[rasn(tag(context, 4))]
    pub talker_priority: Option<Integer>,
    #[rasn(tag(context, 5))]
    pub cksn: Option<OctetString>,
    #[rasn(tag(context, 6))]
    pub extension_container: Option<ExtensionContainer>,
}

impl SendGroupCallInfoArg {
    /// The three mandatory members; every optional member starts `None`.
    pub fn new(
        requested_info: crate::types::OpenEnumerated,
        group_id: OctetString,
        teleservice: OctetString,
    ) -> Self {
        Self {
            requested_info,
            group_id,
            teleservice,
            cell_id: None,
            imsi: None,
            tmsi: None,
            additional_info: None,
            talker_priority: None,
            cksn: None,
            extension_container: None,
        }
    }
}

/// SendGroupCallInfo-Res (op 84).
///
/// ```asn1
/// SendGroupCallInfoRes ::= SEQUENCE {
///     anchorMSC-Address        [0] ISDN-AddressString OPTIONAL,
///     asciCallReference        [1] ASCI-CallReference OPTIONAL,
///     imsi                     [2] IMSI OPTIONAL,
///     additionalInfo           [3] AdditionalInfo OPTIONAL,
///     additionalSubscriptions  [4] AdditionalSubscriptions OPTIONAL,
///     kc                       [5] Kc OPTIONAL,
///     extensionContainer       [6] ExtensionContainer OPTIONAL,
///     ... }
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct SendGroupCallInfoRes {
    #[rasn(tag(context, 0))]
    pub anchor_msc_address: Option<IsdnAddressString>,
    #[rasn(tag(context, 1))]
    pub asci_call_reference: Option<OctetString>,
    #[rasn(tag(context, 2))]
    pub imsi: Option<Imsi>,
    #[rasn(tag(context, 3))]
    pub additional_info: Option<BitString>,
    #[rasn(tag(context, 4))]
    pub additional_subscriptions: Option<BitString>,
    #[rasn(tag(context, 5))]
    pub kc: Option<OctetString>,
    #[rasn(tag(context, 6))]
    pub extension_container: Option<ExtensionContainer>,
}

/// Operation codes for group call. Re-exported from [`crate::types::op_codes`].
pub mod op_codes {
    pub use crate::types::op_codes::{
        FORWARD_GROUP_CALL_SIGNALLING, PREPARE_GROUP_CALL, PROCESS_GROUP_CALL_SIGNALLING,
        SEND_GROUP_CALL_END_SIGNAL, SEND_GROUP_CALL_INFO,
    };
}
