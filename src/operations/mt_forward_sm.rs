//! mt-ForwardSM (operation code 44) — 3GPP TS 29.002.
//!
//! Mobile-terminated SMS forwarding from the SMS-GMSC to the serving MSC/SGSN,
//! or to a registered IP-SM-GW. Also carries `mt-ForwardSM-VGCS` (op 21), the
//! voice-group-call form.
//!
//! Every member TS 29.002 (Rel-18) defines is modelled, so what an SMS-GMSC
//! sends, `smsOverIP-OnlyIndicator` or `smsGmscAddress` for instance, reaches
//! the caller. See [`crate`] on what happens to a member from a later release.

use rasn::prelude::*;

use crate::types::{
    CorrelationId, ExtensionContainer, IsdnAddressString, NetworkNodeDiameterAddress, SignalInfo,
    SmRpDa, SmRpOa, Time,
};

/// MT-ForwardSM-Arg — request parameters.
///
/// ```asn1
/// MT-ForwardSM-Arg ::= SEQUENCE {
///     sm-RP-DA                      SM-RP-DA,
///     sm-RP-OA                      SM-RP-OA,
///     sm-RP-UI                      SignalInfo,
///     moreMessagesToSend            NULL OPTIONAL,
///     extensionContainer            ExtensionContainer OPTIONAL,
///     ...,
///     smDeliveryTimer               SM-DeliveryTimerValue OPTIONAL,
///     smDeliveryStartTime           Time OPTIONAL,
///     smsOverIP-OnlyIndicator   [0] NULL OPTIONAL,
///     correlationID             [1] CorrelationID OPTIONAL,
///     maximumRetransmissionTime [2] Time OPTIONAL,
///     smsGmscAddress            [3] ISDN-AddressString OPTIONAL,
///     smsGmscDiameterAddress    [4] NetworkNodeDiameterAddress OPTIONAL }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct MtForwardSmArg {
    /// Destination address (IMSI or LMSI of the recipient).
    pub sm_rp_da: SmRpDa,
    /// Originating address (service centre address).
    pub sm_rp_oa: SmRpOa,
    /// SM-RP-UI (User Information — the SMS-DELIVER TPDU).
    pub sm_rp_ui: SignalInfo,
    /// `moreMessagesToSend` — an ASN.1 `NULL OPTIONAL` (TS 29.002), not a boolean.
    /// `Some(())` emits the NULL (more segments follow, e.g. a concatenated SMS);
    /// `None` omits it (this is the last / only message).
    pub more_messages_to_send: Option<()>,
    pub extension_container: Option<ExtensionContainer>,
    /// `SM-DeliveryTimerValue ::= INTEGER (30..600)` — seconds.
    pub sm_delivery_timer: Option<Integer>,
    pub sm_delivery_start_time: Option<Time>,
    /// The subscriber is reachable over IMS only; do not fall back to CS.
    #[rasn(tag(context, 0))]
    pub sms_over_ip_only_indicator: Option<()>,
    #[rasn(tag(context, 1))]
    pub correlation_id: Option<CorrelationId>,
    #[rasn(tag(context, 2))]
    pub maximum_retransmission_time: Option<Time>,
    #[rasn(tag(context, 3))]
    pub sms_gmsc_address: Option<IsdnAddressString>,
    #[rasn(tag(context, 4))]
    pub sms_gmsc_diameter_address: Option<NetworkNodeDiameterAddress>,
}

impl MtForwardSmArg {
    /// The three mandatory members; every optional member starts `None`.
    pub fn new(sm_rp_da: SmRpDa, sm_rp_oa: SmRpOa, sm_rp_ui: SignalInfo) -> Self {
        Self {
            sm_rp_da,
            sm_rp_oa,
            sm_rp_ui,
            more_messages_to_send: None,
            extension_container: None,
            sm_delivery_timer: None,
            sm_delivery_start_time: None,
            sms_over_ip_only_indicator: None,
            correlation_id: None,
            maximum_retransmission_time: None,
            sms_gmsc_address: None,
            sms_gmsc_diameter_address: None,
        }
    }
}

/// MT-ForwardSM-Res — response parameters.
///
/// ```asn1
/// MT-ForwardSM-Res ::= SEQUENCE {
///     sm-RP-UI            SignalInfo OPTIONAL,
///     extensionContainer  ExtensionContainer OPTIONAL,
///     ... }
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct MtForwardSmRes {
    /// SM-RP-UI (User Information — the SMS-DELIVER-REPORT TPDU).
    pub sm_rp_ui: Option<SignalInfo>,
    pub extension_container: Option<ExtensionContainer>,
}

/// MT-ForwardSM-VGCS-Arg (op 21) — an MT short message delivered to the talker
/// of a voice group call rather than to a single subscriber.
///
/// ```asn1
/// MT-ForwardSM-VGCS-Arg ::= SEQUENCE {
///     asciCallReference     ASCI-CallReference,
///     sm-RP-OA              SM-RP-OA,
///     sm-RP-UI              SignalInfo,
///     extensionContainer    ExtensionContainer OPTIONAL,
///     ... }
/// ```
///
/// `sm-RP-OA` is **untagged** here: what appears on the wire as `[2]` is the
/// `msisdn` alternative's own tag, not a tag on the member.
///
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct MtForwardSmVgcsArg {
    pub asci_call_reference: OctetString,
    pub sm_rp_oa: SmRpOa,
    pub sm_rp_ui: SignalInfo,
    pub extension_container: Option<ExtensionContainer>,
}

/// MT-ForwardSM-VGCS-Res (op 21).
///
/// ```asn1
/// MT-ForwardSM-VGCS-Res ::= SEQUENCE {
///     sm-RP-UI                [0] SignalInfo OPTIONAL,
///     dispatcherList          [1] DispatcherList OPTIONAL,
///     ongoingCall                 NULL OPTIONAL,
///     extensionContainer      [2] ExtensionContainer OPTIONAL,
///     ...,
///     additionalDispatcherList [3] AdditionalDispatcherList OPTIONAL }
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct MtForwardSmVgcsRes {
    #[rasn(tag(context, 0))]
    pub sm_rp_ui: Option<SignalInfo>,
    #[rasn(tag(context, 1))]
    pub dispatcher_list: Option<Vec<IsdnAddressString>>,
    /// Declared after `[1]`, and BER encodes in declaration order.
    pub ongoing_call: Option<()>,
    #[rasn(tag(context, 2))]
    pub extension_container: Option<ExtensionContainer>,
    #[rasn(tag(context, 3))]
    pub additional_dispatcher_list: Option<Vec<IsdnAddressString>>,
}
