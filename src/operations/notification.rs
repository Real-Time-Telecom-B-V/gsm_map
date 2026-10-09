//! Notifications an HLR or VLR pushes to a gsmSCF — 3GPP TS 29.002.
//!
//! - noteSubscriberDataModified (op 5)
//! - ss-InvocationNotification (op 72)
//! - noteMM-Event (op 89)
//!
//! Every member TS 29.002 defines is modelled; see [`crate`] on what
//! happens to a member that is not.

use rasn::prelude::*;

use crate::types::{ExtensionContainer, Imsi, IsdnAddressString, Opaque};

/// NoteSubscriberDataModified-Arg (op 5) — the HLR telling a gsmSCF that a
/// subscriber's record changed under it.
///
/// ```asn1
/// NoteSubscriberDataModifiedArg ::= SEQUENCE {
///     imsi                            IMSI,
///     msisdn                          ISDN-AddressString,
///     forwardingInfoFor-CSE       [0] Ext-ForwardingInfoFor-CSE OPTIONAL,
///     callBarringInfoFor-CSE      [1] Ext-CallBarringInfoFor-CSE OPTIONAL,
///     odb-Info                    [2] ODB-Info OPTIONAL,
///     camel-SubscriptionInfo      [3] CAMEL-SubscriptionInfo OPTIONAL,
///     allInformationSent          [4] NULL OPTIONAL,
///     extensionContainer              ExtensionContainer OPTIONAL,
///     ...,
///     ue-reachable                [5] ServingNode OPTIONAL,
///     csg-SubscriptionDataList    [6] CSG-SubscriptionDataList OPTIONAL,
///     cw-Data                     [7] CallWaitingData OPTIONAL,
///     ch-Data                     [8] CallHoldData OPTIONAL,
///     clip-Data                   [9] ClipData OPTIONAL,
///     clir-Data                  [10] ClirData OPTIONAL,
///     ect-data                   [11] EctData OPTIONAL }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct NoteSubscriberDataModifiedArg {
    pub imsi: Imsi,
    pub msisdn: IsdnAddressString,
    #[rasn(tag(context, 0))]
    pub forwarding_info_for_cse: Option<Opaque>,
    #[rasn(tag(context, 1))]
    pub call_barring_info_for_cse: Option<Opaque>,
    #[rasn(tag(context, 2))]
    pub odb_info: Option<Opaque>,
    #[rasn(tag(context, 3))]
    pub camel_subscription_info: Option<Opaque>,
    #[rasn(tag(context, 4))]
    pub all_information_sent: Option<()>,
    pub extension_container: Option<ExtensionContainer>,
    /// `ServingNode ::= BIT STRING { mme(0), sgsn(1), msc(2) }`.
    #[rasn(tag(context, 5))]
    pub ue_reachable: Option<BitString>,
    #[rasn(tag(context, 6))]
    pub csg_subscription_data_list: Option<Opaque>,
    #[rasn(tag(context, 7))]
    pub cw_data: Option<Opaque>,
    #[rasn(tag(context, 8))]
    pub ch_data: Option<Opaque>,
    #[rasn(tag(context, 9))]
    pub clip_data: Option<Opaque>,
    #[rasn(tag(context, 10))]
    pub clir_data: Option<Opaque>,
    #[rasn(tag(context, 11))]
    pub ect_data: Option<Opaque>,
}

impl NoteSubscriberDataModifiedArg {
    /// The two mandatory members; every optional member starts `None`.
    pub fn new(imsi: Imsi, msisdn: IsdnAddressString) -> Self {
        Self {
            imsi,
            msisdn,
            forwarding_info_for_cse: None,
            call_barring_info_for_cse: None,
            odb_info: None,
            camel_subscription_info: None,
            all_information_sent: None,
            extension_container: None,
            ue_reachable: None,
            csg_subscription_data_list: None,
            cw_data: None,
            ch_data: None,
            clip_data: None,
            clir_data: None,
            ect_data: None,
        }
    }
}

/// NoteSubscriberDataModified-Res (op 5).
#[derive(Debug, Clone, Default, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct NoteSubscriberDataModifiedRes {
    pub extension_container: Option<ExtensionContainer>,
}

/// SS-InvocationNotification-Arg (op 72) — the VLR/MSC telling a gsmSCF that a
/// subscriber invoked a supplementary service.
///
/// ```asn1
/// SS-InvocationNotificationArg ::= SEQUENCE {
///     imsi                    [0] IMSI,
///     msisdn                  [1] ISDN-AddressString,
///     ss-Event                [2] SS-Event,
///     ss-EventSpecification   [3] SS-EventSpecification OPTIONAL,
///     extensionContainer      [4] ExtensionContainer OPTIONAL,
///     ...,
///     b-subscriberNumber      [5] ISDN-AddressString OPTIONAL,
///     ccbs-RequestState       [6] CCBS-RequestState OPTIONAL }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct SsInvocationNotificationArg {
    #[rasn(tag(context, 0))]
    pub imsi: Imsi,
    #[rasn(tag(context, 1))]
    pub msisdn: IsdnAddressString,
    /// The SS-Code of the service that was invoked.
    #[rasn(tag(context, 2))]
    pub ss_event: OctetString,
    /// `SEQUENCE SIZE (1..2) OF AddressString`.
    #[rasn(tag(context, 3))]
    pub ss_event_specification: Option<Opaque>,
    #[rasn(tag(context, 4))]
    pub extension_container: Option<ExtensionContainer>,
    #[rasn(tag(context, 5))]
    pub b_subscriber_number: Option<IsdnAddressString>,
    /// `CCBS-RequestState ::= ENUMERATED { request(0), recall(1), active(2),
    /// completed(3), suspended(4), frozen(5), deleted(6) }`.
    #[rasn(tag(context, 6))]
    pub ccbs_request_state: Option<Integer>,
}

impl SsInvocationNotificationArg {
    /// The three mandatory members; every optional member starts `None`.
    pub fn new(imsi: Imsi, msisdn: IsdnAddressString, ss_event: OctetString) -> Self {
        Self {
            imsi,
            msisdn,
            ss_event,
            ss_event_specification: None,
            extension_container: None,
            b_subscriber_number: None,
            ccbs_request_state: None,
        }
    }
}

/// SS-InvocationNotification-Res (op 72).
#[derive(Debug, Clone, Default, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct SsInvocationNotificationRes {
    pub extension_container: Option<ExtensionContainer>,
}

/// NoteMM-Event-Arg (op 89) — a mobility-management event report to a gsmSCF.
///
/// ```asn1
/// NoteMM-EventArg ::= SEQUENCE {
///     serviceKey                       ServiceKey,
///     eventMet                     [0] MM-Code,
///     imsi                         [1] IMSI,
///     msisdn                       [2] ISDN-AddressString,
///     locationInformation          [3] LocationInformation OPTIONAL,
///     supportedCAMELPhases         [5] SupportedCamelPhases OPTIONAL,
///     extensionContainer           [6] ExtensionContainer OPTIONAL,
///     ...,
///     locationInformationGPRS      [7] LocationInformationGPRS OPTIONAL,
///     offeredCamel4Functionalities [8] OfferedCamel4Functionalities OPTIONAL }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct NoteMmEventArg {
    /// `ServiceKey ::= INTEGER (0..2147483647)`.
    pub service_key: Integer,
    /// The mobility-management event that was met.
    #[rasn(tag(context, 0))]
    pub event_met: OctetString,
    #[rasn(tag(context, 1))]
    pub imsi: Imsi,
    #[rasn(tag(context, 2))]
    pub msisdn: IsdnAddressString,
    #[rasn(tag(context, 3))]
    pub location_information: Option<crate::operations::subscriber_info::LocationInformation>,
    #[rasn(tag(context, 5))]
    pub supported_camel_phases: Option<BitString>,
    #[rasn(tag(context, 6))]
    pub extension_container: Option<ExtensionContainer>,
    #[rasn(tag(context, 7))]
    pub location_information_gprs: Option<Opaque>,
    #[rasn(tag(context, 8))]
    pub offered_camel4_functionalities: Option<BitString>,
}

impl NoteMmEventArg {
    /// The four mandatory members; every optional member starts `None`.
    pub fn new(
        service_key: Integer,
        event_met: OctetString,
        imsi: Imsi,
        msisdn: IsdnAddressString,
    ) -> Self {
        Self {
            service_key,
            event_met,
            imsi,
            msisdn,
            location_information: None,
            supported_camel_phases: None,
            extension_container: None,
            location_information_gprs: None,
            offered_camel4_functionalities: None,
        }
    }
}

/// NoteMM-Event-Res (op 89).
#[derive(Debug, Clone, Default, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct NoteMmEventRes {
    pub extension_container: Option<ExtensionContainer>,
}

/// Operation codes for these notifications. Re-exported from
/// [`crate::types::op_codes`].
pub mod op_codes {
    pub use crate::types::op_codes::{
        NOTE_MM_EVENT, NOTE_SUBSCRIBER_DATA_MODIFIED, SS_INVOCATION_NOTIFICATION,
    };
}
