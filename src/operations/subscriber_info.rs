//! Subscriber Information operations — 3GPP TS 29.002.
//!
//! - anyTimeSubscriberDataModification (op 65) — including the **IP-SM-GW
//!   registration**, the mechanism by which a node makes itself the MT-SMS
//!   routing node for a subscriber
//! - provideSubscriberInfo (op 70)
//! - anyTimeInterrogation (op 71)
//!
//! Every member TS 29.002 defines is modelled; see [`crate`] on why an
//! unmodelled member is fatal rather than merely absent. Sub-structures this
//! crate does not interpret are carried as [`Opaque`] and survive the round trip
//! unchanged.

use rasn::prelude::*;

use crate::types::{
    ExtensionContainer, Imsi, IsdnAddressString, Lmsi, NetworkNodeDiameterAddress, Opaque, Time,
};

/// NotReachableReason — why the network believes the subscriber is unreachable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, AsnType, Decode, Encode)]
#[rasn(enumerated)]
pub enum NotReachableReason {
    MsPurged = 0,
    ImsiDetached = 1,
    RestrictedArea = 2,
    NotRegistered = 3,
}

/// SubscriberState — a **CHOICE**, not an enumeration.
///
/// ```asn1
/// SubscriberState ::= CHOICE {
///     assumedIdle          [0] NULL,
///     camelBusy            [1] NULL,
///     netDetNotReachable       NotReachableReason,
///     notProvidedFromVLR   [2] NULL }
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, AsnType, Decode, Encode)]
#[rasn(choice)]
pub enum SubscriberState {
    #[rasn(tag(context, 0))]
    AssumedIdle(()),
    #[rasn(tag(context, 1))]
    CamelBusy(()),
    NetDetNotReachable(NotReachableReason),
    #[rasn(tag(context, 2))]
    NotProvidedFromVlr(()),
}

/// GeographicalInformation — the encoded position estimate (8 bytes).
pub type GeographicalInformation = OctetString;

/// CellGlobalIdOrServiceAreaIdOrLAI — a **CHOICE**, so `[3]` on
/// [`LocationInformation`] is an explicit tag.
///
/// ```asn1
/// CellGlobalIdOrServiceAreaIdOrLAI ::= CHOICE {
///     cellGlobalIdOrServiceAreaIdFixedLength [0] OCTET STRING (SIZE (7)),
///     laiFixedLength                         [1] OCTET STRING (SIZE (5)) }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
#[rasn(choice)]
pub enum CellGlobalIdOrServiceAreaIdOrLai {
    #[rasn(tag(context, 0))]
    CellGlobalIdOrServiceAreaIdFixedLength(OctetString),
    #[rasn(tag(context, 1))]
    LaiFixedLength(OctetString),
}

/// LocationInformation — where the CS side last saw the subscriber.
///
/// ```asn1
/// LocationInformation ::= SEQUENCE {
///     ageOfLocationInformation             AgeOfLocationInformation OPTIONAL,
///     geographicalInformation          [0] GeographicalInformation OPTIONAL,
///     vlr-number                       [1] ISDN-AddressString OPTIONAL,
///     locationNumber                   [2] LocationNumber OPTIONAL,
///     cellGlobalIdOrServiceAreaIdOrLAI [3] CellGlobalIdOrServiceAreaIdOrLAI OPTIONAL,
///     extensionContainer               [4] ExtensionContainer OPTIONAL,
///     ...,
///     selectedLSA-Id                   [5] LSAIdentity OPTIONAL,
///     msc-Number                       [6] ISDN-AddressString OPTIONAL,
///     geodeticInformation              [7] GeodeticInformation OPTIONAL,
///     currentLocationRetrieved         [8] NULL OPTIONAL,
///     sai-Present                      [9] NULL OPTIONAL,
///     locationInformationEPS          [10] LocationInformationEPS OPTIONAL,
///     userCSGInformation              [11] UserCSGInformation OPTIONAL }
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct LocationInformation {
    /// Minutes since the position was determined; untagged in the ASN.1.
    pub age_of_location_information: Option<Integer>,
    #[rasn(tag(context, 0))]
    pub geographical_information: Option<GeographicalInformation>,
    #[rasn(tag(context, 1))]
    pub vlr_number: Option<IsdnAddressString>,
    #[rasn(tag(context, 2))]
    pub location_number: Option<OctetString>,
    #[rasn(tag(explicit(context, 3)))]
    pub cell_global_id_or_service_area_id_or_lai: Option<CellGlobalIdOrServiceAreaIdOrLai>,
    #[rasn(tag(context, 4))]
    pub extension_container: Option<ExtensionContainer>,
    #[rasn(tag(context, 5))]
    pub selected_lsa_id: Option<OctetString>,
    #[rasn(tag(context, 6))]
    pub msc_number: Option<IsdnAddressString>,
    #[rasn(tag(context, 7))]
    pub geodetic_information: Option<OctetString>,
    #[rasn(tag(context, 8))]
    pub current_location_retrieved: Option<()>,
    #[rasn(tag(context, 9))]
    pub sai_present: Option<()>,
    #[rasn(tag(context, 10))]
    pub location_information_eps: Option<Opaque>,
    #[rasn(tag(context, 11))]
    pub user_csg_information: Option<Opaque>,
}

/// SubscriberInfo — returned by provideSubscriberInfo and anyTimeInterrogation.
///
/// ```asn1
/// SubscriberInfo ::= SEQUENCE {
///     locationInformation                   [0] LocationInformation OPTIONAL,
///     subscriberState                       [1] SubscriberState OPTIONAL,
///     extensionContainer                    [2] ExtensionContainer OPTIONAL,
///     ...,
///     locationInformationGPRS               [3] LocationInformationGPRS OPTIONAL,
///     ps-SubscriberState                    [4] PS-SubscriberState OPTIONAL,
///     imei                                  [5] IMEI OPTIONAL,
///     ms-Classmark2                         [6] MS-Classmark2 OPTIONAL,
///     gprs-MS-Class                         [7] GPRSMSClass OPTIONAL,
///     mnpInfoRes                            [8] MNPInfoRes OPTIONAL,
///     imsVoiceOverPS-SessionsIndication     [9] IMS-VoiceOverPS-SessionsInd OPTIONAL,
///     lastUE-ActivityTime                  [10] Time OPTIONAL,
///     lastRAT-Type                         [11] Used-RAT-Type OPTIONAL,
///     eps-SubscriberState                  [12] PS-SubscriberState OPTIONAL,
///     locationInformationEPS               [13] LocationInformationEPS OPTIONAL,
///     timeZone                             [14] TimeZone OPTIONAL,
///     daylightSavingTime                   [15] DaylightSavingTime OPTIONAL,
///     locationInformation5GS               [16] LocationInformation5GS OPTIONAL }
/// ```
///
/// `subscriberState`, `ps-SubscriberState` and `eps-SubscriberState` are
/// CHOICEs, so their tags are **explicit**.
///
/// The members typed `Used-RAT-Type`, `IMS-VoiceOverPS-SessionsInd` and
/// `DaylightSavingTime` are ENUMERATEDs the spec keeps extending, so they are
/// carried as `Integer` rather than a closed Rust enum: a value added in a later
/// release must not make the whole `SubscriberInfo` undecodable. `lastRAT-Type`
/// is `utran(0) geran(1) wlan(2) gan(3) i-hspa-evolution(4) eutran(5) nb-iot(6)`;
/// `imsVoiceOverPS-SessionsIndication` is `notSupported(0) supported(1)`;
/// `daylightSavingTime` is `noAdjustment(0) plusOneHour(1) plusTwoHours(2)`.
#[derive(Debug, Clone, Default, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct SubscriberInfo {
    #[rasn(tag(context, 0))]
    pub location_information: Option<LocationInformation>,
    #[rasn(tag(explicit(context, 1)))]
    pub subscriber_state: Option<SubscriberState>,
    #[rasn(tag(context, 2))]
    pub extension_container: Option<ExtensionContainer>,
    #[rasn(tag(context, 3))]
    pub location_information_gprs: Option<Opaque>,
    #[rasn(tag(explicit(context, 4)))]
    pub ps_subscriber_state: Option<Opaque>,
    #[rasn(tag(context, 5))]
    pub imei: Option<OctetString>,
    #[rasn(tag(context, 6))]
    pub ms_classmark2: Option<OctetString>,
    #[rasn(tag(context, 7))]
    pub gprs_ms_class: Option<Opaque>,
    #[rasn(tag(context, 8))]
    pub mnp_info_res: Option<Opaque>,
    #[rasn(tag(context, 9))]
    pub ims_voice_over_ps_sessions_indication: Option<Integer>,
    #[rasn(tag(context, 10))]
    pub last_ue_activity_time: Option<Time>,
    #[rasn(tag(context, 11))]
    pub last_rat_type: Option<Integer>,
    #[rasn(tag(explicit(context, 12)))]
    pub eps_subscriber_state: Option<Opaque>,
    #[rasn(tag(context, 13))]
    pub location_information_eps: Option<Opaque>,
    #[rasn(tag(context, 14))]
    pub time_zone: Option<OctetString>,
    #[rasn(tag(context, 15))]
    pub daylight_saving_time: Option<Integer>,
    #[rasn(tag(context, 16))]
    pub location_information_5gs: Option<Opaque>,
}

/// RequestedInfo — what the requester wants back.
///
/// ```asn1
/// RequestedInfo ::= SEQUENCE {
///     locationInformation              [0] NULL OPTIONAL,
///     subscriberState                  [1] NULL OPTIONAL,
///     extensionContainer               [2] ExtensionContainer OPTIONAL,
///     ...,
///     currentLocation                  [3] NULL OPTIONAL,
///     requestedDomain                  [4] DomainType OPTIONAL,
///     imei                             [6] NULL OPTIONAL,
///     ms-classmark                     [5] NULL OPTIONAL,
///     mnpRequestedInfo                 [7] NULL OPTIONAL,
///     locationInformationEPS-Supported [11] NULL OPTIONAL,
///     t-adsData                        [8] NULL OPTIONAL,
///     requestedNodes                   [9] RequestedNodes OPTIONAL,
///     servingNodeIndication           [10] NULL OPTIONAL,
///     localTimeZoneRequest            [12] NULL OPTIONAL }
/// ```
///
/// The field order is the spec's, which is **not** ascending by tag: `[6]`
/// precedes `[5]`, and `[11]` sits between `[7]` and `[8]`. BER encodes members
/// in declaration order, so this matters on the wire.
///
/// `requestedDomain` is `DomainType ::= ENUMERATED { cs-Domain(0), ps-Domain(1) }`,
/// carried as `Integer` because the type is extensible.
#[derive(Debug, Clone, Default, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct RequestedInfo {
    #[rasn(tag(context, 0))]
    pub location_information: Option<()>,
    #[rasn(tag(context, 1))]
    pub subscriber_state: Option<()>,
    #[rasn(tag(context, 2))]
    pub extension_container: Option<ExtensionContainer>,
    #[rasn(tag(context, 3))]
    pub current_location: Option<()>,
    #[rasn(tag(context, 4))]
    pub requested_domain: Option<Integer>,
    #[rasn(tag(context, 6))]
    pub imei: Option<()>,
    #[rasn(tag(context, 5))]
    pub ms_classmark: Option<()>,
    #[rasn(tag(context, 7))]
    pub mnp_requested_info: Option<()>,
    #[rasn(tag(context, 11))]
    pub location_information_eps_supported: Option<()>,
    #[rasn(tag(context, 8))]
    pub t_ads_data: Option<()>,
    /// `RequestedNodes ::= BIT STRING { mme(0), sgsn(1) }`.
    #[rasn(tag(context, 9))]
    pub requested_nodes: Option<BitString>,
    #[rasn(tag(context, 10))]
    pub serving_node_indication: Option<()>,
    #[rasn(tag(context, 12))]
    pub local_time_zone_request: Option<()>,
}

/// ProvideSubscriberInfo-Arg (op 70).
///
/// ```asn1
/// ProvideSubscriberInfo-Arg ::= SEQUENCE {
///     imsi                [0] IMSI,
///     lmsi                [1] LMSI OPTIONAL,
///     requestedInfo       [2] RequestedInfo,
///     extensionContainer  [3] ExtensionContainer OPTIONAL,
///     ...,
///     callPriority        [4] EMLPP-Priority OPTIONAL }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct ProvideSubscriberInfoArg {
    #[rasn(tag(context, 0))]
    pub imsi: Imsi,
    #[rasn(tag(context, 1))]
    pub lmsi: Option<Lmsi>,
    #[rasn(tag(context, 2))]
    pub requested_info: RequestedInfo,
    #[rasn(tag(context, 3))]
    pub extension_container: Option<ExtensionContainer>,
    /// `EMLPP-Priority ::= INTEGER (0..15)`.
    #[rasn(tag(context, 4))]
    pub call_priority: Option<Integer>,
}

impl ProvideSubscriberInfoArg {
    /// The two mandatory members; every optional member starts `None`.
    pub fn new(imsi: Imsi, requested_info: RequestedInfo) -> Self {
        Self {
            imsi,
            lmsi: None,
            requested_info,
            extension_container: None,
            call_priority: None,
        }
    }
}

/// ProvideSubscriberInfo-Res (op 70).
///
/// ```asn1
/// ProvideSubscriberInfo-Res ::= SEQUENCE {
///     subscriberInfo      SubscriberInfo,
///     extensionContainer  ExtensionContainer OPTIONAL,
///     ... }
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct ProvideSubscriberInfoRes {
    pub subscriber_info: SubscriberInfo,
    pub extension_container: Option<ExtensionContainer>,
}

/// SubscriberIdentity — how an any-time operation names the subscriber.
///
/// ```asn1
/// SubscriberIdentity ::= CHOICE {
///     imsi    [0] IMSI,
///     msisdn  [1] ISDN-AddressString }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
#[rasn(choice)]
pub enum SubscriberIdentity {
    #[rasn(tag(context, 0))]
    Imsi(Imsi),
    #[rasn(tag(context, 1))]
    Msisdn(IsdnAddressString),
}

/// AnyTimeInterrogation-Arg (op 71).
///
/// ```asn1
/// AnyTimeInterrogationArg ::= SEQUENCE {
///     subscriberIdentity  [0] SubscriberIdentity,
///     requestedInfo       [1] RequestedInfo,
///     gsmSCF-Address      [3] ISDN-AddressString,
///     extensionContainer  [2] ExtensionContainer OPTIONAL,
///     ... }
/// ```
///
/// `subscriberIdentity` is a CHOICE, so TS 29.002's `IMPLICIT TAGS` does not
/// apply to it and `[0]` is **explicit**. Note the declaration order: `[3]`
/// precedes `[2]`.
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct AnyTimeInterrogationArg {
    #[rasn(tag(explicit(context, 0)))]
    pub subscriber_identity: SubscriberIdentity,
    #[rasn(tag(context, 1))]
    pub requested_info: RequestedInfo,
    #[rasn(tag(context, 3))]
    pub gsm_scf_address: IsdnAddressString,
    #[rasn(tag(context, 2))]
    pub extension_container: Option<ExtensionContainer>,
}

/// AnyTimeInterrogation-Res (op 71).
///
/// ```asn1
/// AnyTimeInterrogationRes ::= SEQUENCE {
///     subscriberInfo      SubscriberInfo,
///     extensionContainer  ExtensionContainer OPTIONAL,
///     ... }
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct AnyTimeInterrogationRes {
    pub subscriber_info: SubscriberInfo,
    pub extension_container: Option<ExtensionContainer>,
}

/// ModificationInstruction — TS 29.002 MAP-MS-DataTypes.
///
/// ```asn1
/// ModificationInstruction ::= ENUMERATED {
///     deactivate (0),
///     activate   (1) }
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, AsnType, Decode, Encode)]
#[rasn(enumerated)]
pub enum ModificationInstruction {
    Deactivate = 0,
    Activate = 1,
}

/// ModificationRequestFor-IP-SM-GW-Data — the IP-SM-GW registration.
///
/// ```asn1
/// ModificationRequestFor-IP-SM-GW-Data ::= SEQUENCE {
///     modifyRegistrationStatus  [0] ModificationInstruction OPTIONAL,
///     extensionContainer        [1] ExtensionContainer OPTIONAL,
///     ...,
///     ip-sm-gw-DiameterAddress  [2] NetworkNodeDiameterAddress OPTIONAL
///     -- may be present when ModificationInstruction is "activate"
///     }
/// ```
///
/// This is how a node registers itself as the MT-SMS routing node for a
/// subscriber: `Activate` on registration, `Deactivate` on de-registration.
/// Per TS 23.204 the HLR then hands that node out in `RoutingInfoForSM-Res`
/// instead of the serving MSC.
///
/// The registering node's **own address is not here** — it travels in
/// [`AnyTimeModificationArg::gsm_scf_address`], because the IP-SM-GW acts in
/// the gsmSCF role towards the HLR for this dialogue. `ip-sm-gw-DiameterAddress`
/// is the Diameter-realm variant, for a node reached over SGd/S6c rather than
/// MAP.
#[derive(Debug, Clone, Default, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct ModificationRequestForIpSmGwData {
    #[rasn(tag(context, 0))]
    pub modify_registration_status: Option<ModificationInstruction>,
    #[rasn(tag(context, 1))]
    pub extension_container: Option<ExtensionContainer>,
    #[rasn(tag(context, 2))]
    pub ip_sm_gw_diameter_address: Option<NetworkNodeDiameterAddress>,
}

/// AnyTimeSubscriberDataModification-Arg (op 65).
///
/// ```asn1
/// AnyTimeModificationArg ::= SEQUENCE {
///     subscriberIdentity                   [0] SubscriberIdentity,
///     gsmSCF-Address                       [1] ISDN-AddressString,
///     modificationRequestFor-CF-Info       [2] ModificationRequestFor-CF-Info OPTIONAL,
///     modificationRequestFor-CB-Info       [3] ModificationRequestFor-CB-Info OPTIONAL,
///     modificationRequestFor-CSI           [4] ModificationRequestFor-CSI OPTIONAL,
///     extensionContainer                   [5] ExtensionContainer OPTIONAL,
///     longFTN-Supported                    [6] NULL OPTIONAL,
///     ...,
///     modificationRequestFor-ODB-data      [7] ModificationRequestFor-ODB-data OPTIONAL,
///     modificationRequestFor-IP-SM-GW-Data [8] ModificationRequestFor-IP-SM-GW-Data OPTIONAL,
///     activationRequestForUE-reachability  [9] RequestedServingNode OPTIONAL,
///     modificationRequestFor-CSG          [10] ModificationRequestFor-CSG OPTIONAL,
///     modificationRequestFor-CW-Data      [11] ModificationRequestFor-CW-Info OPTIONAL,
///     modificationRequestFor-CLIP-Data    [12] ModificationRequestFor-CLIP-Info OPTIONAL,
///     modificationRequestFor-CLIR-Data    [13] ModificationRequestFor-CLIR-Info OPTIONAL,
///     modificationRequestFor-HOLD-Data    [14] ModificationRequestFor-CH-Info OPTIONAL,
///     modificationRequestFor-ECT-Data     [15] ModificationRequestFor-ECT-Info OPTIONAL }
/// ```
///
/// `subscriberIdentity` is a CHOICE, so `[0]` is an **explicit** tag. The
/// supplementary-service modification requests are carried as [`Opaque`]: this
/// crate does not interpret them, but it has to model them or an HLR dialogue
/// that carries one fails to decode.
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct AnyTimeModificationArg {
    #[rasn(tag(explicit(context, 0)))]
    pub subscriber_identity: SubscriberIdentity,
    /// For an IP-SM-GW registration this is the gateway's **own** address.
    #[rasn(tag(context, 1))]
    pub gsm_scf_address: IsdnAddressString,
    #[rasn(tag(context, 2))]
    pub modification_request_for_cf_info: Option<Opaque>,
    #[rasn(tag(context, 3))]
    pub modification_request_for_cb_info: Option<Opaque>,
    #[rasn(tag(context, 4))]
    pub modification_request_for_csi: Option<Opaque>,
    #[rasn(tag(context, 5))]
    pub extension_container: Option<ExtensionContainer>,
    #[rasn(tag(context, 6))]
    pub long_ftn_supported: Option<()>,
    #[rasn(tag(context, 7))]
    pub modification_request_for_odb_data: Option<Opaque>,
    #[rasn(tag(context, 8))]
    pub modification_request_for_ip_sm_gw_data: Option<ModificationRequestForIpSmGwData>,
    /// `RequestedServingNode ::= BIT STRING { mme(0), sgsn(1) }`.
    #[rasn(tag(context, 9))]
    pub activation_request_for_ue_reachability: Option<BitString>,
    #[rasn(tag(context, 10))]
    pub modification_request_for_csg: Option<Opaque>,
    #[rasn(tag(context, 11))]
    pub modification_request_for_cw_data: Option<Opaque>,
    #[rasn(tag(context, 12))]
    pub modification_request_for_clip_data: Option<Opaque>,
    #[rasn(tag(context, 13))]
    pub modification_request_for_clir_data: Option<Opaque>,
    #[rasn(tag(context, 14))]
    pub modification_request_for_hold_data: Option<Opaque>,
    #[rasn(tag(context, 15))]
    pub modification_request_for_ect_data: Option<Opaque>,
}

impl AnyTimeModificationArg {
    /// The two mandatory members; every optional member starts `None`.
    ///
    /// For the IP-SM-GW registration, set
    /// [`modification_request_for_ip_sm_gw_data`](Self::modification_request_for_ip_sm_gw_data)
    /// with functional-record-update.
    pub fn new(
        subscriber_identity: SubscriberIdentity,
        gsm_scf_address: IsdnAddressString,
    ) -> Self {
        Self {
            subscriber_identity,
            gsm_scf_address,
            modification_request_for_cf_info: None,
            modification_request_for_cb_info: None,
            modification_request_for_csi: None,
            extension_container: None,
            long_ftn_supported: None,
            modification_request_for_odb_data: None,
            modification_request_for_ip_sm_gw_data: None,
            activation_request_for_ue_reachability: None,
            modification_request_for_csg: None,
            modification_request_for_cw_data: None,
            modification_request_for_clip_data: None,
            modification_request_for_clir_data: None,
            modification_request_for_hold_data: None,
            modification_request_for_ect_data: None,
        }
    }
}

/// AnyTimeSubscriberDataModification-Res (op 65).
///
/// ```asn1
/// AnyTimeModificationRes ::= SEQUENCE {
///     ss-InfoFor-CSE          [0] Ext-SS-InfoFor-CSE OPTIONAL,
///     camel-SubscriptionInfo  [1] CAMEL-SubscriptionInfo OPTIONAL,
///     extensionContainer      [2] ExtensionContainer OPTIONAL,
///     ...,
///     odb-Info                [3] ODB-Info OPTIONAL,
///     cw-Data                 [4] CallWaitingData OPTIONAL,
///     ch-Data                 [5] CallHoldData OPTIONAL,
///     clip-Data               [6] ClipData OPTIONAL,
///     clir-Data               [7] ClirData OPTIONAL,
///     ect-data                [8] EctData OPTIONAL,
///     serviceCentreAddress    [9] AddressString OPTIONAL }
/// ```
///
/// `ss-InfoFor-CSE` is a CHOICE, so `[0]` is an **explicit** tag. For an
/// IP-SM-GW registration the result is effectively empty: success is the absence
/// of a `returnError`.
#[derive(Debug, Clone, Default, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct AnyTimeModificationRes {
    #[rasn(tag(explicit(context, 0)))]
    pub ss_info_for_cse: Option<Opaque>,
    #[rasn(tag(context, 1))]
    pub camel_subscription_info: Option<Opaque>,
    #[rasn(tag(context, 2))]
    pub extension_container: Option<ExtensionContainer>,
    #[rasn(tag(context, 3))]
    pub odb_info: Option<Opaque>,
    #[rasn(tag(context, 4))]
    pub cw_data: Option<Opaque>,
    #[rasn(tag(context, 5))]
    pub ch_data: Option<Opaque>,
    #[rasn(tag(context, 6))]
    pub clip_data: Option<Opaque>,
    #[rasn(tag(context, 7))]
    pub clir_data: Option<Opaque>,
    #[rasn(tag(context, 8))]
    pub ect_data: Option<Opaque>,
    #[rasn(tag(context, 9))]
    pub service_centre_address: Option<crate::types::AddressString>,
}

/// Operation codes for this group. Re-exported from [`crate::types::op_codes`],
/// which is the single registry `operation_name()` resolves against.
pub mod op_codes {
    pub use crate::types::op_codes::{
        ANY_TIME_INTERROGATION, ANY_TIME_MODIFICATION, ANY_TIME_SUBSCRIPTION_INTERROGATION,
        PROVIDE_SUBSCRIBER_INFO,
    };
}

/// AnyTimeSubscriptionInterrogation-Arg (op 62) — a gsmSCF asking the HLR what
/// a subscriber is provisioned for, as opposed to where they are.
///
/// ```asn1
/// AnyTimeSubscriptionInterrogationArg ::= SEQUENCE {
///     subscriberIdentity        [0] SubscriberIdentity,
///     requestedSubscriptionInfo [1] RequestedSubscriptionInfo,
///     gsmSCF-Address            [2] ISDN-AddressString,
///     extensionContainer        [3] ExtensionContainer OPTIONAL,
///     longFTN-Supported         [4] NULL OPTIONAL,
///     ... }
/// ```
///
/// `subscriberIdentity` is a CHOICE, so `[0]` is an **explicit** tag.
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct AnyTimeSubscriptionInterrogationArg {
    #[rasn(tag(explicit(context, 0)))]
    pub subscriber_identity: SubscriberIdentity,
    #[rasn(tag(context, 1))]
    pub requested_subscription_info: Opaque,
    #[rasn(tag(context, 2))]
    pub gsm_scf_address: Option<IsdnAddressString>,
    #[rasn(tag(context, 3))]
    pub extension_container: Option<ExtensionContainer>,
    #[rasn(tag(context, 4))]
    pub long_ftn_supported: Option<()>,
}

/// AnyTimeSubscriptionInterrogation-Res (op 62).
///
/// ```asn1
/// AnyTimeSubscriptionInterrogationRes ::= SEQUENCE {
///     callForwardingData        [1] CallForwardingData OPTIONAL,
///     callBarringData           [2] CallBarringData OPTIONAL,
///     odb-Info                  [3] ODB-Info OPTIONAL,
///     camel-SubscriptionInfo    [4] CAMEL-SubscriptionInfo OPTIONAL,
///     supportedVLR-CAMEL-Phases [5] SupportedCamelPhases OPTIONAL,
///     supportedSGSN-CAMEL-Phases [6] SupportedCamelPhases OPTIONAL,
///     extensionContainer        [7] ExtensionContainer OPTIONAL,
///     ...,
///     offeredCamel4CSIsInVLR    [8] OfferedCamel4CSIs OPTIONAL,
///     offeredCamel4CSIsInSGSN   [9] OfferedCamel4CSIs OPTIONAL,
///     msisdn-BS-List           [10] MSISDN-BS-List OPTIONAL,
///     csg-SubscriptionDataList [11] CSG-SubscriptionDataList OPTIONAL,
///     cw-Data                  [12] CallWaitingData OPTIONAL,
///     ch-Data                  [13] CallHoldData OPTIONAL,
///     clip-Data                [14] ClipData OPTIONAL,
///     clir-Data                [15] ClirData OPTIONAL,
///     ect-data                 [16] EctData OPTIONAL }
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct AnyTimeSubscriptionInterrogationRes {
    #[rasn(tag(context, 1))]
    pub call_forwarding_data: Option<Opaque>,
    #[rasn(tag(context, 2))]
    pub call_barring_data: Option<Opaque>,
    #[rasn(tag(context, 3))]
    pub odb_info: Option<Opaque>,
    #[rasn(tag(context, 4))]
    pub camel_subscription_info: Option<Opaque>,
    #[rasn(tag(context, 5))]
    pub supported_vlr_camel_phases: Option<BitString>,
    #[rasn(tag(context, 6))]
    pub supported_sgsn_camel_phases: Option<BitString>,
    #[rasn(tag(context, 7))]
    pub extension_container: Option<ExtensionContainer>,
    #[rasn(tag(context, 8))]
    pub offered_camel4_csis_in_vlr: Option<BitString>,
    #[rasn(tag(context, 9))]
    pub offered_camel4_csis_in_sgsn: Option<BitString>,
    #[rasn(tag(context, 10))]
    pub msisdn_bs_list: Option<Opaque>,
    #[rasn(tag(context, 11))]
    pub csg_subscription_data_list: Option<Opaque>,
    #[rasn(tag(context, 12))]
    pub cw_data: Option<Opaque>,
    #[rasn(tag(context, 13))]
    pub ch_data: Option<Opaque>,
    #[rasn(tag(context, 14))]
    pub clip_data: Option<Opaque>,
    #[rasn(tag(context, 15))]
    pub clir_data: Option<Opaque>,
    #[rasn(tag(context, 16))]
    pub ect_data: Option<Opaque>,
}
