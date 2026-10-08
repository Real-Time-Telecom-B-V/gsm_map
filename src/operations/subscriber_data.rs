//! Subscriber Data Management operations — 3GPP TS 29.002.
//!
//! - insertSubscriberData (op 7)
//! - deleteSubscriberData (op 8)
//!
//! Every member TS 29.002 defines is modelled — all 53 of them on the insert
//! argument — because BER decoding is not tolerant of unmodelled members; see
//! [`crate`]. The subscription sub-structures themselves (CAMEL, GPRS, EPS, LCS,
//! ODB, LSA, CSG) are carried as [`Opaque`] and survive the round trip unchanged.
//!
//! Neither argument is in ascending tag order: TS 29.002 declares the members
//! added in later releases wherever they were introduced, and BER encodes in
//! declaration order, so the order below is on the wire.

use rasn::prelude::*;

use crate::types::{ExtensionContainer, Imsi, IsdnAddressString, Opaque};

/// Category — subscriber category (ITU-T Q.763).
pub type Category = OctetString;

/// SubscriberStatus.
#[derive(Debug, Clone, Copy, PartialEq, Eq, AsnType, Decode, Encode)]
#[rasn(enumerated)]
pub enum SubscriberStatus {
    ServiceGranted = 0,
    OperatorDeterminedBarring = 1,
}

crate::types::extensible_enumerated! {
    /// NetworkAccessMode.
    ///
    /// ```asn1
    /// NetworkAccessMode ::= ENUMERATED {
    ///     packetAndCircuit (0),
    ///     onlyCircuit      (1),
    ///     onlyPacket       (2),
    ///     ... }
    ///     -- if unknown values are received in NetworkAccessMode
    ///     -- they shall be discarded.
    /// ```
    ///
    /// Extensible: discard an `Unrecognised` value as the comment says, and
    /// keep the rest of the subscriber data.
    pub enum NetworkAccessMode {
        PacketAndCircuit = 0,
        OnlyCircuit = 1,
        OnlyPacket = 2,
    }
}

/// ODB-Data — operator-determined barring, the subscription flag that decides
/// whether a subscriber may originate an SMS at all.
///
/// ```asn1
/// ODB-Data ::= SEQUENCE {
///     odb-GeneralData     ODB-GeneralData,
///     odb-HPLMN-Data      ODB-HPLMN-Data OPTIONAL,
///     extensionContainer  ExtensionContainer OPTIONAL,
///     ... }
///
/// ODB-GeneralData ::= BIT STRING {
///     allOG-CallsBarred(0), internationalOGCallsBarred(1), ...,
///     allECT-Barred(12), ...
///     allPacketOrientedServicesBarred(19), ...,
///     barringOfRegistrationOfMPTY(23), ... }
/// ```
///
/// Both members are BIT STRINGs numbered from the most significant bit; use
/// [`BitString`] positions, not a packed integer.
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct OdbData {
    pub odb_general_data: BitString,
    pub odb_hplmn_data: Option<BitString>,
    pub extension_container: Option<ExtensionContainer>,
}

impl OdbData {
    /// The one mandatory member; every optional member starts `None`.
    pub fn new(odb_general_data: BitString) -> Self {
        Self {
            odb_general_data,
            odb_hplmn_data: None,
            extension_container: None,
        }
    }
}

/// InsertSubscriberData-Arg (op 7).
///
/// The HLR pushes subscription data into the VLR/SGSN. See the module docs on
/// member order and on the opaque sub-structures.
#[derive(Debug, Clone, Default, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct InsertSubscriberDataArg {
    #[rasn(tag(context, 0))]
    pub imsi: Option<Imsi>,
    #[rasn(tag(context, 1))]
    pub msisdn: Option<IsdnAddressString>,
    #[rasn(tag(context, 2))]
    pub category: Option<Category>,
    #[rasn(tag(context, 3))]
    pub subscriber_status: Option<SubscriberStatus>,
    #[rasn(tag(context, 4))]
    pub bearer_service_list: Option<Vec<OctetString>>,
    #[rasn(tag(context, 6))]
    pub teleservice_list: Option<Vec<OctetString>>,
    #[rasn(tag(context, 7))]
    pub provisioned_ss: Option<Opaque>,
    #[rasn(tag(context, 8))]
    pub odb_data: Option<OdbData>,
    #[rasn(tag(context, 9))]
    pub roaming_restriction_due_to_unsupported_feature: Option<()>,
    #[rasn(tag(context, 10))]
    pub regional_subscription_data: Option<Opaque>,
    #[rasn(tag(context, 11))]
    pub vbs_subscription_data: Option<Opaque>,
    #[rasn(tag(context, 12))]
    pub vgcs_subscription_data: Option<Opaque>,
    #[rasn(tag(context, 13))]
    pub vlr_camel_subscription_info: Option<Opaque>,
    #[rasn(tag(context, 14))]
    pub extension_container: Option<ExtensionContainer>,
    #[rasn(tag(context, 15))]
    pub naea_preferred_ci: Option<Opaque>,
    #[rasn(tag(context, 16))]
    pub gprs_subscription_data: Option<Opaque>,
    #[rasn(tag(context, 23))]
    pub roaming_restricted_in_sgsn_due_to_unsupported_feature: Option<()>,
    #[rasn(tag(context, 24))]
    pub network_access_mode: Option<NetworkAccessMode>,
    #[rasn(tag(context, 25))]
    pub lsa_information: Option<Opaque>,
    #[rasn(tag(context, 21))]
    pub lmu_indicator: Option<()>,
    #[rasn(tag(context, 22))]
    pub lcs_information: Option<Opaque>,
    #[rasn(tag(context, 26))]
    pub ist_alert_timer: Option<Integer>,
    #[rasn(tag(context, 27))]
    pub super_charger_supported_in_hlr: Option<OctetString>,
    #[rasn(tag(context, 28))]
    pub mc_ss_info: Option<Opaque>,
    #[rasn(tag(context, 29))]
    pub cs_allocation_retention_priority: Option<OctetString>,
    #[rasn(tag(context, 17))]
    pub sgsn_camel_subscription_info: Option<Opaque>,
    /// `ChargingCharacteristics ::= OCTET STRING (SIZE (2))`, coded as in
    /// TS 32.215.
    #[rasn(tag(context, 18))]
    pub charging_characteristics: Option<OctetString>,
    #[rasn(tag(context, 19))]
    pub access_restriction_data: Option<BitString>,
    #[rasn(tag(context, 20))]
    pub ics_indicator: Option<bool>,
    #[rasn(tag(context, 31))]
    pub eps_subscription_data: Option<Opaque>,
    #[rasn(tag(context, 32))]
    pub csg_subscription_data_list: Option<Opaque>,
    #[rasn(tag(context, 33))]
    pub ue_reachability_request_indicator: Option<()>,
    #[rasn(tag(context, 34))]
    pub sgsn_number: Option<IsdnAddressString>,
    #[rasn(tag(context, 35))]
    pub mme_name: Option<OctetString>,
    #[rasn(tag(context, 36))]
    pub subscribed_periodic_rau_tau_timer: Option<Integer>,
    #[rasn(tag(context, 37))]
    pub vplmn_lipa_allowed: Option<()>,
    #[rasn(tag(context, 38))]
    pub mdt_user_consent: Option<bool>,
    #[rasn(tag(context, 39))]
    pub subscribed_periodic_lau_timer: Option<Integer>,
    #[rasn(tag(context, 40))]
    pub vplmn_csg_subscription_data_list: Option<Opaque>,
    #[rasn(tag(context, 41))]
    pub additional_msisdn: Option<IsdnAddressString>,
    #[rasn(tag(context, 42))]
    pub ps_and_sms_only_service_provision: Option<()>,
    #[rasn(tag(context, 43))]
    pub sms_in_sgsn_allowed: Option<()>,
    #[rasn(tag(context, 44))]
    pub cs_to_ps_srvcc_allowed_indicator: Option<()>,
    #[rasn(tag(context, 45))]
    pub pcscf_restoration_request: Option<()>,
    #[rasn(tag(context, 46))]
    pub adjacent_access_restriction_data_list: Option<Opaque>,
    #[rasn(tag(context, 47))]
    pub imsi_group_id_list: Option<Opaque>,
    /// `UE-UsageType ::= OCTET STRING (SIZE (4))`, coded as in TS 29.272.
    #[rasn(tag(context, 48))]
    pub ue_usage_type: Option<OctetString>,
    #[rasn(tag(context, 49))]
    pub user_plane_integrity_protection_indicator: Option<()>,
    #[rasn(tag(context, 50))]
    pub dl_buffering_suggested_packet_count: Option<Integer>,
    #[rasn(tag(context, 51))]
    pub reset_id_list: Option<Opaque>,
    #[rasn(tag(context, 52))]
    pub edrx_cycle_length_list: Option<Opaque>,
    #[rasn(tag(context, 53))]
    pub ext_access_restriction_data: Option<BitString>,
    #[rasn(tag(context, 54))]
    pub iab_operation_allowed_indicator: Option<()>,
}

/// InsertSubscriberData-Res (op 7).
///
/// ```asn1
/// InsertSubscriberDataRes ::= SEQUENCE {
///     teleserviceList              [1] TeleserviceList OPTIONAL,
///     bearerServiceList            [2] BearerServiceList OPTIONAL,
///     ss-List                      [3] SS-List OPTIONAL,
///     odb-GeneralData              [4] ODB-GeneralData OPTIONAL,
///     regionalSubscriptionResponse [5] RegionalSubscriptionResponse OPTIONAL,
///     supportedCamelPhases         [6] SupportedCamelPhases OPTIONAL,
///     extensionContainer           [7] ExtensionContainer OPTIONAL,
///     ...,
///     offeredCamel4CSIs            [8] OfferedCamel4CSIs OPTIONAL,
///     supportedFeatures            [9] SupportedFeatures OPTIONAL,
///     ext-SupportedFeatures       [10] Ext-SupportedFeatures OPTIONAL }
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct InsertSubscriberDataRes {
    #[rasn(tag(context, 1))]
    pub teleservice_list: Option<Vec<OctetString>>,
    #[rasn(tag(context, 2))]
    pub bearer_service_list: Option<Vec<OctetString>>,
    #[rasn(tag(context, 3))]
    pub ss_list: Option<Vec<OctetString>>,
    #[rasn(tag(context, 4))]
    pub odb_general_data: Option<BitString>,
    /// `RegionalSubscriptionResponse ::= ENUMERATED { networkNode-AreaRestricted(0),
    /// tooManyZoneCodes(1), zoneCodesConflict(2), regionalSubscNotSupported(3) }`.
    #[rasn(tag(context, 5))]
    pub regional_subscription_response: Option<Integer>,
    #[rasn(tag(context, 6))]
    pub supported_camel_phases: Option<BitString>,
    #[rasn(tag(context, 7))]
    pub extension_container: Option<ExtensionContainer>,
    #[rasn(tag(context, 8))]
    pub offered_camel4_csis: Option<BitString>,
    #[rasn(tag(context, 9))]
    pub supported_features: Option<BitString>,
    #[rasn(tag(context, 10))]
    pub ext_supported_features: Option<BitString>,
}

/// DeleteSubscriberData-Arg (op 8).
///
/// See the module docs on member order: `[22]` and `[23]` precede `[21]`.
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct DeleteSubscriberDataArg {
    #[rasn(tag(context, 0))]
    pub imsi: Imsi,
    #[rasn(tag(context, 1))]
    pub basic_service_list: Option<Vec<OctetString>>,
    #[rasn(tag(context, 2))]
    pub ss_list: Option<Vec<OctetString>>,
    #[rasn(tag(context, 4))]
    pub roaming_restriction_due_to_unsupported_feature: Option<()>,
    #[rasn(tag(context, 5))]
    pub regional_subscription_identifier: Option<OctetString>,
    #[rasn(tag(context, 7))]
    pub vbs_group_indication: Option<()>,
    #[rasn(tag(context, 8))]
    pub vgcs_group_indication: Option<()>,
    #[rasn(tag(context, 9))]
    pub camel_subscription_info_withdraw: Option<()>,
    #[rasn(tag(context, 6))]
    pub extension_container: Option<ExtensionContainer>,
    /// A CHOICE, so `[10]` is an **explicit** tag.
    #[rasn(tag(explicit(context, 10)))]
    pub gprs_subscription_data_withdraw: Option<Opaque>,
    #[rasn(tag(context, 11))]
    pub roaming_restricted_in_sgsn_due_to_unsupported_feature: Option<()>,
    /// A CHOICE, so `[12]` is an **explicit** tag.
    #[rasn(tag(explicit(context, 12)))]
    pub lsa_information_withdraw: Option<Opaque>,
    #[rasn(tag(context, 13))]
    pub gmlc_list_withdraw: Option<()>,
    #[rasn(tag(context, 14))]
    pub ist_information_withdraw: Option<()>,
    #[rasn(tag(context, 15))]
    pub specific_csi_withdraw: Option<BitString>,
    #[rasn(tag(context, 16))]
    pub charging_characteristics_withdraw: Option<()>,
    #[rasn(tag(context, 17))]
    pub stn_sr_withdraw: Option<()>,
    /// A CHOICE, so `[18]` is an **explicit** tag.
    #[rasn(tag(explicit(context, 18)))]
    pub eps_subscription_data_withdraw: Option<Opaque>,
    #[rasn(tag(context, 19))]
    pub apn_oi_replacement_withdraw: Option<()>,
    #[rasn(tag(context, 20))]
    pub csg_subscription_deleted: Option<()>,
    #[rasn(tag(context, 22))]
    pub subscribed_periodic_tau_rau_timer_withdraw: Option<()>,
    #[rasn(tag(context, 23))]
    pub subscribed_periodic_lau_timer_withdraw: Option<()>,
    #[rasn(tag(context, 21))]
    pub subscribed_vsrvcc_withdraw: Option<()>,
    #[rasn(tag(context, 24))]
    pub vplmn_csg_subscription_deleted: Option<()>,
    #[rasn(tag(context, 25))]
    pub additional_msisdn_withdraw: Option<()>,
    #[rasn(tag(context, 26))]
    pub cs_to_ps_srvcc_withdraw: Option<()>,
    #[rasn(tag(context, 27))]
    pub imsi_group_id_list_withdraw: Option<()>,
    #[rasn(tag(context, 28))]
    pub user_plane_integrity_protection_withdraw: Option<()>,
    #[rasn(tag(context, 29))]
    pub dl_buffering_suggested_packet_count_withdraw: Option<()>,
    #[rasn(tag(context, 30))]
    pub ue_usage_type_withdraw: Option<()>,
    #[rasn(tag(context, 31))]
    pub reset_ids_withdraw: Option<()>,
    #[rasn(tag(context, 32))]
    pub iab_operation_withdraw: Option<()>,
}

impl DeleteSubscriberDataArg {
    /// The one mandatory member; every optional member starts `None`.
    pub fn new(imsi: Imsi) -> Self {
        Self {
            imsi,
            basic_service_list: None,
            ss_list: None,
            roaming_restriction_due_to_unsupported_feature: None,
            regional_subscription_identifier: None,
            vbs_group_indication: None,
            vgcs_group_indication: None,
            camel_subscription_info_withdraw: None,
            extension_container: None,
            gprs_subscription_data_withdraw: None,
            roaming_restricted_in_sgsn_due_to_unsupported_feature: None,
            lsa_information_withdraw: None,
            gmlc_list_withdraw: None,
            ist_information_withdraw: None,
            specific_csi_withdraw: None,
            charging_characteristics_withdraw: None,
            stn_sr_withdraw: None,
            eps_subscription_data_withdraw: None,
            apn_oi_replacement_withdraw: None,
            csg_subscription_deleted: None,
            subscribed_periodic_tau_rau_timer_withdraw: None,
            subscribed_periodic_lau_timer_withdraw: None,
            subscribed_vsrvcc_withdraw: None,
            vplmn_csg_subscription_deleted: None,
            additional_msisdn_withdraw: None,
            cs_to_ps_srvcc_withdraw: None,
            imsi_group_id_list_withdraw: None,
            user_plane_integrity_protection_withdraw: None,
            dl_buffering_suggested_packet_count_withdraw: None,
            ue_usage_type_withdraw: None,
            reset_ids_withdraw: None,
            iab_operation_withdraw: None,
        }
    }
}

/// DeleteSubscriberData-Res (op 8).
///
/// ```asn1
/// DeleteSubscriberDataRes ::= SEQUENCE {
///     regionalSubscriptionResponse [0] RegionalSubscriptionResponse OPTIONAL,
///     extensionContainer               ExtensionContainer OPTIONAL,
///     ... }
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct DeleteSubscriberDataRes {
    #[rasn(tag(context, 0))]
    pub regional_subscription_response: Option<Integer>,
    pub extension_container: Option<ExtensionContainer>,
}

/// Operation codes for subscriber-data management. Re-exported from
/// [`crate::types::op_codes`].
pub mod op_codes {
    pub use crate::types::op_codes::{DELETE_SUBSCRIBER_DATA, INSERT_SUBSCRIBER_DATA};
}
