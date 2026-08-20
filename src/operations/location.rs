//! Location Management operations — 3GPP TS 29.002.
//!
//! - updateLocation (op 2)
//! - cancelLocation (op 3)
//! - purgeMS (op 67)
//! - sendIdentification (op 55)
//!
//! Every member TS 29.002 defines is modelled; see [`crate`] on why an
//! unmodelled member is fatal rather than merely absent. Sub-structures this
//! crate does not interpret are carried as [`Opaque`] and survive the round trip
//! unchanged.

use rasn::prelude::*;

use crate::types::{
    ExtensionContainer, Imsi, IsdnAddressString, Lmsi, NetworkNodeDiameterAddress, Opaque,
};

/// GSN-Address — an SGSN/GGSN/GMLC IP address in its MAP OCTET STRING form.
pub type GsnAddress = OctetString;

/// UpdateLocation-Arg (op 2).
///
/// ```asn1
/// UpdateLocationArg ::= SEQUENCE {
///     imsi                            IMSI,
///     msc-Number                  [1] ISDN-AddressString,
///     vlr-Number                      ISDN-AddressString,
///     lmsi                       [10] LMSI OPTIONAL,
///     extensionContainer              ExtensionContainer OPTIONAL,
///     ...,
///     vlr-Capability              [6] VLR-Capability OPTIONAL,
///     informPreviousNetworkEntity [11] NULL OPTIONAL,
///     cs-LCS-NotSupportedByUE    [12] NULL OPTIONAL,
///     v-gmlc-Address              [2] GSN-Address OPTIONAL,
///     add-info                   [13] ADD-Info OPTIONAL,
///     pagingArea                 [14] PagingArea OPTIONAL,
///     skipSubscriberDataUpdate   [15] NULL OPTIONAL,
///     restorationIndicator       [16] NULL OPTIONAL,
///     eplmn-List                  [3] EPLMN-List OPTIONAL,
///     mme-DiameterAddress         [4] NetworkNodeDiameterAddress OPTIONAL }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct UpdateLocationArg {
    /// IMSI of the subscriber.
    pub imsi: Imsi,
    /// ISDN number of the serving MSC.
    #[rasn(tag(context, 1))]
    pub msc_number: IsdnAddressString,
    /// VLR number.
    pub vlr_number: IsdnAddressString,
    #[rasn(tag(context, 10))]
    pub lmsi: Option<Lmsi>,
    pub extension_container: Option<ExtensionContainer>,
    #[rasn(tag(context, 6))]
    pub vlr_capability: Option<Opaque>,
    #[rasn(tag(context, 11))]
    pub inform_previous_network_entity: Option<()>,
    #[rasn(tag(context, 12))]
    pub cs_lcs_not_supported_by_ue: Option<()>,
    #[rasn(tag(context, 2))]
    pub v_gmlc_address: Option<GsnAddress>,
    #[rasn(tag(context, 13))]
    pub add_info: Option<Opaque>,
    #[rasn(tag(context, 14))]
    pub paging_area: Option<Opaque>,
    #[rasn(tag(context, 15))]
    pub skip_subscriber_data_update: Option<()>,
    #[rasn(tag(context, 16))]
    pub restoration_indicator: Option<()>,
    #[rasn(tag(context, 3))]
    pub eplmn_list: Option<Opaque>,
    #[rasn(tag(context, 4))]
    pub mme_diameter_address: Option<NetworkNodeDiameterAddress>,
}

impl UpdateLocationArg {
    /// The three mandatory members; every optional member starts `None`.
    pub fn new(imsi: Imsi, msc_number: IsdnAddressString, vlr_number: IsdnAddressString) -> Self {
        Self {
            imsi,
            msc_number,
            vlr_number,
            lmsi: None,
            extension_container: None,
            vlr_capability: None,
            inform_previous_network_entity: None,
            cs_lcs_not_supported_by_ue: None,
            v_gmlc_address: None,
            add_info: None,
            paging_area: None,
            skip_subscriber_data_update: None,
            restoration_indicator: None,
            eplmn_list: None,
            mme_diameter_address: None,
        }
    }
}

/// UpdateLocation-Res (op 2).
///
/// ```asn1
/// UpdateLocationRes ::= SEQUENCE {
///     hlr-Number                 ISDN-AddressString,
///     extensionContainer         ExtensionContainer OPTIONAL,
///     ...,
///     add-Capability             NULL OPTIONAL,
///     pagingArea-Capability  [0] NULL OPTIONAL }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct UpdateLocationRes {
    /// HLR number.
    pub hlr_number: IsdnAddressString,
    pub extension_container: Option<ExtensionContainer>,
    pub add_capability: Option<()>,
    #[rasn(tag(context, 0))]
    pub paging_area_capability: Option<()>,
}

impl UpdateLocationRes {
    /// The one mandatory member; every optional member starts `None`.
    pub fn new(hlr_number: IsdnAddressString) -> Self {
        Self {
            hlr_number,
            extension_container: None,
            add_capability: None,
            paging_area_capability: None,
        }
    }
}

/// IMSI-WithLMSI — the second [`Identity`] alternative.
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct ImsiWithLmsi {
    pub imsi: Imsi,
    pub lmsi: Lmsi,
}

/// Identity — how cancelLocation names the subscriber.
///
/// ```asn1
/// Identity ::= CHOICE {
///     imsi          IMSI,
///     imsi-WithLMSI IMSI-WithLMSI }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
#[rasn(choice)]
pub enum Identity {
    Imsi(Imsi),
    ImsiWithLmsi(ImsiWithLmsi),
}

/// CancellationType for cancelLocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, AsnType, Decode, Encode)]
#[rasn(enumerated)]
pub enum CancellationType {
    UpdateProcedure = 0,
    SubscriptionWithdraw = 1,
    InitialAttachProcedure = 2,
}

/// CancelLocation-Arg (op 3).
///
/// ```asn1
/// CancelLocationArg ::= [3] SEQUENCE {
///     identity                            Identity,
///     cancellationType                    CancellationType OPTIONAL,
///     extensionContainer                  ExtensionContainer OPTIONAL,
///     ...,
///     typeOfUpdate                    [0] TypeOfUpdate OPTIONAL,
///     mtrf-SupportedAndAuthorized     [1] NULL OPTIONAL,
///     mtrf-SupportedAndNotAuthorized  [2] NULL OPTIONAL,
///     newMSC-Number                   [3] ISDN-AddressString OPTIONAL,
///     newVLR-Number                   [4] ISDN-AddressString OPTIONAL,
///     new-lmsi                        [5] LMSI OPTIONAL,
///     reattach-Required               [6] NULL OPTIONAL }
/// ```
///
/// The whole argument carries context tag `[3]`, which is what distinguishes it
/// from the bare `Identity` a v1/v2 peer sends.
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
#[rasn(tag(context, 3))]
pub struct CancelLocationArg {
    pub identity: Identity,
    pub cancellation_type: Option<CancellationType>,
    pub extension_container: Option<ExtensionContainer>,
    /// `TypeOfUpdate ::= ENUMERATED { sgsn-change(0), mme-change(1) }`.
    #[rasn(tag(context, 0))]
    pub type_of_update: Option<Integer>,
    #[rasn(tag(context, 1))]
    pub mtrf_supported_and_authorized: Option<()>,
    #[rasn(tag(context, 2))]
    pub mtrf_supported_and_not_authorized: Option<()>,
    #[rasn(tag(context, 3))]
    pub new_msc_number: Option<IsdnAddressString>,
    #[rasn(tag(context, 4))]
    pub new_vlr_number: Option<IsdnAddressString>,
    #[rasn(tag(context, 5))]
    pub new_lmsi: Option<Lmsi>,
    #[rasn(tag(context, 6))]
    pub reattach_required: Option<()>,
}

impl CancelLocationArg {
    /// The one mandatory member; every optional member starts `None`.
    pub fn new(identity: Identity) -> Self {
        Self {
            identity,
            cancellation_type: None,
            extension_container: None,
            type_of_update: None,
            mtrf_supported_and_authorized: None,
            mtrf_supported_and_not_authorized: None,
            new_msc_number: None,
            new_vlr_number: None,
            new_lmsi: None,
            reattach_required: None,
        }
    }
}

/// CancelLocation-Res (op 3).
///
/// ```asn1
/// CancelLocationRes ::= SEQUENCE {
///     extensionContainer  ExtensionContainer OPTIONAL,
///     ... }
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct CancelLocationRes {
    pub extension_container: Option<ExtensionContainer>,
}

/// PurgeMS-Arg (op 67).
///
/// ```asn1
/// PurgeMS-Arg ::= [3] SEQUENCE {
///     imsi                IMSI,
///     vlr-Number      [0] ISDN-AddressString OPTIONAL,
///     sgsn-Number     [1] ISDN-AddressString OPTIONAL,
///     extensionContainer  ExtensionContainer OPTIONAL,
///     ... }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
#[rasn(tag(context, 3))]
pub struct PurgeMsArg {
    /// IMSI of the subscriber.
    pub imsi: Imsi,
    #[rasn(tag(context, 0))]
    pub vlr_number: Option<IsdnAddressString>,
    #[rasn(tag(context, 1))]
    pub sgsn_number: Option<IsdnAddressString>,
    pub extension_container: Option<ExtensionContainer>,
}

impl PurgeMsArg {
    /// The one mandatory member; every optional member starts `None`.
    pub fn new(imsi: Imsi) -> Self {
        Self {
            imsi,
            vlr_number: None,
            sgsn_number: None,
            extension_container: None,
        }
    }
}

/// PurgeMS-Res (op 67).
///
/// ```asn1
/// PurgeMS-Res ::= SEQUENCE {
///     freezeTMSI      [0] NULL OPTIONAL,
///     freezeP-TMSI    [1] NULL OPTIONAL,
///     extensionContainer  ExtensionContainer OPTIONAL,
///     ...,
///     freezeM-TMSI    [2] NULL OPTIONAL }
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct PurgeMsRes {
    #[rasn(tag(context, 0))]
    pub freeze_tmsi: Option<()>,
    #[rasn(tag(context, 1))]
    pub freeze_p_tmsi: Option<()>,
    pub extension_container: Option<ExtensionContainer>,
    #[rasn(tag(context, 2))]
    pub freeze_m_tmsi: Option<()>,
}

/// SendIdentification-Arg (op 55).
///
/// ```asn1
/// SendIdentificationArg ::= SEQUENCE {
///     tmsi                             TMSI,
///     numberOfRequestedVectors         NumberOfRequestedVectors OPTIONAL,
///     segmentationProhibited           NULL OPTIONAL,
///     extensionContainer               ExtensionContainer OPTIONAL,
///     ...,
///     msc-Number                       ISDN-AddressString OPTIONAL,
///     previous-LAI                 [0] LAIFixedLength OPTIONAL,
///     hopCounter                   [1] HopCounter OPTIONAL,
///     mtRoamingForwardingSupported [2] NULL OPTIONAL,
///     newVLR-Number                [3] ISDN-AddressString OPTIONAL,
///     new-lmsi                     [4] LMSI OPTIONAL }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct SendIdentificationArg {
    /// TMSI the new VLR received from the MS.
    pub tmsi: OctetString,
    pub number_of_requested_vectors: Option<Integer>,
    pub segmentation_prohibited: Option<()>,
    pub extension_container: Option<ExtensionContainer>,
    pub msc_number: Option<IsdnAddressString>,
    #[rasn(tag(context, 0))]
    pub previous_lai: Option<OctetString>,
    #[rasn(tag(context, 1))]
    pub hop_counter: Option<Integer>,
    #[rasn(tag(context, 2))]
    pub mt_roaming_forwarding_supported: Option<()>,
    #[rasn(tag(context, 3))]
    pub new_vlr_number: Option<IsdnAddressString>,
    #[rasn(tag(context, 4))]
    pub new_lmsi: Option<Lmsi>,
}

impl SendIdentificationArg {
    /// The one mandatory member; every optional member starts `None`.
    pub fn new(tmsi: OctetString) -> Self {
        Self {
            tmsi,
            number_of_requested_vectors: None,
            segmentation_prohibited: None,
            extension_container: None,
            msc_number: None,
            previous_lai: None,
            hop_counter: None,
            mt_roaming_forwarding_supported: None,
            new_vlr_number: None,
            new_lmsi: None,
        }
    }
}

/// SendIdentification-Res (op 55).
///
/// ```asn1
/// SendIdentificationRes ::= [3] SEQUENCE {
///     imsi                    IMSI OPTIONAL,
///     authenticationSetList   AuthenticationSetList OPTIONAL,
///     currentSecurityContext  [2] CurrentSecurityContext OPTIONAL,
///     extensionContainer      [3] ExtensionContainer OPTIONAL,
///     ...,
///     lastUsedLtePLMN-Id      [4] PLMN-Id OPTIONAL }
/// ```
///
/// `authenticationSetList` is an **untagged optional CHOICE**; see
/// [`SendAuthenticationInfoRes`](crate::operations::auth::SendAuthenticationInfoRes)
/// on why its two alternatives are separate fields here.
#[derive(Debug, Clone, Default, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct SendIdentificationRes {
    /// IMSI of the subscriber.
    pub imsi: Option<Imsi>,
    #[rasn(tag(context, 0))]
    pub triplet_list: Option<Vec<crate::operations::auth::AuthenticationTriplet>>,
    #[rasn(tag(context, 1))]
    pub quintuplet_list: Option<Vec<crate::operations::auth::AuthenticationQuintuplet>>,
    /// `CurrentSecurityContext` is a CHOICE, so `[2]` is an **explicit** tag.
    #[rasn(tag(explicit(context, 2)))]
    pub current_security_context: Option<Opaque>,
    #[rasn(tag(context, 3))]
    pub extension_container: Option<ExtensionContainer>,
    #[rasn(tag(context, 4))]
    pub last_used_lte_plmn_id: Option<OctetString>,
}

/// Operation codes for location management. Re-exported from
/// [`crate::types::op_codes`], the single registry `operation_name()` resolves
/// against.
pub mod op_codes {
    pub use crate::types::op_codes::{
        CANCEL_LOCATION, CANCEL_VCSG_LOCATION, PURGE_MS, SEND_IDENTIFICATION, UPDATE_LOCATION,
        UPDATE_VCSG_LOCATION,
    };
}

/// UpdateVcsgLocation-Arg (op 53) — register the subscriber's VPLMN CSG
/// subscription with the HLR.
///
/// ```asn1
/// UpdateVcsgLocationArg ::= SEQUENCE {
///     imsi                    IMSI,
///     msisdn              [2] ISDN-AddressString OPTIONAL,
///     vlr-Number          [0] ISDN-AddressString OPTIONAL,
///     sgsn-Number         [1] ISDN-AddressString OPTIONAL,
///     extensionContainer      ExtensionContainer OPTIONAL,
///     ... }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct UpdateVcsgLocationArg {
    pub imsi: Imsi,
    /// Declared ahead of `[0]` and `[1]`, and BER encodes in declaration order.
    #[rasn(tag(context, 2))]
    pub msisdn: Option<IsdnAddressString>,
    #[rasn(tag(context, 0))]
    pub vlr_number: Option<IsdnAddressString>,
    #[rasn(tag(context, 1))]
    pub sgsn_number: Option<IsdnAddressString>,
    pub extension_container: Option<ExtensionContainer>,
}

impl UpdateVcsgLocationArg {
    /// The one mandatory member; every optional member starts `None`.
    pub fn new(imsi: Imsi) -> Self {
        Self {
            imsi,
            msisdn: None,
            vlr_number: None,
            sgsn_number: None,
            extension_container: None,
        }
    }
}

/// UpdateVcsgLocation-Res (op 53).
///
/// ```asn1
/// UpdateVcsgLocationRes ::= SEQUENCE {
///     temporaryEmptySubscriptiondataIndicator NULL OPTIONAL,
///     extensionContainer                      ExtensionContainer OPTIONAL,
///     ... }
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct UpdateVcsgLocationRes {
    pub temporary_empty_subscription_data_indicator: Option<()>,
    pub extension_container: Option<ExtensionContainer>,
}

/// CancelVcsgLocation-Arg (op 36).
///
/// ```asn1
/// CancelVcsgLocationArg ::= SEQUENCE {
///     identity            Identity,
///     extensionContainer  ExtensionContainer OPTIONAL,
///     ... }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct CancelVcsgLocationArg {
    pub identity: Identity,
    pub extension_container: Option<ExtensionContainer>,
}

/// CancelVcsgLocation-Res (op 36).
#[derive(Debug, Clone, Default, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct CancelVcsgLocationRes {
    pub extension_container: Option<ExtensionContainer>,
}
