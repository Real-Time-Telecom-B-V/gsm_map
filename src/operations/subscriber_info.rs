//! Subscriber Information operations — 3GPP TS 29.002.
//!
//! - provideSubscriberInfo (op 70)
//! - anyTimeInterrogation (op 71)
//! - anyTimeSubscriberDataModification (op 65)

use rasn::prelude::*;

use crate::types::{Imsi, IsdnAddressString};

/// SubscriberState.
#[derive(Debug, Clone, Copy, PartialEq, Eq, AsnType, Decode, Encode)]
#[rasn(enumerated)]
pub enum SubscriberState {
    AssumedIdle = 0,
    CamelBusy = 1,
    NetDetNotReachable = 2,
    NotProvidedFromVlr = 3,
}

/// GeographicalInformation — 8 bytes.
pub type GeographicalInformation = OctetString;

/// CellGlobalIdOrServiceAreaIdOrLAI.
pub type CellGlobalIdOrServiceAreaIdOrLai = OctetString;

/// LocationInformationWithLMSI — extended location info.
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct SubscriberLocationInfo {
    #[rasn(tag(context, 0))]
    pub age_of_location_information: Option<Integer>,
    #[rasn(tag(context, 1))]
    pub geographical_information: Option<GeographicalInformation>,
    #[rasn(tag(context, 2))]
    pub vlr_number: Option<IsdnAddressString>,
    #[rasn(tag(context, 3))]
    pub location_number: Option<OctetString>,
    #[rasn(tag(context, 4))]
    pub cell_global_id_or_service_area_id_or_lai: Option<CellGlobalIdOrServiceAreaIdOrLai>,
    #[rasn(tag(context, 8))]
    pub selected_lsa_id: Option<OctetString>,
    #[rasn(tag(context, 9))]
    pub msc_number: Option<IsdnAddressString>,
    #[rasn(tag(context, 13))]
    pub sai_present: Option<()>,
}

/// SubscriberInfo — returned by provideSubscriberInfo and anyTimeInterrogation.
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct SubscriberInfo {
    #[rasn(tag(context, 0))]
    pub location_information: Option<SubscriberLocationInfo>,
    #[rasn(tag(context, 1))]
    pub subscriber_state: Option<SubscriberState>,
    #[rasn(tag(context, 4))]
    pub imei: Option<OctetString>,
    #[rasn(tag(context, 5))]
    pub ms_classmark2: Option<OctetString>,
    #[rasn(tag(context, 6))]
    pub gprs_ms_class: Option<OctetString>,
    #[rasn(tag(context, 11))]
    pub mn_p_info_res: Option<OctetString>,
}

/// RequestedInfo — specifies what info to return.
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct RequestedInfo {
    #[rasn(tag(context, 0))]
    pub location_information: Option<()>,
    #[rasn(tag(context, 1))]
    pub subscriber_state: Option<()>,
    #[rasn(tag(context, 3))]
    pub current_location: Option<()>,
    #[rasn(tag(context, 6))]
    pub imei: Option<()>,
    #[rasn(tag(context, 7))]
    pub ms_classmark: Option<()>,
    #[rasn(tag(context, 8))]
    pub mn_p_requested_info: Option<()>,
}

/// ProvideSubscriberInfo-Arg (op 70).
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct ProvideSubscriberInfoArg {
    #[rasn(tag(context, 0))]
    pub imsi: Imsi,
    #[rasn(tag(context, 1))]
    pub lmsi: Option<OctetString>,
    #[rasn(tag(context, 2))]
    pub requested_info: RequestedInfo,
}

/// ProvideSubscriberInfo-Res (op 70).
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct ProvideSubscriberInfoRes {
    pub subscriber_info: SubscriberInfo,
}

/// SubscriberIdentity — CHOICE used in ATI.
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
#[rasn(choice)]
pub enum SubscriberIdentity {
    #[rasn(tag(context, 0))]
    Imsi(Imsi),
    #[rasn(tag(context, 1))]
    Msisdn(IsdnAddressString),
}

/// AnyTimeInterrogation-Arg (op 71).
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct AnyTimeInterrogationArg {
    #[rasn(tag(context, 0))]
    pub subscriber_identity: SubscriberIdentity,
    #[rasn(tag(context, 1))]
    pub requested_info: RequestedInfo,
    #[rasn(tag(context, 3))]
    pub gsm_scf_address: IsdnAddressString,
}

/// AnyTimeInterrogation-Res (op 71).
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct AnyTimeInterrogationRes {
    pub subscriber_info: SubscriberInfo,
}

/// AnyTimeSubscriberDataModification-Arg (op 65).
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct AnyTimeModificationArg {
    #[rasn(tag(context, 0))]
    pub subscriber_identity: SubscriberIdentity,
    #[rasn(tag(context, 1))]
    pub gsm_scf_address: IsdnAddressString,
    #[rasn(tag(context, 2))]
    pub modification_request_for_cf_info: Option<OctetString>,
    #[rasn(tag(context, 3))]
    pub modification_request_for_cb_info: Option<OctetString>,
    #[rasn(tag(context, 4))]
    pub modification_request_for_csi: Option<OctetString>,
}

/// AnyTimeSubscriberDataModification-Res (op 65).
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct AnyTimeModificationRes {
    #[rasn(tag(context, 0))]
    pub ss_info_for_cse: Option<OctetString>,
}

pub mod op_codes {
    pub const PROVIDE_SUBSCRIBER_INFO: i64 = 70;
    pub const ANY_TIME_INTERROGATION: i64 = 71;
    pub const ANY_TIME_MODIFICATION: i64 = 65;
}
