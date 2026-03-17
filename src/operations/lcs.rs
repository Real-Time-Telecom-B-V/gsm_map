//! LCS (Location Services) operations — 3GPP TS 29.002.
//!
//! - provideSubscriberLocation (op 83)
//! - subscriberLocationReport (op 86)
//! - sendRoutingInfoForLCS (op 85)

use rasn::prelude::*;

use crate::types::{Imsi, IsdnAddressString};

/// LocationType.
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct LocationType {
    #[rasn(tag(context, 0))]
    pub location_estimate_type: LocationEstimateType,
    #[rasn(tag(context, 1))]
    pub deferred_location_event_type: Option<OctetString>,
}

/// LocationEstimateType.
#[derive(Debug, Clone, Copy, PartialEq, Eq, AsnType, Decode, Encode)]
#[rasn(enumerated)]
pub enum LocationEstimateType {
    CurrentLocation = 0,
    CurrentOrLastKnownLocation = 1,
    InitialLocation = 2,
    ActivateDeferredLocation = 3,
    CancelDeferredLocation = 4,
}

/// LCS-ClientID.
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct LcsClientId {
    #[rasn(tag(context, 0))]
    pub lcs_client_type: LcsClientType,
    #[rasn(tag(context, 1))]
    pub lcs_client_external_id: Option<OctetString>,
    #[rasn(tag(context, 2))]
    pub lcs_client_dialed_by_ms: Option<OctetString>,
    #[rasn(tag(context, 3))]
    pub lcs_client_internal_id: Option<Integer>,
    #[rasn(tag(context, 4))]
    pub lcs_client_name: Option<OctetString>,
}

/// LCS-ClientType.
#[derive(Debug, Clone, Copy, PartialEq, Eq, AsnType, Decode, Encode)]
#[rasn(enumerated)]
pub enum LcsClientType {
    EmergencyServices = 0,
    ValueAddedServices = 1,
    PlmnOperatorServices = 2,
    LawfulInterceptServices = 3,
}

/// ProvideSubscriberLocation-Arg (op 83).
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct ProvideSubscriberLocationArg {
    pub location_type: LocationType,
    pub mlc_number: IsdnAddressString,
    #[rasn(tag(context, 0))]
    pub lcs_client_id: Option<LcsClientId>,
    #[rasn(tag(context, 2))]
    pub imsi: Option<Imsi>,
    #[rasn(tag(context, 3))]
    pub msisdn: Option<IsdnAddressString>,
    #[rasn(tag(context, 5))]
    pub imei: Option<OctetString>,
    #[rasn(tag(context, 6))]
    pub lcs_priority: Option<OctetString>,
    #[rasn(tag(context, 7))]
    pub lcs_qos: Option<OctetString>,
    #[rasn(tag(context, 9))]
    pub lcs_service_type_id: Option<Integer>,
}

/// ProvideSubscriberLocation-Res (op 83).
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct ProvideSubscriberLocationRes {
    pub location_estimate: OctetString,
    #[rasn(tag(context, 0))]
    pub age_of_location_estimate: Option<Integer>,
    #[rasn(tag(context, 2))]
    pub additional_location_estimate: Option<OctetString>,
    #[rasn(tag(context, 3))]
    pub deferred_mt_lr_response_indicator: Option<()>,
    #[rasn(tag(context, 5))]
    pub cell_id_or_sai: Option<OctetString>,
    #[rasn(tag(context, 6))]
    pub accuracy_fulfilment_indicator: Option<Integer>,
}

/// SubscriberLocationReport-Arg (op 86).
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct SubscriberLocationReportArg {
    pub lcs_event: LcsEvent,
    pub lcs_client_id: LcsClientId,
    pub network_node_number: IsdnAddressString,
    #[rasn(tag(context, 0))]
    pub msisdn: Option<IsdnAddressString>,
    #[rasn(tag(context, 1))]
    pub imsi: Option<Imsi>,
    #[rasn(tag(context, 2))]
    pub imei: Option<OctetString>,
    #[rasn(tag(context, 4))]
    pub location_estimate: Option<OctetString>,
    #[rasn(tag(context, 5))]
    pub age_of_location_estimate: Option<Integer>,
}

/// SubscriberLocationReport-Res (op 86).
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct SubscriberLocationReportRes {
    #[rasn(tag(context, 0))]
    pub na_esrd: Option<IsdnAddressString>,
    #[rasn(tag(context, 1))]
    pub na_esrk: Option<IsdnAddressString>,
}

/// LCS-Event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, AsnType, Decode, Encode)]
#[rasn(enumerated)]
pub enum LcsEvent {
    EmergencyCallOrigination = 0,
    EmergencyCallRelease = 1,
    MoLr = 2,
    DeferredMtLrResponse = 3,
    DeferredMoLrTttpInitiation = 4,
}

/// SendRoutingInfoForLCS-Arg (op 85).
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct SendRoutingInfoForLcsArg {
    #[rasn(tag(context, 0))]
    pub mlc_number: IsdnAddressString,
    #[rasn(tag(context, 1))]
    pub target_ms: SubscriberIdentityLcs,
}

/// SubscriberIdentity for LCS.
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
#[rasn(choice)]
pub enum SubscriberIdentityLcs {
    #[rasn(tag(context, 0))]
    Imsi(Imsi),
    #[rasn(tag(context, 1))]
    Msisdn(IsdnAddressString),
}

/// SendRoutingInfoForLCS-Res (op 85).
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct SendRoutingInfoForLcsRes {
    #[rasn(tag(context, 0))]
    pub target_ms: SubscriberIdentityLcs,
    #[rasn(tag(context, 1))]
    pub lcs_location_info: OctetString,
}

pub mod op_codes {
    pub const PROVIDE_SUBSCRIBER_LOCATION: i64 = 83;
    pub const SEND_ROUTING_INFO_FOR_LCS: i64 = 85;
    pub const SUBSCRIBER_LOCATION_REPORT: i64 = 86;
}
