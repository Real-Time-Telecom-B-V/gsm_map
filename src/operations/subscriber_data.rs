//! Subscriber Data Management operations — 3GPP TS 29.002.
//!
//! - insertSubscriberData (op 7)
//! - deleteSubscriberData (op 8)

use rasn::prelude::*;

use crate::types::{Imsi, IsdnAddressString};

/// Category — subscriber category (ITU-T Q.763).
pub type Category = OctetString;

/// Bearer service / teleservice codes.
pub type BearerServiceList = Vec<OctetString>;
pub type TeleserviceList = Vec<OctetString>;

/// SubscriberStatus.
#[derive(Debug, Clone, Copy, PartialEq, Eq, AsnType, Decode, Encode)]
#[rasn(enumerated)]
pub enum SubscriberStatus {
    ServiceGranted = 0,
    OperatorDeterminedBarring = 1,
}

/// NetworkAccessMode (v3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, AsnType, Decode, Encode)]
#[rasn(enumerated)]
pub enum NetworkAccessMode {
    PacketAndCircuit = 0,
    OnlyCircuit = 1,
    OnlyPacket = 2,
}

/// InsertSubscriberData-Arg (op 7).
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct InsertSubscriberDataArg {
    /// IMSI (optional in ISD, mandatory context usually known).
    #[rasn(tag(context, 0))]
    pub imsi: Option<Imsi>,
    /// MSISDN.
    #[rasn(tag(context, 1))]
    pub msisdn: Option<IsdnAddressString>,
    /// Category.
    #[rasn(tag(context, 2))]
    pub category: Option<Category>,
    /// Subscriber status.
    #[rasn(tag(context, 3))]
    pub subscriber_status: Option<SubscriberStatus>,
    /// Bearer service list.
    #[rasn(tag(context, 4))]
    pub bearer_service_list: Option<BearerServiceList>,
    /// Teleservice list.
    #[rasn(tag(context, 6))]
    pub teleservice_list: Option<TeleserviceList>,
    /// ODB data (Operator Determined Barring).
    #[rasn(tag(context, 8))]
    pub odb_data: Option<OctetString>,
    /// Roaming restriction due to unsupported feature.
    #[rasn(tag(context, 10))]
    pub roaming_restricted_in_sgsn_due_to_unsupported_feature: Option<()>,
    /// Network access mode.
    #[rasn(tag(context, 14))]
    pub network_access_mode: Option<NetworkAccessMode>,
}

/// InsertSubscriberData-Res (op 7).
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct InsertSubscriberDataRes {
    /// Teleservice list not supported.
    #[rasn(tag(context, 1))]
    pub teleservice_list: Option<TeleserviceList>,
    /// Bearer service list not supported.
    #[rasn(tag(context, 2))]
    pub bearer_service_list: Option<BearerServiceList>,
    /// ODB general data.
    #[rasn(tag(context, 4))]
    pub odb_general_data: Option<OctetString>,
}

/// DeleteSubscriberData-Arg (op 8).
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct DeleteSubscriberDataArg {
    /// IMSI.
    #[rasn(tag(context, 0))]
    pub imsi: Imsi,
    /// Basic service list to delete.
    #[rasn(tag(context, 1))]
    pub basic_service_list: Option<Vec<OctetString>>,
    /// SS list to delete.
    #[rasn(tag(context, 2))]
    pub ss_list: Option<Vec<OctetString>>,
    /// Roaming restriction due to unsupported feature.
    #[rasn(tag(context, 4))]
    pub roaming_restricted_in_sgsn_due_to_unsupported_feature: Option<()>,
}

/// DeleteSubscriberData-Res (op 8).
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct DeleteSubscriberDataRes {}

pub mod op_codes {
    pub const INSERT_SUBSCRIBER_DATA: i64 = 7;
    pub const DELETE_SUBSCRIBER_DATA: i64 = 8;
}
