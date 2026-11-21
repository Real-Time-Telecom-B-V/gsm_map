//! GPRS subscription data from MAP-MS-DataTypes.

use crate::types::ExtensionContainer;
use rasn::prelude::*;

/// Ambr (TS 29.002). Tags and declaration order follow the ASN.1.
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct Ambr {
    #[rasn(tag(context, 0))]
    pub max_requested_bandwidth_ul: Integer,
    #[rasn(tag(context, 1))]
    pub max_requested_bandwidth_dl: Integer,
    #[rasn(tag(context, 2))]
    pub extension_container: Option<ExtensionContainer>,
    // ... (ASN.1 extension marker)
    #[rasn(tag(context, 3))]
    pub extended_max_requested_bandwidth_ul: Option<Integer>,
    #[rasn(tag(context, 4))]
    pub extended_max_requested_bandwidth_dl: Option<Integer>,
}

impl Ambr {
    /// Mandatory members; optional members start absent.
    pub fn new(max_requested_bandwidth_ul: Integer, max_requested_bandwidth_dl: Integer) -> Self {
        Self {
            max_requested_bandwidth_ul,
            max_requested_bandwidth_dl,
            extension_container: None,
            extended_max_requested_bandwidth_ul: None,
            extended_max_requested_bandwidth_dl: None,
        }
    }
}

/// PdpContext (TS 29.002). Tags and declaration order follow the ASN.1.
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct PdpContext {
    pub pdp_context_id: Integer,
    #[rasn(tag(context, 16))]
    pub pdp_type: OctetString,
    #[rasn(tag(context, 17))]
    pub pdp_address: Option<OctetString>,
    #[rasn(tag(context, 18))]
    pub qos_subscribed: OctetString,
    #[rasn(tag(context, 19))]
    pub vplmn_address_allowed: Option<()>,
    #[rasn(tag(context, 20))]
    pub apn: OctetString,
    #[rasn(tag(context, 21))]
    pub extension_container: Option<ExtensionContainer>,
    // ... (ASN.1 extension marker)
    #[rasn(tag(context, 0))]
    pub ext_qos_subscribed: Option<OctetString>,
    #[rasn(tag(context, 1))]
    pub pdp_charging_characteristics: Option<OctetString>,
    #[rasn(tag(context, 2))]
    pub ext2_qos_subscribed: Option<OctetString>,
    #[rasn(tag(context, 3))]
    pub ext3_qos_subscribed: Option<OctetString>,
    #[rasn(tag(context, 4))]
    pub ext4_qos_subscribed: Option<OctetString>,
    #[rasn(tag(context, 5))]
    pub apn_oi_replacement: Option<OctetString>,
    #[rasn(tag(context, 6))]
    pub ext_pdp_type: Option<OctetString>,
    #[rasn(tag(context, 7))]
    pub ext_pdp_address: Option<OctetString>,
    #[rasn(tag(context, 10))]
    pub ambr: Option<Ambr>,
    #[rasn(tag(context, 8))]
    pub sipto_permission: Option<Integer>,
    #[rasn(tag(context, 9))]
    pub lipa_permission: Option<Integer>,
    #[rasn(tag(context, 11))]
    pub restoration_priority: Option<OctetString>,
    #[rasn(tag(context, 12))]
    pub sipto_local_network_permission: Option<Integer>,
    #[rasn(tag(context, 13))]
    pub nidd_mechanism: Option<Integer>,
    #[rasn(tag(context, 14))]
    pub scef_id: Option<OctetString>,
}

impl PdpContext {
    /// Mandatory members; optional members start absent.
    pub fn new(
        pdp_context_id: Integer,
        pdp_type: OctetString,
        qos_subscribed: OctetString,
        apn: OctetString,
    ) -> Self {
        Self {
            pdp_context_id,
            pdp_type,
            pdp_address: None,
            qos_subscribed,
            vplmn_address_allowed: None,
            apn,
            extension_container: None,
            ext_qos_subscribed: None,
            pdp_charging_characteristics: None,
            ext2_qos_subscribed: None,
            ext3_qos_subscribed: None,
            ext4_qos_subscribed: None,
            apn_oi_replacement: None,
            ext_pdp_type: None,
            ext_pdp_address: None,
            ambr: None,
            sipto_permission: None,
            lipa_permission: None,
            restoration_priority: None,
            sipto_local_network_permission: None,
            nidd_mechanism: None,
            scef_id: None,
        }
    }
}

/// GPRSDataList ::= SEQUENCE OF PDP-Context.
pub type GprsDataList = Vec<PdpContext>;

/// GprsSubscriptionData (TS 29.002). Tags and declaration order follow the ASN.1.
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct GprsSubscriptionData {
    pub complete_data_list_included: Option<()>,
    #[rasn(tag(context, 1))]
    pub gprs_data_list: GprsDataList,
    #[rasn(tag(context, 2))]
    pub extension_container: Option<ExtensionContainer>,
    // ... (ASN.1 extension marker)
    #[rasn(tag(context, 3))]
    pub apn_oi_replacement: Option<OctetString>,
}

impl GprsSubscriptionData {
    /// Mandatory members; optional members start absent.
    pub fn new(gprs_data_list: GprsDataList) -> Self {
        Self {
            complete_data_list_included: None,
            gprs_data_list,
            extension_container: None,
            apn_oi_replacement: None,
        }
    }
}
