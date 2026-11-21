//! CAMEL subscription data from MAP-MS-DataTypes.
//! VLR vt-CSI carries T-CSI; the VLR sequence has no separate t-CSI member.

use crate::types::{ExtensionContainer, IsdnAddressString, Opaque};
use rasn::prelude::*;

crate::types::extensible_enumerated! {
    /// O-BcsmTriggerDetectionPoint ::= ENUMERATED { collectedInfo(2), ..., routeSelectFailure(4) }.
    pub enum OBcsmTriggerDetectionPoint {
        CollectedInfo = 2,
        RouteSelectFailure = 4,
    }
}

crate::types::extensible_enumerated! {
    /// T-BcsmTriggerDetectionPoint ::= ENUMERATED { termAttemptAuthorized(12), ..., tBusy(13), tNoAnswer(14) }.
    pub enum TBcsmTriggerDetectionPoint {
        TermAttemptAuthorized = 12,
        TBusy = 13,
        TNoAnswer = 14,
    }
}

crate::types::extensible_enumerated! {
    /// DefaultCallHandling ::= ENUMERATED { continueCall(0), releaseCall(1), ... }.
    pub enum DefaultCallHandling {
        ContinueCall = 0,
        ReleaseCall = 1,
    }
}

/// OBcsmCamelTdpData (TS 29.002). Tags and declaration order follow the ASN.1.
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct OBcsmCamelTdpData {
    pub o_bcsm_trigger_detection_point: OBcsmTriggerDetectionPoint,
    pub service_key: Integer,
    #[rasn(tag(context, 0))]
    pub gsm_scf_address: IsdnAddressString,
    #[rasn(tag(context, 1))]
    pub default_call_handling: DefaultCallHandling,
    #[rasn(tag(context, 2))]
    pub extension_container: Option<ExtensionContainer>,
    // ... (ASN.1 extension marker)
}

impl OBcsmCamelTdpData {
    /// Mandatory members; optional members start absent.
    pub fn new(
        o_bcsm_trigger_detection_point: OBcsmTriggerDetectionPoint,
        service_key: Integer,
        gsm_scf_address: IsdnAddressString,
        default_call_handling: DefaultCallHandling,
    ) -> Self {
        Self {
            o_bcsm_trigger_detection_point,
            service_key,
            gsm_scf_address,
            default_call_handling,
            extension_container: None,
        }
    }
}

/// O-BcsmCamelTDPDataList, a SEQUENCE OF trigger data.
pub type OBcsmCamelTdpDataList = Vec<OBcsmCamelTdpData>;

/// OCsi (TS 29.002). Tags and declaration order follow the ASN.1.
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct OCsi {
    pub o_bcsm_camel_tdp_data_list: OBcsmCamelTdpDataList,
    pub extension_container: Option<ExtensionContainer>,
    // ... (ASN.1 extension marker)
    #[rasn(tag(context, 0))]
    pub camel_capability_handling: Option<Integer>,
    #[rasn(tag(context, 1))]
    pub notification_to_cse: Option<()>,
    #[rasn(tag(context, 2))]
    pub csi_active: Option<()>,
}

impl OCsi {
    /// Mandatory members; optional members start absent.
    pub fn new(o_bcsm_camel_tdp_data_list: OBcsmCamelTdpDataList) -> Self {
        Self {
            o_bcsm_camel_tdp_data_list,
            extension_container: None,
            camel_capability_handling: None,
            notification_to_cse: None,
            csi_active: None,
        }
    }
}

/// TBcsmCamelTdpData (TS 29.002). Tags and declaration order follow the ASN.1.
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct TBcsmCamelTdpData {
    pub t_bcsm_trigger_detection_point: TBcsmTriggerDetectionPoint,
    pub service_key: Integer,
    #[rasn(tag(context, 0))]
    pub gsm_scf_address: IsdnAddressString,
    #[rasn(tag(context, 1))]
    pub default_call_handling: DefaultCallHandling,
    #[rasn(tag(context, 2))]
    pub extension_container: Option<ExtensionContainer>,
    // ... (ASN.1 extension marker)
}

impl TBcsmCamelTdpData {
    /// Mandatory members; optional members start absent.
    pub fn new(
        t_bcsm_trigger_detection_point: TBcsmTriggerDetectionPoint,
        service_key: Integer,
        gsm_scf_address: IsdnAddressString,
        default_call_handling: DefaultCallHandling,
    ) -> Self {
        Self {
            t_bcsm_trigger_detection_point,
            service_key,
            gsm_scf_address,
            default_call_handling,
            extension_container: None,
        }
    }
}

/// T-BcsmCamelTDPDataList, a SEQUENCE OF trigger data.
pub type TBcsmCamelTdpDataList = Vec<TBcsmCamelTdpData>;

/// TCsi (TS 29.002). Tags and declaration order follow the ASN.1.
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct TCsi {
    pub t_bcsm_camel_tdp_data_list: TBcsmCamelTdpDataList,
    pub extension_container: Option<ExtensionContainer>,
    // ... (ASN.1 extension marker)
    #[rasn(tag(context, 0))]
    pub camel_capability_handling: Option<Integer>,
    #[rasn(tag(context, 1))]
    pub notification_to_cse: Option<()>,
    #[rasn(tag(context, 2))]
    pub csi_active: Option<()>,
}

impl TCsi {
    /// Mandatory members; optional members start absent.
    pub fn new(t_bcsm_camel_tdp_data_list: TBcsmCamelTdpDataList) -> Self {
        Self {
            t_bcsm_camel_tdp_data_list,
            extension_container: None,
            camel_capability_handling: None,
            notification_to_cse: None,
            csi_active: None,
        }
    }
}

/// VlrCamelSubscriptionInfo (TS 29.002). Tags and declaration order follow the ASN.1.
#[derive(Debug, Clone, Default, PartialEq, Eq, AsnType, Decode)]
pub struct VlrCamelSubscriptionInfo {
    #[rasn(tag(context, 0))]
    pub o_csi: Option<OCsi>,
    #[rasn(tag(context, 1))]
    pub extension_container: Option<ExtensionContainer>,
    // ... (ASN.1 extension marker)
    #[rasn(tag(context, 2))]
    pub ss_csi: Option<Opaque>,
    #[rasn(tag(context, 4))]
    pub o_bcsm_camel_tdp_criteria_list: Option<Opaque>,
    /// Uninterpreted primitive content of tif-CSI [3] NULL (normally empty).
    #[rasn(tag(context, 3))]
    pub tif_csi: Option<Any>,
    #[rasn(tag(context, 5))]
    pub m_csi: Option<Opaque>,
    #[rasn(tag(context, 6))]
    pub mo_sms_csi: Option<Opaque>,
    #[rasn(tag(context, 7))]
    pub vt_csi: Option<Opaque>,
    #[rasn(tag(context, 8))]
    pub t_bcsm_camel_tdp_criteria_list: Option<Opaque>,
    #[rasn(tag(context, 9))]
    pub d_csi: Option<Opaque>,
    #[rasn(tag(context, 10))]
    pub mt_sms_csi: Option<Opaque>,
    #[rasn(tag(context, 11))]
    pub mt_sms_camel_tdp_criteria_list: Option<Opaque>,
}

impl VlrCamelSubscriptionInfo {
    /// Store T-CSI as the VLR's vt-CSI [7], retaining the opaque field API.
    pub fn set_vt_csi(&mut self, value: &TCsi) -> Result<(), crate::MapError> {
        self.vt_csi = Some(Opaque::from_sequence(value)?);
        Ok(())
    }
    /// Decode the VLR's vt-CSI as T-CSI with the strict MAP decoder.
    pub fn vt_csi_typed(&self) -> Option<Result<TCsi, crate::MapError>> {
        self.vt_csi.as_ref().map(Opaque::decode_sequence)
    }
}

impl Encode for VlrCamelSubscriptionInfo {
    fn encode_with_tag_and_constraints<'b, E: Encoder<'b>>(
        &self,
        encoder: &mut E,
        tag: Tag,
        _: &Constraints,
        identifier: Identifier,
    ) -> Result<(), E::Error> {
        encoder
            .encode_sequence::<12, 0, Self, _>(
                tag,
                |encoder| {
                    self.o_csi
                        .encode_with_tag(encoder, Tag::new(Class::Context, 0))?;
                    self.extension_container
                        .encode_with_tag(encoder, Tag::new(Class::Context, 1))?;
                    self.ss_csi
                        .encode_with_tag(encoder, Tag::new(Class::Context, 2))?;
                    self.o_bcsm_camel_tdp_criteria_list
                        .encode_with_tag(encoder, Tag::new(Class::Context, 4))?;
                    // Any omits empty content and wraps nonempty content as constructed.
                    // This member must retain its primitive context tag even when empty.
                    self.tif_csi
                        .as_ref()
                        .map(|value| OctetString::from_slice(value.as_bytes()))
                        .encode_with_tag(encoder, Tag::new(Class::Context, 3))?;
                    self.m_csi
                        .encode_with_tag(encoder, Tag::new(Class::Context, 5))?;
                    self.mo_sms_csi
                        .encode_with_tag(encoder, Tag::new(Class::Context, 6))?;
                    self.vt_csi
                        .encode_with_tag(encoder, Tag::new(Class::Context, 7))?;
                    self.t_bcsm_camel_tdp_criteria_list
                        .encode_with_tag(encoder, Tag::new(Class::Context, 8))?;
                    self.d_csi
                        .encode_with_tag(encoder, Tag::new(Class::Context, 9))?;
                    self.mt_sms_csi
                        .encode_with_tag(encoder, Tag::new(Class::Context, 10))?;
                    self.mt_sms_camel_tdp_criteria_list
                        .encode_with_tag(encoder, Tag::new(Class::Context, 11))?;
                    Ok(())
                },
                identifier,
            )
            .map(drop)
    }
}
