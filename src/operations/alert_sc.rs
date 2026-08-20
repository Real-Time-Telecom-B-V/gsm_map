//! alertServiceCentre (operation code 64) — 3GPP TS 29.002.
//!
//! Also carries `alertServiceCentreWithoutResult` (op 49), the class-4 form of
//! the same alert.
//!
//! Sent by the HLR to the SMS-IWMSC/SMS-SC when a previously unreachable
//! subscriber becomes reachable again, so the service centre drains its queue.
//! The `new*Number` members tell the service centre where the subscriber moved,
//! so it can retry without a fresh SRI-SM.
//!
//! Every member TS 29.002 defines is modelled; see [`crate`] on why an
//! unmodelled member is fatal rather than merely absent.

use rasn::prelude::*;

use crate::types::{
    AddressString, CorrelationId, Imsi, IsdnAddressString, NetworkNodeDiameterAddress, Time,
};

/// SmsGmsc-Alert-Event — why the service centre is being alerted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, AsnType, Decode, Encode)]
#[rasn(enumerated)]
pub enum SmsGmscAlertEvent {
    /// The subscriber is reachable for MT SMS again.
    MsAvailableForMtSms = 0,
    /// The subscriber moved to a new serving node.
    MsUnderNewServingNode = 1,
}

/// AlertServiceCentreArg — request parameters.
///
/// ```asn1
/// AlertServiceCentreArg ::= SEQUENCE {
///     msisdn                      ISDN-AddressString,
///     serviceCentreAddress        AddressString,
///     ...,
///     imsi                        IMSI OPTIONAL,
///     correlationID               CorrelationID OPTIONAL,
///     maximumUeAvailabilityTime [0] Time OPTIONAL,
///     smsGmscAlertEvent         [1] SmsGmsc-Alert-Event OPTIONAL,
///     smsGmscDiameterAddress    [2] NetworkNodeDiameterAddress OPTIONAL,
///     newSGSNNumber             [3] ISDN-AddressString OPTIONAL,
///     newSGSNDiameterAddress    [4] NetworkNodeDiameterAddress OPTIONAL,
///     newMMENumber              [5] ISDN-AddressString OPTIONAL,
///     newMMEDiameterAddress     [6] NetworkNodeDiameterAddress OPTIONAL,
///     newMSCNumber              [7] ISDN-AddressString OPTIONAL }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct AlertServiceCentreArg {
    /// MSISDN of the now-reachable subscriber.
    pub msisdn: IsdnAddressString,
    /// Address of the service centre to alert.
    pub service_centre_address: AddressString,
    pub imsi: Option<Imsi>,
    pub correlation_id: Option<CorrelationId>,
    #[rasn(tag(context, 0))]
    pub maximum_ue_availability_time: Option<Time>,
    #[rasn(tag(context, 1))]
    pub sms_gmsc_alert_event: Option<SmsGmscAlertEvent>,
    #[rasn(tag(context, 2))]
    pub sms_gmsc_diameter_address: Option<NetworkNodeDiameterAddress>,
    #[rasn(tag(context, 3))]
    pub new_sgsn_number: Option<IsdnAddressString>,
    #[rasn(tag(context, 4))]
    pub new_sgsn_diameter_address: Option<NetworkNodeDiameterAddress>,
    #[rasn(tag(context, 5))]
    pub new_mme_number: Option<IsdnAddressString>,
    #[rasn(tag(context, 6))]
    pub new_mme_diameter_address: Option<NetworkNodeDiameterAddress>,
    #[rasn(tag(context, 7))]
    pub new_msc_number: Option<IsdnAddressString>,
}

impl AlertServiceCentreArg {
    /// The two mandatory members; every optional member starts `None`.
    pub fn new(msisdn: IsdnAddressString, service_centre_address: AddressString) -> Self {
        Self {
            msisdn,
            service_centre_address,
            imsi: None,
            correlation_id: None,
            maximum_ue_availability_time: None,
            sms_gmsc_alert_event: None,
            sms_gmsc_diameter_address: None,
            new_sgsn_number: None,
            new_sgsn_diameter_address: None,
            new_mme_number: None,
            new_mme_diameter_address: None,
            new_msc_number: None,
        }
    }
}

/// AlertServiceCentreWithoutResult-Arg (op 49) — the same alert as
/// [`AlertServiceCentreArg`], on the class-4 operation that expects **no
/// answer**. A service centre that has nothing useful to say back uses this so
/// the HLR is not left waiting on a TCAP timer.
pub type AlertServiceCentreWithoutResultArg = AlertServiceCentreArg;
