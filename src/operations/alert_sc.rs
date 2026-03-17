//! alertServiceCentre (operation code 64) — 3GPP TS 29.002.
//!
//! Sent by the HLR to the SMS-SC when a previously unreachable subscriber
//! becomes reachable again.

use rasn::prelude::*;

use crate::types::{AddressString, IsdnAddressString};

/// AlertServiceCentreArg — request parameters.
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct AlertServiceCentreArg {
    /// MSISDN of the now-reachable subscriber.
    pub msisdn: IsdnAddressString,
    /// Address of the service centre to alert.
    pub service_centre_address: AddressString,
}
