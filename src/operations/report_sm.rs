//! reportSM-DeliveryStatus (operation code 47) — 3GPP TS 29.002.
//!
//! Used by the SMS-SC to report the delivery status of an SMS to the HLR.

use rasn::prelude::*;

use crate::types::{AddressString, IsdnAddressString};

/// SM-DeliveryOutcome values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, AsnType, Decode, Encode)]
#[rasn(enumerated)]
pub enum SmDeliveryOutcome {
    MemoryCapacityExceeded = 0,
    AbsentSubscriber = 1,
    SuccessfulTransfer = 2,
}

/// ReportSM-DeliveryStatusArg — request parameters.
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct ReportSmDeliveryStatusArg {
    /// MSISDN of the SMS recipient.
    pub msisdn: IsdnAddressString,
    /// Address of the service centre.
    pub service_centre_address: AddressString,
    /// Delivery outcome.
    pub sm_delivery_outcome: SmDeliveryOutcome,
}

/// ReportSM-DeliveryStatusRes — response parameters.
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct ReportSmDeliveryStatusRes {
    /// Stored MSISDN (if different from request).
    pub stored_msisdn: Option<IsdnAddressString>,
}
