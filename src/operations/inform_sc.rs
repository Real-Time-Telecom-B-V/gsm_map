//! informServiceCentre (operation code 63) — 3GPP TS 29.002.
//!
//! Sent by the HLR to the SMS-SC to provide information about the
//! subscriber's status (e.g., MW (Message Waiting) data).

use rasn::prelude::*;

use crate::types::IsdnAddressString;

/// MW-Status — Message Waiting status flags (encoded as OCTET STRING, 1 byte).
/// bit 0: SC address not included
/// bit 1: MNRF (Mobile Not Reachable Flag) set
/// bit 2: MCEF (Memory Capacity Exceeded Flag) set
/// bit 3: MNRG (Mobile Not Reachable for GPRS) set
pub type MwStatus = OctetString;

/// Create an MW-Status byte from individual flags.
pub fn mw_status(sc_addr_not_included: bool, mnrf: bool, mcef: bool, mnrg: bool) -> MwStatus {
    let byte = (sc_addr_not_included as u8)
        | ((mnrf as u8) << 1)
        | ((mcef as u8) << 2)
        | ((mnrg as u8) << 3);
    vec![byte].into()
}

/// InformServiceCentreArg — request parameters.
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct InformServiceCentreArg {
    /// Stored MSISDN (if different from original).
    pub stored_msisdn: Option<IsdnAddressString>,
    /// Message waiting data status.
    #[rasn(tag(context, 0))]
    pub mw_status: Option<MwStatus>,
}
