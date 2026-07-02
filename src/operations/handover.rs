//! Handover operations — 3GPP TS 29.002.
//!
//! - prepareHandover (op 68)
//! - sendEndSignal (op 29)
//! - processAccessSignalling (op 33)
//! - forwardAccessSignalling (op 34)
//! - prepareSubsequentHandover (op 69)

use rasn::prelude::*;

use crate::types::IsdnAddressString;

/// TargetRNC-Id or target cell for handover.
pub type TargetCellId = OctetString;
pub type TargetRncId = OctetString;

/// PrepareHandover-Arg (op 68).
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct PrepareHandoverArg {
    #[rasn(tag(context, 0))]
    pub target_cell_id: Option<TargetCellId>,
    #[rasn(tag(context, 1))]
    pub ho_number_not_required: Option<()>,
    #[rasn(tag(context, 2))]
    pub target_rnc_id: Option<TargetRncId>,
    #[rasn(tag(context, 3))]
    pub an_apdu: Option<OctetString>,
    #[rasn(tag(context, 4))]
    pub multiplicity_indicator: Option<Integer>,
    #[rasn(tag(context, 5))]
    pub rab_id: Option<Integer>,
}

/// PrepareHandover-Res (op 68).
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct PrepareHandoverRes {
    #[rasn(tag(context, 0))]
    pub handover_number: Option<IsdnAddressString>,
    #[rasn(tag(context, 1))]
    pub relocation_number_list: Option<Vec<OctetString>>,
    #[rasn(tag(context, 2))]
    pub an_apdu: Option<OctetString>,
    #[rasn(tag(context, 3))]
    pub multicall_bearer_info: Option<Integer>,
}

/// SendEndSignal-Arg (op 29).
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct SendEndSignalArg {
    #[rasn(tag(context, 0))]
    pub an_apdu: OctetString,
}

/// SendEndSignal-Res (op 29).
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct SendEndSignalRes {}

/// ProcessAccessSignalling-Arg (op 33).
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct ProcessAccessSignallingArg {
    #[rasn(tag(context, 0))]
    pub an_apdu: OctetString,
    #[rasn(tag(context, 1))]
    pub selected_umts_algorithms: Option<OctetString>,
    #[rasn(tag(context, 2))]
    pub selected_gsm_algorithm: Option<OctetString>,
    #[rasn(tag(context, 3))]
    pub chosen_radio_resource_information: Option<OctetString>,
}

/// ForwardAccessSignalling-Arg (op 34).
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct ForwardAccessSignallingArg {
    #[rasn(tag(context, 0))]
    pub an_apdu: OctetString,
    #[rasn(tag(context, 1))]
    pub integrityprotection_information: Option<OctetString>,
    #[rasn(tag(context, 2))]
    pub encryption_information: Option<OctetString>,
    #[rasn(tag(context, 5))]
    pub allowed_gsm_algorithms: Option<OctetString>,
    #[rasn(tag(context, 6))]
    pub allowed_umts_algorithms: Option<OctetString>,
}

/// PrepareSubsequentHandover-Arg (op 69).
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct PrepareSubsequentHandoverArg {
    #[rasn(tag(context, 0))]
    pub target_cell_id: Option<TargetCellId>,
    #[rasn(tag(context, 1))]
    pub target_msc_number: IsdnAddressString,
    #[rasn(tag(context, 2))]
    pub target_rnc_id: Option<TargetRncId>,
    #[rasn(tag(context, 3))]
    pub an_apdu: Option<OctetString>,
}

/// PrepareSubsequentHandover-Res (op 69).
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct PrepareSubsequentHandoverRes {
    #[rasn(tag(context, 0))]
    pub an_apdu: OctetString,
}

pub mod op_codes {
    pub const PREPARE_HANDOVER: i64 = 68;
    pub const SEND_END_SIGNAL: i64 = 29;
    pub const PROCESS_ACCESS_SIGNALLING: i64 = 33;
    pub const FORWARD_ACCESS_SIGNALLING: i64 = 34;
    pub const PREPARE_SUBSEQUENT_HANDOVER: i64 = 69;
}
