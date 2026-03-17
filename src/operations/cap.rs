//! CAP (CAMEL Application Part) operations — 3GPP TS 29.078.
//!
//! CAMEL operations for intelligent network services (prepaid, call control, SMS control).
//!
//! ## Call Control (gsmSSF ↔ gsmSCF)
//! - initialDP (0)
//! - connect (20)
//! - continue (31)
//! - releaseCall (22)
//! - requestReportBCSMEvent (23)
//! - eventReportBCSM (24)
//! - applyCharging (35)
//! - applyChargingReport (36)
//! - furnishChargingInformation (34)
//! - cancel (53)
//! - activityTest (55)
//!
//! ## Specialized Resource Control (gsmSRF ↔ gsmSCF)
//! - connectToResource (19)
//! - playAnnouncement (47)
//! - promptAndCollectUserInformation (48)
//! - specializedResourceReport (49)
//!
//! ## SMS Control (gprsSSF/gsmSSF ↔ gsmSCF)
//! - initialDPSMS (60)
//! - connectSMS (61) (CAP v3+)
//! - continueSMS (65)
//! - releaseSMS (62)
//! - eventReportSMS (64)
//! - requestReportSMSEvent (63)

use rasn::prelude::*;

use crate::types::IsdnAddressString;

// ─── Common CAP Types ──────────────────────────────────────────

/// ServiceKey — identifies the CAMEL service logic.
pub type ServiceKey = Integer;

/// CallReferenceNumber — uniquely identifies a call at the SSF.
pub type CallReferenceNumber = OctetString;

/// CalledPartyNumber — Q.763 format.
pub type CalledPartyNumber = OctetString;

/// CallingPartyNumber — Q.763 format.
pub type CallingPartyNumber = OctetString;

/// CalledPartyBCDNumber — 3GPP TS 24.008 format.
pub type CalledPartyBcdNumber = OctetString;

/// LocationNumber — Q.763 format.
pub type LocationNumber = OctetString;

/// OriginalCalledPartyID — Q.763 format.
pub type OriginalCalledPartyId = OctetString;

/// RedirectingPartyID — Q.763 format.
pub type RedirectingPartyId = OctetString;

/// Cause — Q.850 cause value.
pub type Cause = OctetString;

/// IMSI.
pub type Imsi = OctetString;

/// LocationInformation — per TS 29.002.
/// Note: ageOfLocationInformation has NO context tag (plain INTEGER).
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct LocationInformation {
    pub age_of_location_information: Option<Integer>,
    #[rasn(tag(context, 0))]
    pub geographical_information: Option<OctetString>,
    #[rasn(tag(context, 1))]
    pub vlr_number: Option<IsdnAddressString>,
    #[rasn(tag(context, 2))]
    pub location_number: Option<LocationNumber>,
    #[rasn(tag(context, 3))]
    pub cell_global_id_or_service_area_id_or_lai: Option<OctetString>,
    #[rasn(tag(context, 8))]
    pub msc_number: Option<IsdnAddressString>,
}

/// EventTypeBCSM — BCSM detection point events.
#[derive(Debug, Clone, Copy, PartialEq, Eq, AsnType, Decode, Encode)]
#[rasn(enumerated)]
pub enum EventTypeBcsm {
    CollectedInfo = 2,
    AnalysedInformation = 3,
    RouteSelectFailure = 4,
    OCalledPartyBusy = 5,
    ONoAnswer = 6,
    OAnswer = 7,
    ODisconnect = 9,
    OAbandon = 10,
    TermAttemptAuthorized = 12,
    TBusy = 13,
    TNoAnswer = 14,
    TAnswer = 15,
    TDisconnect = 17,
    TAbandon = 18,
}

/// MonitorMode — how an event should be reported.
#[derive(Debug, Clone, Copy, PartialEq, Eq, AsnType, Decode, Encode)]
#[rasn(enumerated)]
pub enum MonitorMode {
    Interrupted = 0,
    NotifyAndContinue = 1,
    Transparent = 2,
}

/// BCSMEvent — event detection point configuration.
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct BcsmEvent {
    #[rasn(tag(context, 0))]
    pub event_type_bcsm: EventTypeBcsm,
    #[rasn(tag(context, 1))]
    pub monitor_mode: MonitorMode,
    #[rasn(tag(context, 2))]
    pub leg_id: Option<OctetString>,
}

// ─── Call Control Operations ───────────────────────────────────

/// InitialDP-Arg (op 0) — per 3GPP TS 29.078 Section 7.1.
/// Tags from CAP v3 ASN.1 (NOT same as MAP!).
/// Fields in ascending tag order.
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct InitialDpArg {
    #[rasn(tag(context, 0))]
    pub service_key: ServiceKey,
    #[rasn(tag(context, 2))]
    pub called_party_number: Option<CalledPartyNumber>,
    #[rasn(tag(context, 3))]
    pub calling_party_number: Option<CallingPartyNumber>,
    #[rasn(tag(context, 5))]
    pub calling_partys_category: Option<OctetString>,
    #[rasn(tag(context, 12))]
    pub original_called_party_id: Option<OriginalCalledPartyId>,
    #[rasn(tag(context, 28))]
    pub event_type_bcsm: Option<EventTypeBcsm>,
    #[rasn(tag(context, 29))]
    pub redirecting_party_id: Option<RedirectingPartyId>,
    #[rasn(tag(context, 50))]
    pub imsi: Option<Imsi>,
    #[rasn(tag(context, 52))]
    pub location_information: Option<LocationInformation>,
    #[rasn(tag(context, 54))]
    pub call_reference_number: Option<CallReferenceNumber>,
    #[rasn(tag(context, 55))]
    pub msc_address: Option<IsdnAddressString>,
    #[rasn(tag(context, 56))]
    pub called_party_bcd_number: Option<CalledPartyBcdNumber>,
    #[rasn(tag(context, 57))]
    pub time_and_timezone: Option<OctetString>,
}

/// Connect-Arg (op 20) — gsmSCF instructs gsmSSF to route the call.
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct ConnectArg {
    #[rasn(tag(context, 0))]
    pub destination_routing_address: Vec<CalledPartyNumber>,
    #[rasn(tag(context, 4))]
    pub original_called_party_id: Option<OriginalCalledPartyId>,
    #[rasn(tag(context, 6))]
    pub calling_partys_category: Option<OctetString>,
    #[rasn(tag(context, 7))]
    pub redirecting_party_id: Option<RedirectingPartyId>,
    #[rasn(tag(context, 11))]
    pub generic_numbers: Option<Vec<OctetString>>,
}

/// ReleaseCall-Arg (op 22) — gsmSCF instructs gsmSSF to release the call.
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct ReleaseCallArg {
    /// Q.850 cause value.
    pub cause: Cause,
}

/// RequestReportBCSMEvent-Arg (op 23).
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct RequestReportBcsmEventArg {
    #[rasn(tag(context, 0))]
    pub bcsm_events: Vec<BcsmEvent>,
}

/// EventReportBCSM-Arg (op 24) — gsmSSF reports a BCSM event to gsmSCF.
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct EventReportBcsmArg {
    #[rasn(tag(context, 0))]
    pub event_type_bcsm: EventTypeBcsm,
    #[rasn(tag(context, 2))]
    pub leg_id: Option<OctetString>,
    #[rasn(tag(context, 3))]
    pub misc_call_info: Option<OctetString>,
}

/// ApplyCharging-Arg (op 35).
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct ApplyChargingArg {
    #[rasn(tag(context, 0))]
    pub ach_billing_charging_characteristics: OctetString,
    #[rasn(tag(context, 2))]
    pub party_to_charge: Option<OctetString>,
}

/// ApplyChargingReport-Arg (op 36).
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct ApplyChargingReportArg {
    /// Encoded call result.
    pub call_result: OctetString,
}

/// FurnishChargingInformation-Arg (op 34).
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct FurnishChargingInformationArg {
    /// Free-format data for charging.
    pub fci_billing_charging_characteristics: OctetString,
}

/// Cancel-Arg (op 53).
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
#[rasn(choice)]
pub enum CancelArg {
    #[rasn(tag(context, 0))]
    InvokeId(Integer),
    #[rasn(tag(context, 1))]
    AllRequests(()),
}

// ─── Specialized Resource Control ──────────────────────────────

/// ConnectToResource-Arg (op 19).
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct ConnectToResourceArg {
    /// Resource address: IP routing address or none.
    #[rasn(tag(context, 0))]
    pub resource_address_ipv4: Option<CalledPartyNumber>,
    #[rasn(tag(context, 3))]
    pub resource_address_none: Option<()>,
}

/// PlayAnnouncement-Arg (op 47).
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct PlayAnnouncementArg {
    #[rasn(tag(context, 0))]
    pub information_to_send: OctetString,
    #[rasn(tag(context, 1))]
    pub disconnect_from_ip_forbidden: Option<bool>,
    #[rasn(tag(context, 2))]
    pub request_announcement_complete: Option<bool>,
}

/// PromptAndCollectUserInformation-Arg (op 48).
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct PromptAndCollectUserInformationArg {
    #[rasn(tag(context, 0))]
    pub collected_info: OctetString,
    #[rasn(tag(context, 1))]
    pub disconnect_from_ip_forbidden: Option<bool>,
    #[rasn(tag(context, 2))]
    pub information_to_send: Option<OctetString>,
}

/// PromptAndCollectUserInformation-Res (op 48).
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
#[rasn(choice)]
pub enum PromptAndCollectUserInformationRes {
    #[rasn(tag(context, 0))]
    DigitsResponse(OctetString),
}

// ─── SMS Control Operations ────────────────────────────────────

/// EventTypeSMS — SMS detection point events.
#[derive(Debug, Clone, Copy, PartialEq, Eq, AsnType, Decode, Encode)]
#[rasn(enumerated)]
pub enum EventTypeSms {
    SmsCollectedInfo = 1,
    OSmsFailure = 2,
    OSmsSubmission = 3,
    SmsDeliveryRequested = 11,
    TSmsFailure = 12,
    TSmsDelivery = 13,
}

/// InitialDPSMS-Arg (op 60).
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct InitialDpSmsArg {
    #[rasn(tag(context, 0))]
    pub service_key: ServiceKey,
    #[rasn(tag(context, 1))]
    pub destination_subscriber_number: Option<CalledPartyBcdNumber>,
    #[rasn(tag(context, 2))]
    pub calling_party_number: Option<IsdnAddressString>,
    #[rasn(tag(context, 3))]
    pub event_type_sms: Option<EventTypeSms>,
    #[rasn(tag(context, 4))]
    pub imsi: Option<Imsi>,
    #[rasn(tag(context, 5))]
    pub location_information_msc: Option<LocationInformation>,
    #[rasn(tag(context, 6))]
    pub smsc_address: Option<IsdnAddressString>,
    #[rasn(tag(context, 7))]
    pub time_and_timezone: Option<OctetString>,
    #[rasn(tag(context, 8))]
    pub tp_short_message_specific_info: Option<OctetString>,
    #[rasn(tag(context, 9))]
    pub tp_protocol_identifier: Option<OctetString>,
    #[rasn(tag(context, 10))]
    pub tp_data_coding_scheme: Option<OctetString>,
    #[rasn(tag(context, 11))]
    pub tp_validity_period: Option<OctetString>,
    #[rasn(tag(context, 13))]
    pub sms_reference_number: Option<CallReferenceNumber>,
    #[rasn(tag(context, 14))]
    pub msc_address: Option<IsdnAddressString>,
    #[rasn(tag(context, 15))]
    pub sgsn_number: Option<IsdnAddressString>,
    #[rasn(tag(context, 16))]
    pub ms_classmark2: Option<OctetString>,
}

/// ConnectSMS-Arg (op 61) — CAP v3+.
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct ConnectSmsArg {
    #[rasn(tag(context, 0))]
    pub calling_partys_number: Option<IsdnAddressString>,
    #[rasn(tag(context, 1))]
    pub destination_subscriber_number: Option<CalledPartyBcdNumber>,
    #[rasn(tag(context, 2))]
    pub smsc_address: Option<IsdnAddressString>,
}

/// ReleaseSMS-Arg (op 62).
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct ReleaseSmsArg {
    /// RP-Cause value.
    pub rp_cause: OctetString,
}

/// SMSEvent — SMS event detection point configuration.
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct SmsEvent {
    #[rasn(tag(context, 0))]
    pub event_type_sms: EventTypeSms,
    #[rasn(tag(context, 1))]
    pub monitor_mode: MonitorMode,
}

/// RequestReportSMSEvent-Arg (op 63).
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct RequestReportSmsEventArg {
    #[rasn(tag(context, 0))]
    pub sms_events: Vec<SmsEvent>,
}

/// EventReportSMS-Arg (op 64).
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct EventReportSmsArg {
    #[rasn(tag(context, 0))]
    pub event_type_sms: EventTypeSms,
    #[rasn(tag(context, 1))]
    pub event_specific_information_sms: Option<OctetString>,
    #[rasn(tag(context, 2))]
    pub misc_call_info: Option<OctetString>,
}

// ─── Operation Codes ───────────────────────────────────────────

pub mod op_codes {
    // Call control
    pub const INITIAL_DP: i64 = 0;
    pub const CONNECT_TO_RESOURCE: i64 = 19;
    pub const CONNECT: i64 = 20;
    pub const RELEASE_CALL: i64 = 22;
    pub const REQUEST_REPORT_BCSM_EVENT: i64 = 23;
    pub const EVENT_REPORT_BCSM: i64 = 24;
    pub const CONTINUE: i64 = 31;
    pub const FURNISH_CHARGING_INFORMATION: i64 = 34;
    pub const APPLY_CHARGING: i64 = 35;
    pub const APPLY_CHARGING_REPORT: i64 = 36;
    pub const PLAY_ANNOUNCEMENT: i64 = 47;
    pub const PROMPT_AND_COLLECT_USER_INFORMATION: i64 = 48;
    pub const SPECIALIZED_RESOURCE_REPORT: i64 = 49;
    pub const CANCEL: i64 = 53;
    pub const ACTIVITY_TEST: i64 = 55;

    // SMS control
    pub const INITIAL_DP_SMS: i64 = 60;
    pub const CONNECT_SMS: i64 = 61;
    pub const RELEASE_SMS: i64 = 62;
    pub const REQUEST_REPORT_SMS_EVENT: i64 = 63;
    pub const EVENT_REPORT_SMS: i64 = 64;
    pub const CONTINUE_SMS: i64 = 65;
}
