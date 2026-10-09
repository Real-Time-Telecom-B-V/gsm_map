//! Byte vectors written by hand from the ASN.1 of 3GPP TS 29.002 (Rel-18),
//! one per operation argument, result and error parameter that a short
//! message service centre, an IP short message gateway and a location or
//! authentication exchange depend on.
//!
//! They are used twice. `tests/spec_vectors.rs` requires the encoder to emit
//! exactly these octets and the decoder to read them back, and
//! `examples/wireshark_vectors.rs` sends the same octets through Wireshark's
//! dissector and requires the `fields` below in its output. So each vector is
//! checked against the specification by derivation, against an independent
//! decoder, and as input this crate did not produce.
//!
//! Notation in the derivations: TS 29.002 is an `IMPLICIT TAGS` module, so
//! `[n]` replaces the tag of the type it is put on (`8n` primitive, `an`
//! constructed), except on a CHOICE, where it is EXPLICIT and wraps it.
//!
//! All values are synthetic. The IMSI is 001 01 0123456789 in the test
//! network, TBCD coded `00 01 01 21 43 65 87 f9`. Numbers are ISDN address
//! strings, `91` (international, E.164) followed by TBCD digits:
//!
//! ```text
//! 91 51 55 10 00 99 f9    +1 555 010 0999    the subscriber
//! 91 51 55 10 99          +1 555 0199        the service centre
//! 91 51 55 10 00 10 f0    +1 555 010 0010    an MSC
//! 91 51 55 10 00 20 f0    +1 555 010 0020    an SGSN
//! 91 51 55 10 00 30 f0    +1 555 010 0030    an MME
//! 91 51 55 10 00 40 f0    +1 555 010 0040    the HLR
//! 91 51 55 10 00 50 f0    +1 555 010 0050    a VLR
//! 91 51 55 10 00 60 f0    +1 555 010 0060    an IP-SM-GW
//! ```
#![allow(dead_code)]

/// Where a vector travels in TCAP.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// The argument of an invoke.
    Argument,
    /// The result in a return-result-last.
    Result,
    /// The parameter of a return-error.
    ErrorParameter,
}

pub struct SpecVector {
    pub label: &'static str,
    /// The operation code, or the error code for an error parameter.
    pub code: i64,
    pub kind: Kind,
    /// Members at the top level of the value, which the dissector has to
    /// name back one by one.
    pub members: usize,
    pub octets: &'static str,
    /// Lines the dissection has to contain.
    pub fields: &'static [&'static str],
}

// ── sendRoutingInfoForSM (45) ───────────────────────────────────────────────

/// ```text
/// 30 1d                            RoutingInfoForSM-Arg
///    80 07 91 51 55 10 00 99 f9    msisdn [0]
///    81 01 ff                      sm-RP-PRI [1] TRUE
///    82 05 91 51 55 10 99          serviceCentreAddress [2]
///    87 00                         gprsSupportIndicator [7] NULL
///    88 01 00                      sm-RP-MTI [8] 0: SMS Deliver
///    8a 01 00                      sm-deliveryNotIntended [10] onlyIMSI-requested (0)
///    8b 00                         ip-sm-gwGuidanceIndicator [11] NULL
/// ```
pub const SRI_SM_ARG: SpecVector = SpecVector {
    label: "spec_sri_sm_arg",
    code: 45,
    kind: Kind::Argument,
    members: 7,
    octets: "30 1d 80 07 91 51 55 10 00 99 f9 81 01 ff 82 05 91 51 55 10 99
             87 00 88 01 00 8a 01 00 8b 00",
    fields: &[
        "msisdn: 915155100099f9",
        "sm-RP-PRI: True",
        "serviceCentreAddress: 9151551099",
        "gprsSupportIndicator",
        "sm-RP-MTI: 0",
        "sm-deliveryNotIntended: onlyIMSI-requested (0)",
        "ip-sm-gwGuidanceIndicator",
    ],
};

/// The subscriber is reachable through an SGSN and an MSC. The first node is
/// the SGSN, which `gprsNodeIndicator` says, and the MSC is the additional
/// number. The HLR also returns delivery timer guidance for an IP-SM-GW.
///
/// ```text
/// 30 2b                                  RoutingInfoForSM-Res
///    04 08 00 01 01 21 43 65 87 f9       imsi
///    a0 16                               locationInfoWithLMSI [0]
///       81 07 91 51 55 10 00 20 f0       networkNode-Number [1]: the SGSN
///       85 00                            gprsNodeIndicator [5] NULL
///       a6 09                            additional-Number [6], EXPLICIT
///          80 07 91 51 55 10 00 10 f0    msc-Number [0]
///    a5 07                               ip-sm-gwGuidance [5]
///       02 01 1e                         minimumDeliveryTimeValue 30
///       02 02 01 2c                      recommendedDeliveryTimeValue 300
/// ```
pub const SRI_SM_RES_ADDITIONAL_MSC: SpecVector = SpecVector {
    label: "spec_sri_sm_res_additional_msc",
    code: 45,
    kind: Kind::Result,
    members: 3,
    octets: "30 2b 04 08 00 01 01 21 43 65 87 f9
             a0 16 81 07 91 51 55 10 00 20 f0 85 00 a6 09 80 07 91 51 55 10 00 10 f0
             a5 07 02 01 1e 02 02 01 2c",
    fields: &[
        "IMSI: 001010123456789",
        "networkNode-Number: 915155100020f0",
        "gprsNodeIndicator",
        "additional-Number: msc-Number (0)",
        "msc-Number: 915155100010f0",
        "minimumDeliveryTimeValue: 30",
        "recommendedDeliveryTimeValue: 300",
    ],
};

/// The first node is the MSC, the additional number an SGSN and the third
/// number an MME, which answers on an MSC number for SMS.
///
/// ```text
/// 30 31                                  RoutingInfoForSM-Res
///    04 08 00 01 01 21 43 65 87 f9       imsi
///    a0 25                               locationInfoWithLMSI [0]
///       81 07 91 51 55 10 00 10 f0       networkNode-Number [1]: the MSC
///       04 04 00 00 00 2a                lmsi
///       a6 09                            additional-Number [6], EXPLICIT
///          81 07 91 51 55 10 00 20 f0    sgsn-Number [1]
///       a9 09                            thirdNumber [9], EXPLICIT
///          80 07 91 51 55 10 00 30 f0    msc-Number [0]
/// ```
pub const SRI_SM_RES_ADDITIONAL_SGSN: SpecVector = SpecVector {
    label: "spec_sri_sm_res_additional_sgsn",
    code: 45,
    kind: Kind::Result,
    members: 2,
    octets: "30 31 04 08 00 01 01 21 43 65 87 f9
             a0 25 81 07 91 51 55 10 00 10 f0 04 04 00 00 00 2a
             a6 09 81 07 91 51 55 10 00 20 f0 a9 09 80 07 91 51 55 10 00 30 f0",
    fields: &[
        "networkNode-Number: 915155100010f0",
        "lmsi: 0000002a",
        "additional-Number: sgsn-Number (1)",
        "sgsn-Number: 915155100020f0",
        "thirdNumber: msc-Number (0)",
        "msc-Number: 915155100030f0",
    ],
};

// ── mo-forwardSM (46) and mt-forwardSM (44) ─────────────────────────────────

/// The SMS-SUBMIT in `sm-RP-UI` (TS 23.040): `01` SMS-SUBMIT, `00` message
/// reference, `0b 91 51 55 10 00 88 f8` destination +1 555 010 0888, `00`
/// protocol identifier, `00` data coding scheme, `02 c8 34` two septets "Hi".
///
/// ```text
/// 30 2b                                   MO-ForwardSM-Arg
///    84 05 91 51 55 10 99                 sm-RP-DA: serviceCentreAddressDA [4]
///    82 07 91 51 55 10 00 99 f9           sm-RP-OA: msisdn [2]
///    04 0f 01 00 0b 91 51 55 10 00 88     sm-RP-UI, 15 octets
///          f8 00 00 02 c8 34
///    04 08 00 01 01 21 43 65 87 f9        imsi, after the extension marker
/// ```
pub const MO_FORWARD_SM_ARG: SpecVector = SpecVector {
    label: "spec_mo_forward_sm_arg",
    code: 46,
    kind: Kind::Argument,
    members: 4,
    octets: "30 2b 84 05 91 51 55 10 99 82 07 91 51 55 10 00 99 f9
             04 0f 01 00 0b 91 51 55 10 00 88 f8 00 00 02 c8 34
             04 08 00 01 01 21 43 65 87 f9",
    fields: &[
        "sm-RP-DA: serviceCentreAddressDA (4)",
        "serviceCentreAddressDA: 9151551099",
        "sm-RP-OA: msisdn (2)",
        "msisdn: 915155100099f9",
        "sm-RP-UI: 01000b915155100088f8000002c834",
        "IMSI: 001010123456789",
    ],
};

/// The SMS-SUBMIT-REPORT for RP-ACK in `sm-RP-UI`: `01` SMS-SUBMIT-REPORT,
/// `00` no optional parameters, then the service centre time stamp
/// `62 01 01 00 00 00 00`.
///
/// ```text
/// 30 0b                                  MO-ForwardSM-Res
///    04 09 01 00 62 01 01 00 00 00 00    sm-RP-UI
/// ```
pub const MO_FORWARD_SM_RES: SpecVector = SpecVector {
    label: "spec_mo_forward_sm_res",
    code: 46,
    kind: Kind::Result,
    members: 1,
    octets: "30 0b 04 09 01 00 62 01 01 00 00 00 00",
    fields: &["sm-RP-UI: 010062010100000000"],
};

/// The SMS-DELIVER in `sm-RP-UI`: `04` SMS-DELIVER with no more messages to
/// send in the TPDU, `0b 91 51 55 10 00 88 f8` originator, `00 00` protocol
/// identifier and data coding scheme, `62 01 01 00 00 00 00` time stamp,
/// `02 c8 34` "Hi".
///
/// ```text
/// 30 2f                                   MT-ForwardSM-Arg
///    80 08 00 01 01 21 43 65 87 f9        sm-RP-DA: imsi [0]
///    84 05 91 51 55 10 99                 sm-RP-OA: serviceCentreAddressOA [4]
///    04 15 04 0b 91 51 55 10 00 88 f8     sm-RP-UI, 21 octets
///          00 00 62 01 01 00 00 00 00
///          02 c8 34
///    05 00                                moreMessagesToSend NULL
///    02 01 3c                             smDeliveryTimer 60, after the marker
///    80 00                                smsOverIP-OnlyIndicator [0] NULL
/// ```
pub const MT_FORWARD_SM_ARG: SpecVector = SpecVector {
    label: "spec_mt_forward_sm_arg",
    code: 44,
    kind: Kind::Argument,
    members: 6,
    octets: "30 2f 80 08 00 01 01 21 43 65 87 f9 84 05 91 51 55 10 99
             04 15 04 0b 91 51 55 10 00 88 f8 00 00 62 01 01 00 00 00 00 02 c8 34
             05 00 02 01 3c 80 00",
    fields: &[
        "sm-RP-DA: imsi (0)",
        "IMSI: 001010123456789",
        "sm-RP-OA: serviceCentreAddressOA (4)",
        "serviceCentreAddressOA: 9151551099",
        "sm-RP-UI: 040b915155100088f800006201010000000002c834",
        "moreMessagesToSend",
        "smDeliveryTimer: 60",
        "smsOverIP-OnlyIndicator",
    ],
};

/// The SMS-DELIVER-REPORT for RP-ACK: `00` SMS-DELIVER-REPORT, `00` no
/// optional parameters.
///
/// ```text
/// 30 04           MT-ForwardSM-Res
///    04 02 00 00  sm-RP-UI
/// ```
pub const MT_FORWARD_SM_RES: SpecVector = SpecVector {
    label: "spec_mt_forward_sm_res",
    code: 44,
    kind: Kind::Result,
    members: 1,
    octets: "30 04 04 02 00 00",
    fields: &["sm-RP-UI: 0000"],
};

// ── reportSM-DeliveryStatus (47) ────────────────────────────────────────────

/// An IP-SM-GW reporting that delivery failed both ways.
///
/// ```text
/// 30 1e                            ReportSM-DeliveryStatusArg
///    04 07 91 51 55 10 00 99 f9    msisdn
///    04 05 91 51 55 10 99          serviceCentreAddress
///    0a 01 01                      sm-DeliveryOutcome absentSubscriber (1)
///    80 01 01                      absentSubscriberDiagnosticSM [0] 1
///    86 00                         ip-sm-gw-Indicator [6] NULL
///    87 01 01                      ip-sm-gw-sm-deliveryOutcome [7] absentSubscriber (1)
///    88 01 04                      ip-sm-gw-absentSubscriberDiagnosticSM [8] 4
/// ```
pub const REPORT_SM_DELIVERY_STATUS_ARG: SpecVector = SpecVector {
    label: "spec_report_sm_delivery_status_arg",
    code: 47,
    kind: Kind::Argument,
    members: 7,
    octets: "30 1e 04 07 91 51 55 10 00 99 f9 04 05 91 51 55 10 99 0a 01 01
             80 01 01 86 00 87 01 01 88 01 04",
    fields: &[
        "msisdn: 915155100099f9",
        "serviceCentreAddress: 9151551099",
        "sm-DeliveryOutcome: absentSubscriber (1)",
        "absentSubscriberDiagnosticSM: 1",
        "ip-sm-gw-Indicator",
        "ip-sm-gw-sm-deliveryOutcome: absentSubscriber (1)",
        "ip-sm-gw-absentSubscriberDiagnosticSM: 4",
    ],
};

/// ```text
/// 30 09                            ReportSM-DeliveryStatusRes
///    04 07 91 51 55 10 00 99 f9    storedMSISDN
/// ```
pub const REPORT_SM_DELIVERY_STATUS_RES: SpecVector = SpecVector {
    label: "spec_report_sm_delivery_status_res",
    code: 47,
    kind: Kind::Result,
    members: 1,
    octets: "30 09 04 07 91 51 55 10 00 99 f9",
    fields: &["storedMSISDN: 915155100099f9"],
};

// ── alertServiceCentre (64), informServiceCentre (63), readyForSM (66) ──────

/// ```text
/// 30 1d                               AlertServiceCentreArg
///    04 07 91 51 55 10 00 99 f9       msisdn
///    04 05 91 51 55 10 99             serviceCentreAddress
///    04 08 00 01 01 21 43 65 87 f9    imsi, after the extension marker
///    81 01 01                         smsGmscAlertEvent [1] msUnderNewServingNode (1)
/// ```
pub const ALERT_SERVICE_CENTRE_ARG: SpecVector = SpecVector {
    label: "spec_alert_service_centre_arg",
    code: 64,
    kind: Kind::Argument,
    members: 4,
    octets: "30 1d 04 07 91 51 55 10 00 99 f9 04 05 91 51 55 10 99
             04 08 00 01 01 21 43 65 87 f9 81 01 01",
    fields: &[
        "msisdn: 915155100099f9",
        "serviceCentreAddress: 9151551099",
        "IMSI: 001010123456789",
        "smsGmscAlertEvent: msUnderNewServingNode (1)",
    ],
};

/// `mw-Status` is a BIT STRING of at least six bits numbered from the most
/// significant: sc-AddressNotIncluded (0), mnrf-Set (1), mcef-Set (2),
/// mnrg-Set (3), mnr5g-Set (4), mnr5gn3g-Set (5). With mnrf and mcef set the
/// six bits are 011000, one octet `60` with two unused bits.
///
/// ```text
/// 30 13                            InformServiceCentreArg
///    04 07 91 51 55 10 00 99 f9    storedMSISDN
///    03 02 02 60                   mw-Status: two unused bits, 0110 00..
///    02 01 01                      absentSubscriberDiagnosticSM 1, after the marker
///    80 01 02                      additionalAbsentSubscriberDiagnosticSM [0] 2
/// ```
pub const INFORM_SERVICE_CENTRE_ARG: SpecVector = SpecVector {
    label: "spec_inform_service_centre_arg",
    code: 63,
    kind: Kind::Argument,
    members: 4,
    octets: "30 13 04 07 91 51 55 10 00 99 f9 03 02 02 60 02 01 01 80 01 02",
    fields: &[
        "storedMSISDN: 915155100099f9",
        "mw-Status: 60",
        "= mnrf-Set: True",
        "= mcef-Set: True",
        "= sc-AddressNotIncluded: False",
        "absentSubscriberDiagnosticSM: 1",
        "additionalAbsentSubscriberDiagnosticSM: 2",
    ],
};

/// ```text
/// 30 0f                               ReadyForSM-Arg
///    80 08 00 01 01 21 43 65 87 f9    imsi [0]
///    0a 01 01                         alertReason memoryAvailable (1)
///    05 00                            alertReasonIndicator NULL
/// ```
pub const READY_FOR_SM_ARG: SpecVector = SpecVector {
    label: "spec_ready_for_sm_arg",
    code: 66,
    kind: Kind::Argument,
    members: 3,
    octets: "30 0f 80 08 00 01 01 21 43 65 87 f9 0a 01 01 05 00",
    fields: &[
        "IMSI: 001010123456789",
        "alertReason: memoryAvailable (1)",
        "alertReasonIndicator",
    ],
};

// ── sendAuthenticationInfo (56) ─────────────────────────────────────────────

/// `requestingPLMN-Id` is the PLMN identity of TS 23.003 in three octets:
/// MCC digit 2 and 1, then MNC digit 3 and MCC digit 3, then MNC digit 2 and
/// 1. For 001 01 with a two-digit MNC: `00 f1 10`.
///
/// ```text
/// 30 1c                               SendAuthenticationInfoArg
///    80 08 00 01 01 21 43 65 87 f9    imsi [0]
///    02 01 03                         numberOfRequestedVectors 3
///    81 00                            immediateResponsePreferred [1] NULL
///    83 01 10                         requestingNodeType [3] mme (16)
///    84 03 00 f1 10                   requestingPLMN-Id [4]
///    85 01 02                         numberOfRequestedAdditional-Vectors [5] 2
///    86 00                            additionalVectorsAreForEPS [6] NULL
/// ```
pub const SEND_AUTHENTICATION_INFO_ARG: SpecVector = SpecVector {
    label: "spec_send_authentication_info_arg",
    code: 56,
    kind: Kind::Argument,
    members: 7,
    octets: "30 1c 80 08 00 01 01 21 43 65 87 f9 02 01 03 81 00 83 01 10
             84 03 00 f1 10 85 01 02 86 00",
    fields: &[
        "IMSI: 001010123456789",
        "numberOfRequestedVectors: 3",
        "immediateResponsePreferred",
        "requestingNodeType: mme (16)",
        "requestingPLMN-Id: 00f110",
        "numberOfRequestedAdditional-Vectors: 2",
        "additionalVectorsAreForEPS",
    ],
};

/// ```text
/// a3 26                          SendAuthenticationInfoRes ::= [3] SEQUENCE
///    a0 24                       authenticationSetList: tripletList [0]
///       30 22                    AuthenticationTriplet
///          04 10 00 01 .. 0f     rand, 16 octets
///          04 04 a1 a2 a3 a4     sres
///          04 08 c0 c1 .. c7     kc
/// ```
pub const SEND_AUTHENTICATION_INFO_RES_TRIPLET: SpecVector = SpecVector {
    label: "spec_send_authentication_info_res_triplet",
    code: 56,
    kind: Kind::Result,
    members: 1,
    octets: "a3 26 a0 24 30 22 04 10 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f
             04 04 a1 a2 a3 a4 04 08 c0 c1 c2 c3 c4 c5 c6 c7",
    fields: &[
        "authenticationSetList: tripletList (0)",
        "rand: 000102030405060708090a0b0c0d0e0f",
        "sres: a1a2a3a4",
        "kc: c0c1c2c3c4c5c6c7",
    ],
};

/// ```text
/// a3 56                          SendAuthenticationInfoRes ::= [3] SEQUENCE
///    a1 54                       authenticationSetList: quintupletList [1]
///       30 52                    AuthenticationQuintuplet
///          04 10 00 01 .. 0f     rand, 16 octets
///          04 08 d0 d1 .. d7     xres, 8 octets (4 to 16 are allowed)
///          04 10 20 21 .. 2f     ck, 16 octets
///          04 10 30 31 .. 3f     ik, 16 octets
///          04 10 40 41 .. 4f     autn, 16 octets
/// ```
pub const SEND_AUTHENTICATION_INFO_RES_QUINTUPLET: SpecVector = SpecVector {
    label: "spec_send_authentication_info_res_quintuplet",
    code: 56,
    kind: Kind::Result,
    members: 1,
    octets: "a3 56 a1 54 30 52 04 10 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f
             04 08 d0 d1 d2 d3 d4 d5 d6 d7
             04 10 20 21 22 23 24 25 26 27 28 29 2a 2b 2c 2d 2e 2f
             04 10 30 31 32 33 34 35 36 37 38 39 3a 3b 3c 3d 3e 3f
             04 10 40 41 42 43 44 45 46 47 48 49 4a 4b 4c 4d 4e 4f",
    fields: &[
        "authenticationSetList: quintupletList (1)",
        "rand: 000102030405060708090a0b0c0d0e0f",
        "xres: d0d1d2d3d4d5d6d7",
        "ck: 202122232425262728292a2b2c2d2e2f",
        "ik: 303132333435363738393a3b3c3d3e3f",
        "autn: 404142434445464748494a4b4c4d4e4f",
    ],
};

/// An EPS vector and the UE usage type. `UE-UsageType` is an OCTET STRING of
/// exactly four octets.
///
/// ```text
/// a3 5a                          SendAuthenticationInfoRes ::= [3] SEQUENCE
///    a2 52                       eps-AuthenticationSetList [2], SEQUENCE OF
///       30 50                    EPC-AV
///          04 10 00 01 .. 0f     rand, 16 octets
///          04 08 d0 d1 .. d7     xres, 8 octets
///          04 10 40 41 .. 4f     autn, 16 octets
///          04 20 50 51 .. 6f     kasme, 32 octets
///    83 04 00 00 00 01           ueUsageType [3]
/// ```
pub const SEND_AUTHENTICATION_INFO_RES_EPS: SpecVector = SpecVector {
    label: "spec_send_authentication_info_res_eps",
    code: 56,
    kind: Kind::Result,
    members: 2,
    octets: "a3 5a a2 52 30 50 04 10 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f
             04 08 d0 d1 d2 d3 d4 d5 d6 d7
             04 10 40 41 42 43 44 45 46 47 48 49 4a 4b 4c 4d 4e 4f
             04 20 50 51 52 53 54 55 56 57 58 59 5a 5b 5c 5d 5e 5f
                   60 61 62 63 64 65 66 67 68 69 6a 6b 6c 6d 6e 6f
             83 04 00 00 00 01",
    fields: &[
        "eps-AuthenticationSetList: 1 item",
        "EPC-AV",
        "rand: 000102030405060708090a0b0c0d0e0f",
        "xres: d0d1d2d3d4d5d6d7",
        "autn: 404142434445464748494a4b4c4d4e4f",
        "kasme: 505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f",
        "ueUsageType: 00000001",
    ],
};

// ── updateLocation (2), updateGprsLocation (23), cancelLocation (3) ─────────

/// `add-info` carries the IMEISV, 16 digits in eight TBCD octets, here
/// 0011223344556677.
///
/// ```text
/// 30 2a                                     UpdateLocationArg
///    04 08 00 01 01 21 43 65 87 f9          imsi
///    81 07 91 51 55 10 00 10 f0             msc-Number [1]
///    04 07 91 51 55 10 00 50 f0             vlr-Number
///    8b 00                                  informPreviousNetworkEntity [11] NULL
///    ad 0a                                  add-info [13]
///       80 08 00 11 22 33 44 55 66 77       imeisv [0]
/// ```
pub const UPDATE_LOCATION_ARG: SpecVector = SpecVector {
    label: "spec_update_location_arg",
    code: 2,
    kind: Kind::Argument,
    members: 5,
    octets: "30 2a 04 08 00 01 01 21 43 65 87 f9 81 07 91 51 55 10 00 10 f0
             04 07 91 51 55 10 00 50 f0 8b 00 ad 0a 80 08 00 11 22 33 44 55 66 77",
    fields: &[
        "IMSI: 001010123456789",
        "msc-Number: 915155100010f0",
        "vlr-Number: 915155100050f0",
        "informPreviousNetworkEntity",
        "add-info",
        "imeisv: 0011223344556677",
    ],
};

/// ```text
/// 30 0b                            UpdateLocationRes
///    04 07 91 51 55 10 00 40 f0    hlr-Number
///    05 00                         add-Capability NULL, after the marker
/// ```
pub const UPDATE_LOCATION_RES: SpecVector = SpecVector {
    label: "spec_update_location_res",
    code: 2,
    kind: Kind::Result,
    members: 2,
    octets: "30 0b 04 07 91 51 55 10 00 40 f0 05 00",
    fields: &["hlr-Number: 915155100040f0", "add-Capability"],
};

/// `sgsn-Address` is a GSN address of TS 23.003: one octet with the address
/// type in the two high bits (0 for IPv4) and the length in the low six,
/// then the address, here 192.0.2.1.
///
/// `isr-Information` is a BIT STRING of at least three bits: updateLocation
/// (0), cancelSGSN (1), initialAttachIndicator (2). With the first and the
/// third set the bits are 101, one octet `a0` with five unused bits.
///
/// ```text
/// 30 20                               UpdateGprsLocationArg
///    04 08 00 01 01 21 43 65 87 f9    imsi
///    04 07 91 51 55 10 00 20 f0       sgsn-Number
///    04 05 04 c0 00 02 01             sgsn-Address
///    a5 04                            eps-info [5], EXPLICIT: EPS-Info is a CHOICE
///       81 02 05 a0                   isr-Information [1]
/// ```
pub const UPDATE_GPRS_LOCATION_ARG_ISR: SpecVector = SpecVector {
    label: "spec_update_gprs_location_arg_isr",
    code: 23,
    kind: Kind::Argument,
    members: 4,
    octets: "30 20 04 08 00 01 01 21 43 65 87 f9 04 07 91 51 55 10 00 20 f0
             04 05 04 c0 00 02 01 a5 04 81 02 05 a0",
    fields: &[
        "IMSI: 001010123456789",
        "sgsn-Number: 915155100020f0",
        "sgsn-Address: 04c0000201",
        "eps-info: isr-Information (1)",
        "= updateLocation: True",
        "= cancelSGSN: False",
        "= initialAttachIndicator: True",
    ],
};

/// The other alternative of `eps-info`. The APN is coded as labels, each
/// preceded by its length (TS 23.003): `03 69 6d 73` is "ims". The PDN
/// gateway is 192.0.2.10.
///
/// ```text
/// 30 2f                               UpdateGprsLocationArg
///    04 08 00 01 01 21 43 65 87 f9    imsi
///    04 07 91 51 55 10 00 20 f0       sgsn-Number
///    04 05 04 c0 00 02 01             sgsn-Address
///    a5 13                            eps-info [5], EXPLICIT
///       a0 11                         pdn-gw-update [0]
///          80 04 03 69 6d 73          apn [0]
///          a1 06                      pdn-gw-Identity [1]
///             80 04 c0 00 02 0a       pdn-gw-ipv4-Address [0]
///          82 01 05                   contextId [2] 5
/// ```
pub const UPDATE_GPRS_LOCATION_ARG_PDN_GW: SpecVector = SpecVector {
    label: "spec_update_gprs_location_arg_pdn_gw",
    code: 23,
    kind: Kind::Argument,
    members: 4,
    octets: "30 2f 04 08 00 01 01 21 43 65 87 f9 04 07 91 51 55 10 00 20 f0
             04 05 04 c0 00 02 01
             a5 13 a0 11 80 04 03 69 6d 73 a1 06 80 04 c0 00 02 0a 82 01 05",
    fields: &[
        "eps-info: pdn-gw-update (0)",
        "apn: 03696d73",
        "pdn-gw-Identity",
        "pdn-gw-ipv4-Address: c000020a",
        "contextId: 5",
    ],
};

/// ```text
/// 30 09                            UpdateGprsLocationRes
///    04 07 91 51 55 10 00 40 f0    hlr-Number
/// ```
pub const UPDATE_GPRS_LOCATION_RES: SpecVector = SpecVector {
    label: "spec_update_gprs_location_res",
    code: 23,
    kind: Kind::Result,
    members: 1,
    octets: "30 09 04 07 91 51 55 10 00 40 f0",
    fields: &["hlr-Number: 915155100040f0"],
};

/// ```text
/// a3 12                               CancelLocationArg ::= [3] SEQUENCE
///    04 08 00 01 01 21 43 65 87 f9    identity: imsi
///    0a 01 00                         cancellationType updateProcedure (0)
///    80 01 01                         typeOfUpdate [0] mme-change (1), after the marker
///    86 00                            reattach-Required [6] NULL
/// ```
pub const CANCEL_LOCATION_ARG: SpecVector = SpecVector {
    label: "spec_cancel_location_arg",
    code: 3,
    kind: Kind::Argument,
    members: 4,
    octets: "a3 12 04 08 00 01 01 21 43 65 87 f9 0a 01 00 80 01 01 86 00",
    fields: &[
        "identity: imsi (0)",
        "IMSI: 001010123456789",
        "cancellationType: updateProcedure (0)",
        "typeOfUpdate: mme-change (1)",
        "reattach-Required",
    ],
};

/// The other alternative of `identity`, with a subscription withdrawal.
///
/// ```text
/// a3 15                                  CancelLocationArg ::= [3] SEQUENCE
///    30 10                               identity: imsi-WithLMSI
///       04 08 00 01 01 21 43 65 87 f9    imsi
///       04 04 00 00 00 2a                lmsi
///    0a 01 01                            cancellationType subscriptionWithdraw (1)
/// ```
pub const CANCEL_LOCATION_ARG_WITH_LMSI: SpecVector = SpecVector {
    label: "spec_cancel_location_arg_with_lmsi",
    code: 3,
    kind: Kind::Argument,
    members: 2,
    octets: "a3 15 30 10 04 08 00 01 01 21 43 65 87 f9 04 04 00 00 00 2a 0a 01 01",
    fields: &[
        "identity: imsi-WithLMSI (1)",
        "IMSI: 001010123456789",
        "lmsi: 0000002a",
        "cancellationType: subscriptionWithdraw (1)",
    ],
};

// ── insertSubscriberData (7) ────────────────────────────────────────────────

/// The members a short message exchange turns on. BER encodes in declaration
/// order, and TS 29.002 declares `networkAccessMode [24]` before
/// `chargingCharacteristics [18]`. `[48]` needs the high tag number form,
/// `9f 30`. The teleservices are shortMessageMT-PP (`21`) and
/// shortMessageMO-PP (`22`), the category is an ordinary subscriber (`0a`).
///
/// ```text
/// 30 2f                               InsertSubscriberDataArg
///    80 08 00 01 01 21 43 65 87 f9    imsi [0]
///    81 07 91 51 55 10 00 99 f9       msisdn [1]
///    82 01 0a                         category [2]
///    83 01 00                         subscriberStatus [3] serviceGranted (0)
///    a6 06                            teleserviceList [6]
///       04 01 21                      shortMessageMT-PP
///       04 01 22                      shortMessageMO-PP
///    98 01 00                         networkAccessMode [24] packetAndCircuit (0)
///    92 02 08 00                      chargingCharacteristics [18], two octets: profile
///                                     index 8, "normal billing" in TS 32.215
///    9f 30 04 00 00 00 01             ueUsageType [48], four octets
/// ```
pub const INSERT_SUBSCRIBER_DATA_ARG: SpecVector = SpecVector {
    label: "spec_insert_subscriber_data_arg",
    code: 7,
    kind: Kind::Argument,
    members: 8,
    octets: "30 2f 80 08 00 01 01 21 43 65 87 f9 81 07 91 51 55 10 00 99 f9
             82 01 0a 83 01 00 a6 06 04 01 21 04 01 22 98 01 00 92 02 08 00
             9f 30 04 00 00 00 01",
    fields: &[
        "IMSI: 001010123456789",
        "msisdn: 915155100099f9",
        "category: 0a",
        "subscriberStatus: serviceGranted (0)",
        "teleserviceList: 2 items",
        "Ext-TeleserviceCode: shortMessageMT-PP (33)",
        "Ext-TeleserviceCode: shortMessageMO-PP (34)",
        "networkAccessMode: packetAndCircuit (0)",
        "= chargingCharacteristics: N (Normal billing) (8)",
        "ueUsageType: 00000001",
    ],
};

// ── anyTimeModification (65) for IP-SM-GW data ──────────────────────────────

/// An IP-SM-GW registering itself for a subscriber.
///
/// ```text
/// 30 19                               AnyTimeModificationArg
///    a0 09                            subscriberIdentity [0], EXPLICIT
///       81 07 91 51 55 10 00 99 f9    msisdn [1]
///    81 07 91 51 55 10 00 60 f0       gsmSCF-Address [1]: the IP-SM-GW
///    a8 03                            modificationRequestFor-IP-SM-GW-Data [8]
///       80 01 01                      modifyRegistrationStatus [0] activate (1)
/// ```
pub const ANY_TIME_MODIFICATION_ARG_ACTIVATE: SpecVector = SpecVector {
    label: "spec_any_time_modification_arg_activate",
    code: 65,
    kind: Kind::Argument,
    members: 3,
    octets: "30 19 a0 09 81 07 91 51 55 10 00 99 f9 81 07 91 51 55 10 00 60 f0
             a8 03 80 01 01",
    fields: &[
        "subscriberIdentity: msisdn (1)",
        "msisdn: 915155100099f9",
        "gsmSCF-Address: 915155100060f0",
        "modificationRequestFor-IP-SM-GW-Data",
        "modifyRegistrationStatus: activate (1)",
    ],
};

/// The de-registration, by IMSI, with the Diameter address of the gateway.
///
/// ```text
/// 30 37                                        AnyTimeModificationArg
///    a0 0a                                     subscriberIdentity [0], EXPLICIT
///       80 08 00 01 01 21 43 65 87 f9          imsi [0]
///    81 07 91 51 55 10 00 60 f0                gsmSCF-Address [1]
///    a8 20                                     modificationRequestFor-IP-SM-GW-Data [8]
///       80 01 00                               modifyRegistrationStatus [0] deactivate (0)
///       a2 1b                                  ip-sm-gw-DiameterAddress [2]
///          80 0d 69 70 73 6d 67 77 30 31       diameter-Name [0] "ipsmgw01.test",
///                2e 74 65 73 74                13 octets
///          81 0a 72 65 61 6c 6d 2e 74 65       diameter-Realm [1] "realm.test",
///                73 74                         10 octets
/// ```
pub const ANY_TIME_MODIFICATION_ARG_DEACTIVATE: SpecVector = SpecVector {
    label: "spec_any_time_modification_arg_deactivate",
    code: 65,
    kind: Kind::Argument,
    members: 3,
    octets: "30 37 a0 0a 80 08 00 01 01 21 43 65 87 f9 81 07 91 51 55 10 00 60 f0
             a8 20 80 01 00
             a2 1b 80 0d 69 70 73 6d 67 77 30 31 2e 74 65 73 74
                   81 0a 72 65 61 6c 6d 2e 74 65 73 74",
    fields: &[
        "subscriberIdentity: imsi (0)",
        "IMSI: 001010123456789",
        "modifyRegistrationStatus: deactivate (0)",
        "ip-sm-gw-DiameterAddress",
        "diameter-Name: ipsmgw01.test",
        "diameter-Realm: realm.test",
    ],
};

/// ```text
/// 30 07                      AnyTimeModificationRes
///    89 05 91 51 55 10 99    serviceCentreAddress [9]
/// ```
pub const ANY_TIME_MODIFICATION_RES: SpecVector = SpecVector {
    label: "spec_any_time_modification_res",
    code: 65,
    kind: Kind::Result,
    members: 1,
    octets: "30 07 89 05 91 51 55 10 99",
    fields: &["serviceCentreAddress: 9151551099"],
};

// ── Error parameters ────────────────────────────────────────────────────────

/// absentSubscriberSM (6). `requestedRetransmissionTime` is a `Time`, four
/// octets.
///
/// ```text
/// 30 20                               AbsentSubscriberSM-Param
///    02 01 01                         absentSubscriberDiagnosticSM 1
///    80 01 05                         additionalAbsentSubscriberDiagnosticSM [0] 5
///    81 08 00 01 01 21 43 65 87 f9    imsi [1]
///    82 04 00 00 0e 10                requestedRetransmissionTime [2]
///    83 08 00 01 01 21 43 65 87 f9    userIdentifierAlert [3]
/// ```
pub const ABSENT_SUBSCRIBER_SM: SpecVector = SpecVector {
    label: "spec_absent_subscriber_sm_param",
    code: 6,
    kind: Kind::ErrorParameter,
    members: 5,
    octets: "30 20 02 01 01 80 01 05 81 08 00 01 01 21 43 65 87 f9
             82 04 00 00 0e 10 83 08 00 01 01 21 43 65 87 f9",
    fields: &[
        "localValue: absentSubscriberSM (6)",
        "absentSubscriberDiagnosticSM: 1",
        "additionalAbsentSubscriberDiagnosticSM: 5",
        "IMSI: 001010123456789",
        "requestedRetransmissionTime: 00000e10",
    ],
};

/// sm-DeliveryFailure (32). `diagnosticInfo` is the SMS-DELIVER-REPORT for
/// RP-ERROR: `00` SMS-DELIVER-REPORT, `d3` failure cause "memory capacity
/// exceeded", `00` no optional parameters.
///
/// ```text
/// 30 08                SM-DeliveryFailureCause
///    0a 01 00          sm-EnumeratedDeliveryFailureCause memoryCapacityExceeded (0)
///    04 03 00 d3 00    diagnosticInfo
/// ```
pub const SM_DELIVERY_FAILURE: SpecVector = SpecVector {
    label: "spec_sm_delivery_failure_cause",
    code: 32,
    kind: Kind::ErrorParameter,
    members: 2,
    octets: "30 08 0a 01 00 04 03 00 d3 00",
    fields: &[
        "localValue: sm-DeliveryFailure (32)",
        "sm-EnumeratedDeliveryFailureCause: memoryCapacityExceeded (0)",
        "diagnosticInfo: 00d300",
    ],
};

/// unknownSubscriber (1).
///
/// ```text
/// 30 03          UnknownSubscriberParam
///    0a 01 00    unknownSubscriberDiagnostic imsiUnknown (0), after the marker
/// ```
pub const UNKNOWN_SUBSCRIBER: SpecVector = SpecVector {
    label: "spec_unknown_subscriber_param",
    code: 1,
    kind: Kind::ErrorParameter,
    members: 1,
    octets: "30 03 0a 01 00",
    fields: &[
        "localValue: unknownSubscriber (1)",
        "unknownSubscriberDiagnostic: imsiUnknown (0)",
    ],
};

/// absentSubscriber (27).
///
/// ```text
/// 30 03          AbsentSubscriberParam
///    80 01 00    absentSubscriberReason [0] imsiDetach (0)
/// ```
pub const ABSENT_SUBSCRIBER: SpecVector = SpecVector {
    label: "spec_absent_subscriber_param",
    code: 27,
    kind: Kind::ErrorParameter,
    members: 1,
    octets: "30 03 80 01 00",
    fields: &[
        "localValue: absentSubscriber (27)",
        "absentSubscriberReason: imsiDetach (0)",
    ],
};

/// subscriberBusyForMT-SMS (31).
///
/// ```text
/// 30 02       SubBusyForMT-SMS-Param
///    05 00    gprsConnectionSuspended NULL, after the marker
/// ```
pub const SUBSCRIBER_BUSY_FOR_MT_SMS: SpecVector = SpecVector {
    label: "spec_sub_busy_for_mt_sms_param",
    code: 31,
    kind: Kind::ErrorParameter,
    members: 1,
    octets: "30 02 05 00",
    fields: &[
        "localValue: subscriberBusyForMT-SMS (31)",
        "gprsConnectionSuspended",
    ],
};

/// unexpectedDataValue (36).
///
/// ```text
/// 30 02       UnexpectedDataParam
///    80 00    unexpectedSubscriber [0] NULL, after the marker
/// ```
pub const UNEXPECTED_DATA_VALUE: SpecVector = SpecVector {
    label: "spec_unexpected_data_param",
    code: 36,
    kind: Kind::ErrorParameter,
    members: 1,
    octets: "30 02 80 00",
    fields: &[
        "localValue: unexpectedDataValue (36)",
        "unexpectedSubscriber",
    ],
};

/// Every vector, for the Wireshark cross-check.
pub const ALL: &[&SpecVector] = &[
    &SRI_SM_ARG,
    &SRI_SM_RES_ADDITIONAL_MSC,
    &SRI_SM_RES_ADDITIONAL_SGSN,
    &MO_FORWARD_SM_ARG,
    &MO_FORWARD_SM_RES,
    &MT_FORWARD_SM_ARG,
    &MT_FORWARD_SM_RES,
    &REPORT_SM_DELIVERY_STATUS_ARG,
    &REPORT_SM_DELIVERY_STATUS_RES,
    &ALERT_SERVICE_CENTRE_ARG,
    &INFORM_SERVICE_CENTRE_ARG,
    &READY_FOR_SM_ARG,
    &SEND_AUTHENTICATION_INFO_ARG,
    &SEND_AUTHENTICATION_INFO_RES_TRIPLET,
    &SEND_AUTHENTICATION_INFO_RES_QUINTUPLET,
    &SEND_AUTHENTICATION_INFO_RES_EPS,
    &UPDATE_LOCATION_ARG,
    &UPDATE_LOCATION_RES,
    &UPDATE_GPRS_LOCATION_ARG_ISR,
    &UPDATE_GPRS_LOCATION_ARG_PDN_GW,
    &UPDATE_GPRS_LOCATION_RES,
    &CANCEL_LOCATION_ARG,
    &CANCEL_LOCATION_ARG_WITH_LMSI,
    &INSERT_SUBSCRIBER_DATA_ARG,
    &ANY_TIME_MODIFICATION_ARG_ACTIVATE,
    &ANY_TIME_MODIFICATION_ARG_DEACTIVATE,
    &ANY_TIME_MODIFICATION_RES,
    &ABSENT_SUBSCRIBER_SM,
    &SM_DELIVERY_FAILURE,
    &UNKNOWN_SUBSCRIBER,
    &ABSENT_SUBSCRIBER,
    &SUBSCRIBER_BUSY_FOR_MT_SMS,
    &UNEXPECTED_DATA_VALUE,
];
