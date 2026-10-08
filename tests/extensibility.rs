//! Members this crate does not model, and what happens to them.
//!
//! TS 29.002 (Rel-18) clause 17.1.4, "Compatibility considerations":
//!
//! > An extension marker ("...") is used wherever future protocol extensions
//! > are foreseen. The "..." construct applies only to SEQUENCE and ENUMERATED
//! > data types. An entity supporting a version greater than 1 shall not
//! > reject an unsupported extension following "..." of that SEQUENCE or
//! > ENUMERATED data type.
//!
//! `rasn` rejects them: a SEQUENCE with a member it does not know fails with
//! `UnexpectedExtraData`, and where that SEQUENCE is an element of a list the
//! failure turns into a list that is silently short. [`gsm_map::decode`]
//! skips such members where the type is extensible, reports them through
//! [`gsm_map::decode_with_extensions`], and still refuses everything that is
//! not an extension: a member of a type without a marker, a member this crate
//! does model in the wrong place, and an unknown CHOICE alternative (no CHOICE
//! in TS 29.002 has a marker).
//!
//! All values are synthetic.

mod common;

use common::{lenient, refused, vector};
use gsm_map::operations::auth::SendAuthenticationInfoRes;
use gsm_map::operations::mo_forward_sm::MoForwardSmRes;
use gsm_map::operations::sri_sm::{RoutingInfoForSmArg, RoutingInfoForSmRes};
use gsm_map::UnknownExtension;
use rasn::types::{Class, Tag};

/// ```text
/// 30 13                            RoutingInfoForSM-Arg
///    80 07 91 51 55 10 00 99 f9    msisdn [0] +1 555 010 0999
///    81 01 ff                      sm-RP-PRI [1] TRUE
///    82 05 91 51 55 10 99          serviceCentreAddress [2] +1 555 0199
/// ```
/// The 19 octets of content, to which each test appends members.
const REQUEST: &str = "80 07 91 51 55 10 00 99 f9 81 01 ff 82 05 91 51 55 10 99";

fn extension(container: &'static str, tag: Tag, encoding: &str) -> UnknownExtension {
    let encoding = vector(encoding);
    UnknownExtension {
        container,
        tag,
        constructed: encoding[0] & 0x20 != 0,
        encoding,
    }
}

// ── Extension additions are skipped and reported ────────────────────────────

#[test]
fn an_unknown_member_after_the_last_one_is_skipped_and_reported() {
    // [30] is past everything Rel-18 defines for RoutingInfoForSM-Arg, whose
    // last member is smsf-supportIndicator [16].
    //   30 16  <the request>  9e 01 2a
    let wire = vector(&format!("30 16 {REQUEST} 9e 01 2a"));

    assert!(
        rasn::ber::decode::<RoutingInfoForSmArg>(&wire).is_err(),
        "rasn refuses the whole argument"
    );

    let decoded = gsm_map::decode_with_extensions::<RoutingInfoForSmArg>(&wire).unwrap();
    assert!(decoded.value.sm_rp_pri);
    assert_eq!(decoded.value.smsf_support_indicator, None);
    assert_eq!(
        decoded.unknown_extensions,
        [extension(
            "RoutingInfoForSmArg",
            Tag::new(Class::Context, 30),
            "9e 01 2a"
        )]
    );
    assert_eq!(
        decoded.unknown_extensions[0].to_string(),
        "[30] in RoutingInfoForSmArg (3 octets)"
    );

    // The plain entry point decodes the same value and says nothing.
    let value: RoutingInfoForSmArg = gsm_map::decode(&wire).unwrap();
    assert_eq!(value, decoded.value);
}

#[test]
fn unknown_members_follow_modelled_additions() {
    // gprsSupportIndicator [7] and smsf-supportIndicator [16] (90 00), which
    // this crate models, then two additions it does not: a primitive [31]
    // (9f 1f 00, high tag number form) and a constructed [32] (bf 20 02 05 00).
    let wire = vector(&format!(
        "30 1f {REQUEST} 87 00 90 00 9f 1f 00 bf 20 02 05 00"
    ));

    let decoded = gsm_map::decode_with_extensions::<RoutingInfoForSmArg>(&wire).unwrap();
    assert_eq!(decoded.value.gprs_support_indicator, Some(()));
    assert_eq!(decoded.value.smsf_support_indicator, Some(()));
    assert_eq!(
        decoded.unknown_extensions,
        [
            extension(
                "RoutingInfoForSmArg",
                Tag::new(Class::Context, 31),
                "9f 1f 00"
            ),
            extension(
                "RoutingInfoForSmArg",
                Tag::new(Class::Context, 32),
                "bf 20 02 05 00"
            ),
        ]
    );
}

#[test]
fn an_unknown_member_of_a_nested_sequence_is_skipped() {
    // 30 19                               RoutingInfoForSM-Res
    //    04 08 00 01 01 21 43 65 87 f9    imsi
    //    a0 0d                            locationInfoWithLMSI [0]
    //       81 07 91 51 55 10 00 10 f0    networkNode-Number [1]
    //       9f 32 01 00                   [50]: the last Rel-18 member is [17]
    let wire =
        vector("30 19 04 08 00 01 01 21 43 65 87 f9 a0 0d 81 07 91 51 55 10 00 10 f0 9f 32 01 00");

    assert!(rasn::ber::decode::<RoutingInfoForSmRes>(&wire).is_err());

    let decoded = gsm_map::decode_with_extensions::<RoutingInfoForSmRes>(&wire).unwrap();
    assert_eq!(
        decoded.value.location_info_with_lmsi.network_node_number,
        common::isdn("15550100010")
    );
    assert_eq!(
        decoded.unknown_extensions,
        [extension(
            "LocationInfoWithLmsi",
            Tag::new(Class::Context, 50),
            "9f 32 01 00"
        )]
    );
}

#[test]
fn an_unknown_member_of_a_list_element_does_not_cost_the_element() {
    // AuthenticationTriplet ::= SEQUENCE { rand, sres, kc, ... }. The second
    // triplet carries a member [5] after kc.
    //   a3 4c  a0 4a
    //      30 22 <rand> <sres> <kc>            36 octets
    //      30 24 <rand> <sres> <kc> 85 00      38 octets
    let members = "04 10 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f
         04 04 a1 a2 a3 a4 04 08 c0 c1 c2 c3 c4 c5 c6 c7";
    let wire = vector(&format!(
        "a3 4c a0 4a 30 22 {members} 30 24 {members} 85 00"
    ));

    // rasn fails the second triplet, stops, and returns a list of one: the
    // refusal of an extension turned into silent loss.
    let lost: SendAuthenticationInfoRes = lenient(&wire);
    assert_eq!(lost.triplet_list.map(|list| list.len()), Some(1));

    let decoded = gsm_map::decode_with_extensions::<SendAuthenticationInfoRes>(&wire).unwrap();
    assert_eq!(decoded.value.triplet_list.map(|list| list.len()), Some(2));
    assert_eq!(
        decoded.unknown_extensions,
        [extension(
            "AuthenticationTriplet",
            Tag::new(Class::Context, 5),
            "85 00"
        )]
    );
}

#[test]
fn a_private_tagged_member_is_skipped() {
    // Clause 17.1.4: private extensions in a version 2 context "follow the
    // extension marker and [are] tagged using PRIVATE tags".
    //   c5 01 07   [PRIVATE 5]
    let wire = vector(&format!("30 16 {REQUEST} c5 01 07"));
    let decoded = gsm_map::decode_with_extensions::<RoutingInfoForSmArg>(&wire).unwrap();
    assert_eq!(
        decoded.unknown_extensions,
        [extension(
            "RoutingInfoForSmArg",
            Tag::new(Class::Private, 5),
            "c5 01 07"
        )]
    );
}

#[test]
fn an_unknown_untagged_member_is_skipped() {
    // MO-ForwardSM-Res ::= SEQUENCE { sm-RP-UI SignalInfo OPTIONAL,
    // extensionContainer ExtensionContainer OPTIONAL, ... }, followed by a
    // BOOLEAN no release defines.
    //   30 06  04 01 00  01 01 ff
    let wire = vector("30 06 04 01 00 01 01 ff");
    assert!(rasn::ber::decode::<MoForwardSmRes>(&wire).is_err());
    let decoded = gsm_map::decode_with_extensions::<MoForwardSmRes>(&wire).unwrap();
    assert_eq!(decoded.value.sm_rp_ui, Some(vec![0x00].into()));
    assert_eq!(
        decoded.unknown_extensions,
        [extension("MoForwardSmRes", Tag::BOOL, "01 01 ff")]
    );
}

#[test]
fn the_extension_container_is_extensible_too() {
    // extensionContainer [6] { [2] ... }: ExtensionContainer defines
    // privateExtensionList [0] and pcs-Extensions [1], then "...".
    let wire = vector(&format!("30 18 {REQUEST} a6 03 82 01 00"));
    let decoded = gsm_map::decode_with_extensions::<RoutingInfoForSmArg>(&wire).unwrap();
    assert!(decoded.value.extension_container.is_some());
    assert_eq!(
        decoded.unknown_extensions,
        [extension(
            "ExtensionContainer",
            Tag::new(Class::Context, 2),
            "82 01 00"
        )]
    );
}

// ── What is not an extension stays an error ─────────────────────────────────

#[test]
fn a_type_without_an_extension_marker_refuses_an_extra_member() {
    // NetworkNodeDiameterAddress ::= SEQUENCE { diameter-Name [0],
    // diameter-Realm [1] }: no marker.
    //
    // 30 32
    //    04 08 00 01 01 21 43 65 87 f9             imsi
    //    a0 26                                     locationInfoWithLMSI [0]
    //       81 07 91 51 55 10 00 10 f0             networkNode-Number [1]
    //       a7 1b                                  networkNodeDiameterAddress [7]
    //          80 0a 6d 73 63 30 31 2e 74 65 73 74    diameter-Name "msc01.test"
    //          81 0a 72 65 61 6c 6d 2e 74 65 73 74    diameter-Realm "realm.test"
    //          82 01 00                               [2]: not defined
    let wire = vector(
        "30 32 04 08 00 01 01 21 43 65 87 f9 a0 26 81 07 91 51 55 10 00 10 f0
         a7 1b 80 0a 6d 73 63 30 31 2e 74 65 73 74 81 0a 72 65 61 6c 6d 2e 74 65 73 74
         82 01 00",
    );
    let error = refused::<RoutingInfoForSmRes>(&wire);
    assert!(
        error.contains("NetworkNodeDiameterAddress is not extensible"),
        "{error}"
    );

    // Without the extra member it decodes.
    let wire = vector(
        "30 2f 04 08 00 01 01 21 43 65 87 f9 a0 23 81 07 91 51 55 10 00 10 f0
         a7 18 80 0a 6d 73 63 30 31 2e 74 65 73 74 81 0a 72 65 61 6c 6d 2e 74 65 73 74",
    );
    let value: RoutingInfoForSmRes = common::accepted(&wire);
    let address = value
        .location_info_with_lmsi
        .network_node_diameter_address
        .unwrap();
    assert_eq!(address.diameter_name, b"msc01.test".to_vec());
    assert_eq!(address.diameter_realm, b"realm.test".to_vec());
}

#[test]
fn correlation_id_has_no_extension_marker_either() {
    // CorrelationID ::= SEQUENCE { hlr-id [0] OPTIONAL, sip-uri-A [1]
    // OPTIONAL, sip-uri-B [2] }, here as correlationID [15] with a [3].
    //   af 08  82 03 73 69 70  83 01 00
    let wire = vector(&format!("30 1d {REQUEST} af 08 82 03 73 69 70 83 01 00"));
    let error = refused::<RoutingInfoForSmArg>(&wire);
    assert!(error.contains("CorrelationId is not extensible"), "{error}");

    let wire = vector(&format!("30 1a {REQUEST} af 05 82 03 73 69 70"));
    let value: RoutingInfoForSmArg = common::accepted(&wire);
    assert_eq!(value.correlation_id.unwrap().sip_uri_b, b"sip".to_vec());
}

#[test]
fn a_modelled_member_after_an_unknown_one_is_refused() {
    // Additions unknown to this crate can only come after the ones it knows:
    // the marker is the insertion point and every release appends. [30]
    // followed by gprsSupportIndicator [7] is a misplaced [7].
    let wire = vector(&format!("30 18 {REQUEST} 9e 01 2a 87 00"));
    let error = refused::<RoutingInfoForSmArg>(&wire);
    assert!(error.contains("gprs_support_indicator"), "{error}");
}

#[test]
fn a_malformed_unknown_member_is_refused() {
    // [30] announcing five octets with one present.
    let wire = vector(&format!("30 16 {REQUEST} 9e 05 2a"));
    let error = refused::<RoutingInfoForSmArg>(&wire);
    assert!(error.contains("truncated"), "{error}");
}

#[test]
fn a_modelled_member_that_does_not_decode_is_not_an_extension() {
    // sm-RP-MTI [8] is an INTEGER; here it is empty. The tag is one this
    // crate models, so the content has to decode.
    let wire = vector(&format!("30 15 {REQUEST} 88 00"));
    let error = refused::<RoutingInfoForSmArg>(&wire);
    assert!(error.contains("sm_rp_mti"), "{error}");
}

// ── Extensible ENUMERATED types ─────────────────────────────────────────────
//
// Clause 17.1.4 covers them with the same sentence as SEQUENCE: a value after
// the marker that the receiver does not know may not be rejected. What the
// receiver does with it differs per type and is written next to the type in
// the ASN.1, so the value is handed to the caller.

#[test]
fn an_unknown_value_of_an_extensible_enumerated_is_kept() {
    use gsm_map::operations::sri_sm::SmDeliveryNotIntended;

    // sm-deliveryNotIntended [10] with the value 2; the type defines 0 and 1
    // and then "...".
    //   8a 01 02
    let wire = vector(&format!("30 16 {REQUEST} 8a 01 02"));
    let value: RoutingInfoForSmArg = common::accepted(&wire);
    let not_intended = value.sm_delivery_not_intended.unwrap();
    assert_eq!(not_intended, SmDeliveryNotIntended::Unrecognised(2));
    assert!(!not_intended.is_recognised());
    assert_eq!(gsm_map::encode(&value).unwrap(), wire);

    // A value with a name decodes to the name.
    let wire = vector(&format!("30 16 {REQUEST} 8a 01 01"));
    let value: RoutingInfoForSmArg = common::accepted(&wire);
    assert_eq!(
        value.sm_delivery_not_intended,
        Some(SmDeliveryNotIntended::OnlyMccMncRequested)
    );
}

#[test]
fn an_unnamed_value_holding_a_named_number_is_the_named_value_on_the_wire() {
    use gsm_map::operations::sri_sm::SmDeliveryNotIntended;

    let unnamed = SmDeliveryNotIntended::Unrecognised(1);
    assert!(unnamed.is_recognised());
    assert_eq!(unnamed.value(), 1);
    assert_eq!(
        gsm_map::encode(&unnamed).unwrap(),
        gsm_map::encode(&SmDeliveryNotIntended::OnlyMccMncRequested).unwrap()
    );
    assert_eq!(
        gsm_map::decode::<SmDeliveryNotIntended>(&[0x0a, 0x01, 0x01]).unwrap(),
        SmDeliveryNotIntended::OnlyMccMncRequested
    );
}

#[test]
fn cancel_location_keeps_an_unknown_cancellation_type() {
    use gsm_map::operations::location::{CancelLocationArg, CancellationType, Identity};

    // a3 0d                               CancelLocationArg ::= [3] SEQUENCE
    //    04 08 00 01 01 21 43 65 87 f9    identity: imsi
    //    0a 01 07                         cancellationType 7 (0 to 2 are defined)
    let wire = vector("a3 0d 04 08 00 01 01 21 43 65 87 f9 0a 01 07");
    let value: CancelLocationArg = common::accepted(&wire);
    assert_eq!(value.identity, Identity::Imsi(common::IMSI.to_vec().into()));
    assert_eq!(
        value.cancellation_type,
        Some(CancellationType::Unrecognised(7))
    );

    let wire = vector("a3 0d 04 08 00 01 01 21 43 65 87 f9 0a 01 02");
    let value: CancelLocationArg = common::accepted(&wire);
    assert_eq!(
        value.cancellation_type,
        Some(CancellationType::InitialAttachProcedure)
    );
}

#[test]
fn every_extensible_enumerated_maps_its_numbers_both_ways() {
    use gsm_map::operations::lcs::LcsEvent;
    use gsm_map::operations::location::CancellationType;
    use gsm_map::operations::subscriber_data::NetworkAccessMode;

    for value in 0..=5 {
        assert!(LcsEvent::from_value(value).is_recognised(), "{value}");
        assert_eq!(LcsEvent::from_value(value).value(), value);
    }
    assert_eq!(LcsEvent::from_value(5), LcsEvent::EmergencyCallHandover);
    assert_eq!(LcsEvent::from_value(6), LcsEvent::Unrecognised(6));
    assert_eq!(
        NetworkAccessMode::from_value(2),
        NetworkAccessMode::OnlyPacket
    );
    assert_eq!(
        NetworkAccessMode::from_value(3),
        NetworkAccessMode::Unrecognised(3)
    );
    assert_eq!(
        CancellationType::from_value(-1),
        CancellationType::Unrecognised(-1)
    );
    // Untagged, the type is a universal ENUMERATED (0a), not an INTEGER (02).
    assert_eq!(
        gsm_map::encode(&LcsEvent::EmergencyCallHandover).unwrap(),
        [0x0a, 0x01, 0x05]
    );
    assert!(gsm_map::decode::<LcsEvent>(&[0x02, 0x01, 0x05]).is_err());
}

#[test]
fn an_enumerated_without_a_marker_refuses_an_unknown_value() {
    use gsm_map::operations::report_sm::ReportSmDeliveryStatusArg;

    // SM-DeliveryOutcome ::= ENUMERATED { memoryCapacityExceeded (0),
    // absentSubscriber (1), successfulTransfer (2) }: no marker.
    //   30 13  04 07 91 51 55 10 00 99 f9  04 05 91 51 55 10 99  0a 01 03
    let wire = vector("30 13 04 07 91 51 55 10 00 99 f9 04 05 91 51 55 10 99 0a 01 03");
    let error = refused::<ReportSmDeliveryStatusArg>(&wire);
    assert!(error.contains("sm_delivery_outcome"), "{error}");

    let wire = vector("30 13 04 07 91 51 55 10 00 99 f9 04 05 91 51 55 10 99 0a 01 02");
    common::accepted::<ReportSmDeliveryStatusArg>(&wire);
}
