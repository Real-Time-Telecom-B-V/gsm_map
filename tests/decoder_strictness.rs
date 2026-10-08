//! What `rasn` loses while decoding, and that [`gsm_map::decode`] refuses it.
//!
//! Each test first shows the leniency with `rasn::ber::decode` on the crate's
//! own type: the decode succeeds and data that was on the wire is gone. It
//! then shows `gsm_map::decode` returning an error for the same octets. If a
//! future `rasn` stops being lenient, the first half of a test fails and says
//! so; the second half is the behaviour this crate guarantees either way.
//!
//! The three cases (seen on rasn 0.28.14 and 0.28.15):
//!
//! 1. an OPTIONAL member behind an EXPLICIT tag whose content does not decode
//!    is reported as absent, after its octets have been consumed;
//! 2. a SEQUENCE OF whose last element does not decode is returned without
//!    that element (an earlier malformed element leaves octets behind and is
//!    caught by rasn);
//! 3. octets after the outermost value are ignored.
//!
//! The vectors are written by hand from the ASN.1 of TS 29.002 (Rel-18) and
//! all values are synthetic.

mod common;

use common::{accepted, lenient, refused, vector};
use gsm_map::operations::auth::SendAuthenticationInfoRes;
use gsm_map::operations::gprs_location::UpdateGprsLocationArg;
use gsm_map::operations::mt_forward_sm::MtForwardSmArg;
use gsm_map::operations::sri_sm::{RoutingInfoForSmArg, RoutingInfoForSmRes};
use gsm_map::operations::subscriber_info::AnyTimeModificationArg;
use gsm_map::types::AdditionalNumber;

// ── 1. OPTIONAL behind an EXPLICIT tag ──────────────────────────────────────

/// A routing-information answer naming two serving nodes, the second in an
/// alternative `Additional-Number` does not have.
///
/// ```text
/// 30 20                                  RoutingInfoForSM-Res
///    04 08 00 01 01 21 43 65 87 f9       imsi 001 01 0123456789
///    a0 14                               locationInfoWithLMSI [0]
///       81 07 91 51 55 10 00 10 f0       networkNode-Number [1] +1 555 010 0010
///       a6 09                            additional-Number [6], EXPLICIT: it is a CHOICE
///          85 07 91 51 55 10 00 20 f0    [5]; the alternatives are msc-Number [0]
///                                        and sgsn-Number [1]
/// ```
const SECOND_NODE_UNREADABLE: &str = "30 20 04 08 00 01 01 21 43 65 87 f9
     a0 14 81 07 91 51 55 10 00 10 f0 a6 09 85 07 91 51 55 10 00 20 f0";

#[test]
fn routing_info_additional_number_with_an_unknown_alternative() {
    let wire = vector(SECOND_NODE_UNREADABLE);

    let lost: RoutingInfoForSmRes = lenient(&wire);
    assert_eq!(
        lost.location_info_with_lmsi.additional_number, None,
        "the second serving node is on the wire and rasn dropped it"
    );
    // A service centre handed this value sees one serving node, delivers
    // there, and never tries the other.

    let error = refused::<RoutingInfoForSmRes>(&wire);
    assert!(error.contains("AdditionalNumber"), "{error}");
}

#[test]
fn routing_info_third_number_with_an_unknown_alternative() {
    // The same answer with the unreadable number in thirdNumber [9]:
    //   a9 09 85 07 91 51 55 10 00 20 f0
    let wire = vector(&SECOND_NODE_UNREADABLE.replace("a6 09", "a9 09"));

    let lost: RoutingInfoForSmRes = lenient(&wire);
    assert_eq!(lost.location_info_with_lmsi.third_number, None);

    let error = refused::<RoutingInfoForSmRes>(&wire);
    assert!(error.contains("AdditionalNumber"), "{error}");
}

#[test]
fn routing_info_additional_number_lost_while_a_later_member_survives() {
    // The unreadable additional-Number followed by imsNodeIndicator [11] NULL
    // (8b 00): the lengths grow by two, a0 16 and 30 22.
    let wire = vector(
        "30 22 04 08 00 01 01 21 43 65 87 f9
         a0 16 81 07 91 51 55 10 00 10 f0 a6 09 85 07 91 51 55 10 00 20 f0 8b 00",
    );

    let lost: RoutingInfoForSmRes = lenient(&wire);
    assert_eq!(lost.location_info_with_lmsi.additional_number, None);
    assert_eq!(lost.location_info_with_lmsi.ims_node_indicator, Some(()));

    let error = refused::<RoutingInfoForSmRes>(&wire);
    assert!(error.contains("AdditionalNumber"), "{error}");
}

#[test]
fn routing_info_additional_number_that_is_not_constructed() {
    // An EXPLICIT tag is always constructed (X.690 8.14.2). Here [6] is
    // primitive, 86 instead of a6, around the same well-formed sgsn-Number.
    //   86 09 81 07 91 51 55 10 00 20 f0
    let wire = vector(
        "30 20 04 08 00 01 01 21 43 65 87 f9
         a0 14 81 07 91 51 55 10 00 10 f0 86 09 81 07 91 51 55 10 00 20 f0",
    );

    // rasn does not look at the bit and reads the number.
    let read: RoutingInfoForSmRes = lenient(&wire);
    assert!(matches!(
        read.location_info_with_lmsi.additional_number,
        Some(AdditionalNumber::SgsnNumber(_))
    ));

    let error = refused::<RoutingInfoForSmRes>(&wire);
    assert!(error.contains("constructed"), "{error}");
}

#[test]
fn update_gprs_location_eps_info_with_a_truncated_member() {
    // 30 22                                UpdateGprsLocationArg
    //    04 08 00 01 01 21 43 65 87 f9     imsi
    //    04 07 91 51 55 10 00 30 f0        sgsn-Number +1 555 010 0030
    //    04 05 04 c0 00 02 01              sgsn-Address: IPv4, 192.0.2.1
    //    a5 06                             eps-info [5], EXPLICIT: it is a CHOICE
    //       a0 04                          pdn-gw-update [0]
    //          80 05 01 02                 apn [0]: five octets announced, two present
    let wire = vector(
        "30 22 04 08 00 01 01 21 43 65 87 f9 04 07 91 51 55 10 00 30 f0
         04 05 04 c0 00 02 01 a5 06 a0 04 80 05 01 02",
    );

    let lost: UpdateGprsLocationArg = lenient(&wire);
    assert_eq!(lost.eps_info, None, "eps-info is on the wire and is gone");
    // The HSS processes the location update as if the serving node had sent
    // no PDN gateway at all.

    let error = refused::<UpdateGprsLocationArg>(&wire);
    assert!(error.contains("truncated"), "{error}");
}

#[test]
fn update_gprs_location_eps_info_with_an_unknown_alternative() {
    // eps-info [5] holding [2]; EPS-Info has pdn-gw-update [0] and
    // isr-Information [1].
    //   a5 04 82 02 05 a0
    let wire = vector(
        "30 20 04 08 00 01 01 21 43 65 87 f9 04 07 91 51 55 10 00 30 f0
         04 05 04 c0 00 02 01 a5 04 82 02 05 a0",
    );

    let lost: UpdateGprsLocationArg = lenient(&wire);
    assert_eq!(lost.eps_info, None);

    let error = refused::<UpdateGprsLocationArg>(&wire);
    assert!(error.contains("EpsInfo"), "{error}");
}

#[test]
fn any_time_modification_subscriber_identity_was_never_lenient() {
    // The same kind of fault in a member that is not OPTIONAL fails in rasn
    // itself: the leniency is specific to OPTIONAL.
    //   30 10  a0 05 85 03 01 02 03       subscriberIdentity [0] holding [5]
    //          a3 07 81 05 91 51 55 10 99 gsmSCF-Address [3]
    let wire = vector("30 10 a0 05 85 03 01 02 03 a3 07 81 05 91 51 55 10 99");
    assert!(rasn::ber::decode::<AnyTimeModificationArg>(&wire).is_err());
    refused::<AnyTimeModificationArg>(&wire);
}

// ── 2. SEQUENCE OF ──────────────────────────────────────────────────────────

/// One authentication triplet (TS 29.002 `AuthenticationTriplet`):
///
/// ```text
/// 30 22
///    04 10 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f   rand, 16 octets
///    04 04 a1 a2 a3 a4                                       sres, 4 octets
///    04 08 c0 c1 c2 c3 c4 c5 c6 c7                           kc, 8 octets
/// ```
const TRIPLET: &str = "30 22 04 10 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f
     04 04 a1 a2 a3 a4 04 08 c0 c1 c2 c3 c4 c5 c6 c7";

/// A triplet that stops after its RAND: sres and kc are missing.
const HALF_TRIPLET: &str = "30 12 04 10 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f";

#[test]
fn authentication_triplet_list_loses_a_malformed_last_triplet() {
    // a3 3a                 SendAuthenticationInfoRes [3]
    //    a0 38              tripletList [0], the first alternative of
    //                       authenticationSetList (untagged CHOICE)
    //       30 22 ...       a complete triplet        (36 octets)
    //       30 12 ...       a triplet with RAND only  (20 octets)
    let wire = vector(&format!("a3 3a a0 38 {TRIPLET} {HALF_TRIPLET}"));

    let lost: SendAuthenticationInfoRes = lenient(&wire);
    assert_eq!(
        lost.triplet_list.map(|list| list.len()),
        Some(1),
        "one of two vectors is gone"
    );

    let error = refused::<SendAuthenticationInfoRes>(&wire);
    assert!(error.contains("triplet_list"), "{error}");
}

#[test]
fn authentication_triplet_list_with_one_malformed_triplet_comes_back_empty() {
    //   a3 16  a0 14  30 12 04 10 ...
    let wire = vector(&format!("a3 16 a0 14 {HALF_TRIPLET}"));

    let lost: SendAuthenticationInfoRes = lenient(&wire);
    assert_eq!(lost.triplet_list, Some(vec![]));
    // The answer reads as "here are your vectors: none".

    refused::<SendAuthenticationInfoRes>(&wire);
}

#[test]
fn a_malformed_triplet_before_a_good_one_was_never_lenient() {
    // With the short triplet first, rasn stops there, finds the good one left
    // over and reports unexpected extra data.
    let wire = vector(&format!("a3 3a a0 38 {HALF_TRIPLET} {TRIPLET}"));
    assert!(rasn::ber::decode::<SendAuthenticationInfoRes>(&wire).is_err());
    refused::<SendAuthenticationInfoRes>(&wire);
}

#[test]
fn a_well_formed_triplet_list_decodes() {
    let wire = vector(&format!("a3 4a a0 48 {TRIPLET} {TRIPLET}"));
    let value: SendAuthenticationInfoRes = accepted(&wire);
    assert_eq!(value.triplet_list.map(|list| list.len()), Some(2));
}

// ── 3. Octets after the value ───────────────────────────────────────────────

/// ```text
/// 30 13                            RoutingInfoForSM-Arg
///    80 07 91 51 55 10 00 99 f9    msisdn [0] +1 555 010 0999
///    81 01 ff                      sm-RP-PRI [1] TRUE
///    82 05 91 51 55 10 99          serviceCentreAddress [2] +1 555 0199
/// ```
const ROUTING_INFO_REQUEST: &str = "30 13 80 07 91 51 55 10 00 99 f9 81 01 ff 82 05 91 51 55 10 99";

#[test]
fn octets_after_the_argument_are_refused() {
    let wire = vector(&format!("{ROUTING_INFO_REQUEST} 05 00"));

    let read: RoutingInfoForSmArg = lenient(&wire);
    assert!(
        read.sm_rp_pri,
        "rasn reads the argument and ignores the rest"
    );

    let error = refused::<RoutingInfoForSmArg>(&wire);
    assert!(error.contains("2 octets follow"), "{error}");
}

#[test]
fn an_argument_cut_short_is_refused() {
    let wire = vector(ROUTING_INFO_REQUEST);
    for length in 0..wire.len() {
        assert!(
            gsm_map::decode::<RoutingInfoForSmArg>(&wire[..length]).is_err(),
            "the first {length} octets decoded"
        );
    }
    accepted::<RoutingInfoForSmArg>(&wire);
}

// ── Members in the wrong place ──────────────────────────────────────────────

#[test]
fn a_repeated_member_is_refused() {
    // gprsSupportIndicator [7] NULL twice.
    let wire = vector("30 17 80 07 91 51 55 10 00 99 f9 81 01 ff 82 05 91 51 55 10 99 87 00 87 00");
    let error = refused::<RoutingInfoForSmArg>(&wire);
    assert!(error.contains("gprs_support_indicator"), "{error}");
    assert!(error.contains("repeated or out of order"), "{error}");
}

#[test]
fn members_out_of_order_are_refused() {
    // sm-RP-MTI [8] before gprsSupportIndicator [7]. An independent decoder
    // walks past the misplaced member and loses it; here it is an error.
    let wire =
        vector("30 18 80 07 91 51 55 10 00 99 f9 81 01 ff 82 05 91 51 55 10 99 88 01 00 87 00");
    let error = refused::<RoutingInfoForSmArg>(&wire);
    assert!(error.contains("gprs_support_indicator"), "{error}");
}

#[test]
fn an_unknown_choice_alternative_in_a_mandatory_member_is_refused() {
    // MT-ForwardSM-Arg with sm-RP-DA [3]; SM-RP-DA has [0], [1], [4] and [5].
    // No CHOICE in TS 29.002 is extensible, so this is a mistyped parameter.
    //   30 0f  83 03 01 02 03  84 05 91 51 55 10 99  04 01 00
    let wire = vector("30 0f 83 03 01 02 03 84 05 91 51 55 10 99 04 01 00");
    assert!(rasn::ber::decode::<MtForwardSmArg>(&wire).is_err());
    refused::<MtForwardSmArg>(&wire);
}
