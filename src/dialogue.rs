//! TCAP dialogue portions for MAP — thin helpers over [`tcap::DialoguePortion`].
//!
//! A MAP dialogue announces its application context in the TCAP dialogue portion
//! so the peer knows which ASN.1 module the components belong to: an **AARQ** on
//! the `Begin`, an **AARE** on the `End`/`Continue`, an **ABRT** if either side
//! walks away. The `tcap` crate already models all three and can parse them
//! back, so this module only adds the MAP-shaped convenience: take an
//! [`application_context`](crate::application_context) OID, hand back a portion
//! ready to drop into a message.
//!
//! Reading a received portion has three outcomes, and they call for different
//! reactions: a PDU, a well-formed portion that carries something else, and a
//! malformed portion. The last one is an error ([`DialogueError`]), for which
//! Q.774 3.2.2.1 has the dialogue aborted.
//!
//! ```no_run
//! use gsm_map::{application_context as ac, dialogue};
//!
//! let portion = dialogue::begin(&ac::short_msg_gateway_context(ac::V3));
//! // ... put `portion` in a tcap::Begin, send it, and on the answer:
//! # let answer = portion;
//! match dialogue::parse(&answer) {
//!     Ok(Some(pdu)) => println!("{pdu:?}"),
//!     Ok(None) => println!("well-formed, not a dialogue PDU"),
//!     Err(error) => println!("abort the dialogue: {error}"),
//! }
//! ```

use rasn::types::ObjectIdentifier;

#[doc(inline)]
pub use tcap::dialogue::{
    AbortSource, AssociateResult, AssociateSourceDiagnostic, DialogueError, DialoguePdu,
    DialoguePortion, External, ExternalEncoding, ProtocolVersion,
};

/// The **AARQ** portion for a `Begin`: "let's talk `ac`".
pub fn begin(ac: &ObjectIdentifier) -> DialoguePortion {
    DialoguePortion::aarq(ac)
}

/// The **AARE** portion for an `End` or `Continue` that accepts the dialogue —
/// result `accepted(0)`, diagnostic `dialogue-service-user null(0)`.
pub fn end_accept(ac: &ObjectIdentifier) -> DialoguePortion {
    DialoguePortion::aare_accept(ac)
}

/// The **AARE** portion that refuses the dialogue: result `reject-permanent(1)`
/// with the given diagnostic.
///
/// Q.773 defines no other refusal (`reject-transient` is a value of ACSE, not
/// of the TC dialogue PDUs), so the result is not a parameter. The diagnostic
/// says who decided and why. For a MAP peer that does not support the offered
/// context that is [`AssociateSourceDiagnostic::USER_NO_REASON_GIVEN`] or
/// [`AssociateSourceDiagnostic::USER_APPLICATION_CONTEXT_NAME_NOT_SUPPORTED`].
///
/// A refusal does not travel in an `End`: it is the user abort information of
/// a TCAP `Abort` (Q.774 3.2.1.2).
pub fn end_reject(ac: &ObjectIdentifier, diagnostic: AssociateSourceDiagnostic) -> DialoguePortion {
    DialoguePortion::aare_reject(ac, diagnostic)
}

/// The **ABRT** portion for a TCAP `Abort`.
pub fn abort(source: AbortSource) -> DialoguePortion {
    DialoguePortion::abrt(source)
}

/// Parse a dialogue portion back into a typed PDU.
///
/// `Ok(None)` for a well-formed portion that carries something this layer does
/// not model, user information in a syntax of its own for instance. A peer
/// that sends one has not refused the dialogue, so that is not an error.
///
/// `Err` for a portion that is malformed. Q.774 3.2.2.1 has the dialogue
/// aborted in that case, with [`DialoguePortion::abnormal_dialogue`] as the
/// user abort information towards the peer.
pub fn parse(portion: &DialoguePortion) -> Result<Option<DialoguePdu>, DialogueError> {
    portion.dialogue_pdu()
}

/// The application context a portion names, if it is an AARQ, an AARE or an
/// AUDT.
///
/// An ABRT carries no context, and neither does a portion this layer does not
/// model; both give `Ok(None)`. A malformed portion is an `Err`, as in
/// [`parse`].
pub fn application_context(
    portion: &DialoguePortion,
) -> Result<Option<ObjectIdentifier>, DialogueError> {
    Ok(match parse(portion)? {
        Some(
            DialoguePdu::Aarq {
                application_context_name,
                ..
            }
            | DialoguePdu::Aare {
                application_context_name,
                ..
            }
            | DialoguePdu::Audt {
                application_context_name,
                ..
            },
        ) => Some(application_context_name),
        Some(DialoguePdu::Abrt { .. }) | None => None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::application_context as ac;

    #[test]
    fn aarq_round_trips_through_the_portion() {
        let oid = ac::short_msg_gateway_context(ac::V3);
        let portion = begin(&oid);
        match parse(&portion).expect("well-formed").expect("a PDU") {
            DialoguePdu::Aarq { .. } => {}
            other => panic!("expected AARQ, got {other:?}"),
        }
        assert_eq!(application_context(&portion), Ok(Some(oid)));
    }

    #[test]
    fn aare_carries_the_result_and_diagnostic() {
        let oid = ac::any_time_info_handling_context(ac::V3);
        match parse(&end_accept(&oid))
            .expect("well-formed")
            .expect("a PDU")
        {
            DialoguePdu::Aare {
                result,
                result_source_diagnostic,
                ..
            } => {
                assert_eq!(result, AssociateResult::Accepted);
                assert_eq!(
                    result_source_diagnostic,
                    AssociateSourceDiagnostic::DialogueServiceUser(0)
                );
            }
            other => panic!("expected AARE, got {other:?}"),
        }

        // application-context-name-not-supported: the answer an HLR gives an
        // IP-SM-GW that offered a context it does not implement.
        let refused = end_reject(&oid, AssociateSourceDiagnostic::DialogueServiceUser(2));
        match parse(&refused).expect("well-formed").expect("a PDU") {
            DialoguePdu::Aare {
                result,
                result_source_diagnostic,
                ..
            } => {
                assert_eq!(result, AssociateResult::RejectedPermanent);
                assert_eq!(
                    result_source_diagnostic,
                    AssociateSourceDiagnostic::DialogueServiceUser(2)
                );
            }
            other => panic!("expected AARE, got {other:?}"),
        }
    }

    /// The refusing AARE, octet by octet from Q.773 3.2.1 (DialoguePDUs) and
    /// Table 34, for shortMsgGatewayContext-v3 `0.4.0.0.1.0.20.3`. Not derived
    /// from the encoder.
    ///
    /// ```text
    /// 28 28                               EXTERNAL
    ///    06 07 00 11 86 05 01 01 01       dialogue-as-id 0.0.17.773.1.1.1
    ///    A0 1D                            single-ASN1-type
    ///       61 1B                         AARE-apdu [APPLICATION 1]
    ///          80 02 07 80                protocol-version { version1 }
    ///          A1 09 06 07 04 00 00 01 00 14 03   application-context-name
    ///          A2 03 02 01 01             result reject-permanent (1)
    ///          A3 05 A1 03 02 01 02       dialogue-service-user:
    ///                                     application-context-name-not-supported (2)
    /// ```
    #[test]
    fn refusing_aare_matches_the_hand_assembled_octets() {
        let expected: &[u8] = &[
            0x28, 0x28, 0x06, 0x07, 0x00, 0x11, 0x86, 0x05, 0x01, 0x01, 0x01, 0xA0, 0x1D, 0x61,
            0x1B, 0x80, 0x02, 0x07, 0x80, 0xA1, 0x09, 0x06, 0x07, 0x04, 0x00, 0x00, 0x01, 0x00,
            0x14, 0x03, 0xA2, 0x03, 0x02, 0x01, 0x01, 0xA3, 0x05, 0xA1, 0x03, 0x02, 0x01, 0x02,
        ];
        let portion = end_reject(
            &ac::short_msg_gateway_context(ac::V3),
            AssociateSourceDiagnostic::USER_APPLICATION_CONTEXT_NAME_NOT_SUPPORTED,
        );
        assert_eq!(portion.external.as_bytes(), expected);
    }

    #[test]
    fn abrt_round_trips_and_names_no_context() {
        for source in [
            AbortSource::DialogueServiceUser,
            AbortSource::DialogueServiceProvider,
        ] {
            let portion = abort(source);
            match parse(&portion).expect("well-formed").expect("a PDU") {
                DialoguePdu::Abrt { abort_source, .. } => assert_eq!(abort_source, source),
                other => panic!("expected ABRT, got {other:?}"),
            }
            assert_eq!(application_context(&portion), Ok(None));
        }
    }

    #[test]
    fn audt_names_its_context() {
        let oid = ac::short_msg_gateway_context(ac::V3);
        let portion = DialoguePortion::audt(&oid);
        assert_eq!(application_context(&portion), Ok(Some(oid)));
    }

    /// A well-formed EXTERNAL in a syntax of the user's own (`2.999.1`,
    /// carrying an OCTET STRING): not a dialogue PDU, and not an error.
    #[test]
    fn a_portion_this_layer_does_not_model_parses_to_none() {
        let portion = DialoguePortion {
            external: rasn::types::Any::new(vec![
                0x28, 0x0A, 0x06, 0x03, 0x88, 0x37, 0x01, 0xA0, 0x03, 0x04, 0x01, 0x00,
            ]),
        };
        assert_eq!(parse(&portion), Ok(None));
        assert_eq!(application_context(&portion), Ok(None));
    }

    /// An EXTERNAL without its `encoding` member (X.690 8.18.1 has it
    /// mandatory) is a syntactically incorrect dialogue portion. Q.774 3.2.2.1
    /// has the dialogue aborted, so it must not read as "nothing to see".
    #[test]
    fn a_malformed_portion_is_an_error() {
        let portion = DialoguePortion {
            external: rasn::types::Any::new(vec![0x28, 0x02, 0x05, 0x00]),
        };
        assert!(parse(&portion).is_err());
        assert!(application_context(&portion).is_err());
    }

    /// A portion that names the dialogue abstract syntax and carries a damaged
    /// AARE (the result `[2]` is missing) is malformed too.
    #[test]
    fn a_damaged_dialogue_pdu_is_an_error() {
        let portion = DialoguePortion {
            external: rasn::types::Any::new(vec![
                0x28, 0x1C, 0x06, 0x07, 0x00, 0x11, 0x86, 0x05, 0x01, 0x01, 0x01, 0xA0, 0x11, 0x61,
                0x0F, 0x80, 0x02, 0x07, 0x80, 0xA1, 0x09, 0x06, 0x07, 0x04, 0x00, 0x00, 0x01, 0x00,
                0x14, 0x03,
            ]),
        };
        assert!(parse(&portion).is_err());
    }
}
