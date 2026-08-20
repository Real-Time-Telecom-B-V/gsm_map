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
//! ```no_run
//! use gsm_map::{application_context as ac, dialogue};
//!
//! let portion = dialogue::begin(&ac::short_msg_gateway_context(ac::V3));
//! // ... put `portion` in a tcap::Begin, send it, and on the answer:
//! # let answer = portion;
//! if let Some(pdu) = dialogue::parse(&answer) {
//!     println!("{pdu:?}");
//! }
//! ```

use rasn::types::ObjectIdentifier;

#[doc(inline)]
pub use tcap::dialogue::{
    AbortSource, AssociateResult, AssociateSourceDiagnostic, DialoguePdu, DialoguePortion,
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

/// The **AARE** portion that refuses the dialogue.
///
/// `reject-permanent` tells the peer not to retry; `reject-transient` invites a
/// retry. The diagnostic says who decided and why — for a MAP peer that does not
/// support the offered context, that is
/// `DialogueServiceUser(1)` (`no-reason-given`) or `DialogueServiceUser(2)`
/// (`application-context-name-not-supported`).
pub fn end_reject(
    ac: &ObjectIdentifier,
    result: AssociateResult,
    diagnostic: AssociateSourceDiagnostic,
) -> DialoguePortion {
    DialoguePortion::from_pdu(&DialoguePdu::Aare {
        protocol_version: Default::default(),
        application_context_name: ac.clone(),
        result,
        result_source_diagnostic: diagnostic,
        user_information: None,
    })
}

/// The **ABRT** portion for a TCAP `Abort`.
pub fn abort(source: AbortSource) -> DialoguePortion {
    DialoguePortion::abrt(source)
}

/// Parse a dialogue portion back into a typed PDU.
///
/// `None` if the portion is not a well-formed AARQ / AARE / ABRT — an opaque or
/// structured-dialogue portion, say. A peer that sends one has not refused the
/// dialogue, so treat `None` as "not something this layer models", not as an
/// error.
pub fn parse(portion: &DialoguePortion) -> Option<DialoguePdu> {
    portion.dialogue_pdu()
}

/// The application context a portion names, if it is an AARQ or an AARE.
///
/// An ABRT carries no context, and neither does a portion this layer cannot
/// parse; both give `None`.
pub fn application_context(portion: &DialoguePortion) -> Option<ObjectIdentifier> {
    match parse(portion)? {
        DialoguePdu::Aarq {
            application_context_name,
            ..
        }
        | DialoguePdu::Aare {
            application_context_name,
            ..
        } => Some(application_context_name),
        DialoguePdu::Abrt { .. } => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::application_context as ac;

    #[test]
    fn aarq_round_trips_through_the_portion() {
        let oid = ac::short_msg_gateway_context(ac::V3);
        let portion = begin(&oid);
        match parse(&portion).expect("AARQ parses") {
            DialoguePdu::Aarq { .. } => {}
            other => panic!("expected AARQ, got {other:?}"),
        }
        assert_eq!(application_context(&portion), Some(oid));
    }

    #[test]
    fn aare_carries_the_result_and_diagnostic() {
        let oid = ac::any_time_info_handling_context(ac::V3);
        match parse(&end_accept(&oid)).expect("AARE parses") {
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
        let refused = end_reject(
            &oid,
            AssociateResult::RejectedPermanent,
            AssociateSourceDiagnostic::DialogueServiceUser(2),
        );
        match parse(&refused).expect("AARE parses") {
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

    #[test]
    fn abrt_round_trips_and_names_no_context() {
        for source in [
            AbortSource::DialogueServiceUser,
            AbortSource::DialogueServiceProvider,
        ] {
            let portion = abort(source);
            match parse(&portion).expect("ABRT parses") {
                DialoguePdu::Abrt { abort_source, .. } => assert_eq!(abort_source, source),
                other => panic!("expected ABRT, got {other:?}"),
            }
            assert_eq!(application_context(&portion), None);
        }
    }

    #[test]
    fn a_portion_this_layer_does_not_model_parses_to_none() {
        let portion = DialoguePortion {
            external: rasn::types::Any::new(vec![0x28, 0x02, 0x05, 0x00]),
        };
        assert!(parse(&portion).is_none());
        assert!(application_context(&portion).is_none());
    }
}
