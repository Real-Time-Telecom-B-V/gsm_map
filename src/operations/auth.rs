//! Authentication operations — 3GPP TS 29.002.
//!
//! - sendAuthenticationInfo (op 56)
//!
//! Every member TS 29.002 defines is modelled; see [`crate`] on why an
//! unmodelled member is fatal rather than merely absent.

use rasn::prelude::*;

use crate::types::{ExtensionContainer, Imsi, Opaque, OpenEnumerated};

/// SendAuthenticationInfo-Arg (op 56).
///
/// ```asn1
/// SendAuthenticationInfoArg ::= SEQUENCE {
///     imsi                                [0] IMSI,
///     numberOfRequestedVectors                NumberOfRequestedVectors,
///     segmentationProhibited                  NULL OPTIONAL,
///     immediateResponsePreferred          [1] NULL OPTIONAL,
///     re-synchronisationInfo                  Re-synchronisationInfo OPTIONAL,
///     extensionContainer                  [2] ExtensionContainer OPTIONAL,
///     ...,
///     requestingNodeType                  [3] RequestingNodeType OPTIONAL,
///     requestingPLMN-Id                   [4] PLMN-Id OPTIONAL,
///     numberOfRequestedAdditional-Vectors [5] NumberOfRequestedVectors OPTIONAL,
///     additionalVectorsAreForEPS          [6] NULL OPTIONAL,
///     ueUsageTypeRequestIndication        [7] NULL OPTIONAL }
/// ```
///
/// `re-synchronisationInfo` is **untagged**; `[1]` is `immediateResponsePreferred`
/// and `[2]` is the extension container, not the other way round.
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct SendAuthenticationInfoArg {
    #[rasn(tag(context, 0))]
    pub imsi: Imsi,
    pub number_of_requested_vectors: Integer,
    pub segmentation_prohibited: Option<()>,
    #[rasn(tag(context, 1))]
    pub immediate_response_preferred: Option<()>,
    pub re_synchronisation_info: Option<ReSynchronisationInfo>,
    #[rasn(tag(context, 2))]
    pub extension_container: Option<ExtensionContainer>,
    /// `RequestingNodeType ::= ENUMERATED { vlr(0), sgsn(1), ..., s4-sgsn(2),
    /// mme(3), mme-sgsn(4) }`.
    #[rasn(tag(context, 3))]
    pub requesting_node_type: Option<Integer>,
    #[rasn(tag(context, 4))]
    pub requesting_plmn_id: Option<OctetString>,
    #[rasn(tag(context, 5))]
    pub number_of_requested_additional_vectors: Option<Integer>,
    #[rasn(tag(context, 6))]
    pub additional_vectors_are_for_eps: Option<()>,
    #[rasn(tag(context, 7))]
    pub ue_usage_type_request_indication: Option<()>,
}

impl SendAuthenticationInfoArg {
    /// The two mandatory members; every optional member starts `None`.
    pub fn new(imsi: Imsi, number_of_requested_vectors: Integer) -> Self {
        Self {
            imsi,
            number_of_requested_vectors,
            segmentation_prohibited: None,
            immediate_response_preferred: None,
            re_synchronisation_info: None,
            extension_container: None,
            requesting_node_type: None,
            requesting_plmn_id: None,
            number_of_requested_additional_vectors: None,
            additional_vectors_are_for_eps: None,
            ue_usage_type_request_indication: None,
        }
    }
}

/// Re-synchronisationInfo — the AUTS the USIM produced on a sequence-number
/// failure, so the HLR/AuC can resynchronise.
///
/// ```asn1
/// Re-synchronisationInfo ::= SEQUENCE {
///     rand  RAND,
///     auts  AUTS,
///     ... }
/// ```
///
/// Modelled rather than carried opaquely because it sits at an **untagged**
/// optional position, where an opaque value would have no tag to check against
/// and would swallow whatever follows.
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct ReSynchronisationInfo {
    pub rand: OctetString,
    pub auts: OctetString,
}

/// AuthenticationTriplet — GSM authentication vector.
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct AuthenticationTriplet {
    pub rand: OctetString,
    pub sres: OctetString,
    pub kc: OctetString,
}

/// AuthenticationQuintuplet — UMTS authentication vector.
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct AuthenticationQuintuplet {
    pub rand: OctetString,
    pub xres: OctetString,
    pub ck: OctetString,
    pub ik: OctetString,
    pub autn: OctetString,
}

/// AuthenticationSetList — CHOICE between triplets and quintuplets.
///
/// ```asn1
/// AuthenticationSetList ::= CHOICE {
///     tripletList     [0] TripletList,
///     quintupletList  [1] QuintupletList }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
#[rasn(choice)]
pub enum AuthenticationSetList {
    #[rasn(tag(context, 0))]
    TripletList(Vec<AuthenticationTriplet>),
    #[rasn(tag(context, 1))]
    QuintupletList(Vec<AuthenticationQuintuplet>),
}

/// SendAuthenticationInfo-Res (op 56) — v3.
///
/// ```asn1
/// SendAuthenticationInfoRes ::= [3] SEQUENCE {
///     authenticationSetList       AuthenticationSetList OPTIONAL,
///     extensionContainer          ExtensionContainer OPTIONAL,
///     ...,
///     eps-AuthenticationSetList   [2] EPS-AuthenticationSetList OPTIONAL,
///     ueUsageType                 [3] UE-Usage-Type OPTIONAL }
/// ```
///
/// The response as a whole carries context tag `[3]`.
/// The response as a whole carries context tag `[3]`.
///
/// `authenticationSetList` is an **untagged optional CHOICE**, which `rasn`
/// cannot decode in place: with no tag of its own there is nothing to test
/// before committing, so an absent list would swallow the next member. The two
/// alternatives are therefore separate fields carrying their own `[0]` / `[1]`
/// tags — identical on the wire, since only one may be present — and
/// [`authentication_set_list`](Self::authentication_set_list) reassembles the
/// ASN.1 view.
#[derive(Debug, Clone, Default, PartialEq, Eq, AsnType, Decode, Encode)]
#[rasn(tag(context, 3))]
pub struct SendAuthenticationInfoRes {
    #[rasn(tag(context, 0))]
    pub triplet_list: Option<Vec<AuthenticationTriplet>>,
    #[rasn(tag(context, 1))]
    pub quintuplet_list: Option<Vec<AuthenticationQuintuplet>>,
    pub extension_container: Option<ExtensionContainer>,
    #[rasn(tag(context, 2))]
    pub eps_authentication_set_list: Option<Opaque>,
    #[rasn(tag(context, 3))]
    pub ue_usage_type: Option<Integer>,
}

impl SendAuthenticationInfoRes {
    /// The vectors as the ASN.1 CHOICE, or `None` if neither list is present.
    pub fn authentication_set_list(&self) -> Option<AuthenticationSetList> {
        if let Some(triplets) = &self.triplet_list {
            Some(AuthenticationSetList::TripletList(triplets.clone()))
        } else {
            self.quintuplet_list
                .clone()
                .map(AuthenticationSetList::QuintupletList)
        }
    }

    /// Set the vectors from the ASN.1 CHOICE, clearing the other alternative.
    pub fn set_authentication_set_list(&mut self, list: AuthenticationSetList) {
        match list {
            AuthenticationSetList::TripletList(t) => {
                self.triplet_list = Some(t);
                self.quintuplet_list = None;
            }
            AuthenticationSetList::QuintupletList(q) => {
                self.quintuplet_list = Some(q);
                self.triplet_list = None;
            }
        }
    }
}

/// Operation codes for authentication. Re-exported from
/// [`crate::types::op_codes`].
pub mod op_codes {
    pub use crate::types::op_codes::{AUTHENTICATION_FAILURE_REPORT, SEND_AUTHENTICATION_INFO};
}

/// AuthenticationFailureReport-Arg (op 15) — the VLR/SGSN telling the HLR that
/// authentication failed, so the HLR can spot a cloned or misbehaving USIM.
///
/// ```asn1
/// AuthenticationFailureReportArg ::= SEQUENCE {
///     imsi                IMSI,
///     failureCause        FailureCause,
///     extensionContainer  ExtensionContainer OPTIONAL,
///     ...,
///     re-attempt          BOOLEAN OPTIONAL,
///     accessType          AccessType OPTIONAL,
///     rand                RAND OPTIONAL,
///     vlr-Number      [0] ISDN-AddressString OPTIONAL,
///     sgsn-Number     [1] ISDN-AddressString OPTIONAL }
/// ```
///
/// `failureCause` and `accessType` are untagged ENUMERATEDs, so they carry the
/// ENUMERATED universal tag: `wrongUserResponse(0)`, `wrongNetworkSignature(1)`;
/// `call(0)`, `emergencyCall(1)`, `locationUpdating(2)`, `supplementaryService(3)`,
/// `shortMessage(4)`, `gprsAttach(5)`, `routingAreaUpdating(6)`,
/// `serviceRequest(7)`, `pdpContextActivation(8)`, `pdpContextDeactivation(9)`,
/// `gprsDetach(10)`.
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct AuthenticationFailureReportArg {
    pub imsi: Imsi,
    pub failure_cause: OpenEnumerated,
    pub extension_container: Option<ExtensionContainer>,
    pub re_attempt: Option<bool>,
    pub access_type: Option<OpenEnumerated>,
    pub rand: Option<OctetString>,
    #[rasn(tag(context, 0))]
    pub vlr_number: Option<crate::types::IsdnAddressString>,
    #[rasn(tag(context, 1))]
    pub sgsn_number: Option<crate::types::IsdnAddressString>,
}

impl AuthenticationFailureReportArg {
    /// The two mandatory members; every optional member starts `None`.
    pub fn new(imsi: Imsi, failure_cause: OpenEnumerated) -> Self {
        Self {
            imsi,
            failure_cause,
            extension_container: None,
            re_attempt: None,
            access_type: None,
            rand: None,
            vlr_number: None,
            sgsn_number: None,
        }
    }
}

/// AuthenticationFailureReport-Res (op 15).
#[derive(Debug, Clone, Default, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct AuthenticationFailureReportRes {
    pub extension_container: Option<ExtensionContainer>,
}
