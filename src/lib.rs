//! GSM MAP (Mobile Application Part) per 3GPP TS 29.002.
//!
//! Provides BER encode/decode for MAP operations across all major groups:
//! - **SMS**: SRI-SM, MO/MT-ForwardSM, reportSM-DeliveryStatus, alertSC, informSC, readyForSM
//! - **Location Management**: updateLocation, cancelLocation, purgeMS, sendIdentification
//! - **Authentication**: sendAuthenticationInfo (triplets + quintuplets)
//! - **Subscriber Data**: insertSubscriberData, deleteSubscriberData
//! - **Subscriber Info**: provideSubscriberInfo, anyTimeInterrogation,
//!   anyTimeModification (including the IP-SM-GW registration a node uses to
//!   make itself the MT-SMS routing node for a subscriber)
//! - **USSD**: processUnstructuredSS-Request, unstructuredSS-Request/Notify
//! - **Call Handling**: sendRoutingInfo, provideRoamingNumber
//! - **Supplementary Services**: registerSS, eraseSS, activateSS, deactivateSS, interrogateSS
//! - **Fault Recovery**: reset, restoreData
//!
//! Application contexts (v1/v2/v3) are provided for TCAP dialogue negotiation.
//!
//! The types derive their ASN.1 from `rasn`. Encode with [`encode`] and decode
//! with [`decode`].
//!
//! # Decoding what a peer sends
//!
//! Always decode with [`decode`] (or [`decode_with_extensions`]), never with
//! `rasn::ber::decode` on these types. `rasn` 0.28 is unsafe on signalling in
//! both directions:
//!
//! * it **loses data without an error**. An OPTIONAL member behind an
//!   EXPLICIT tag (in MAP: every CHOICE-typed member behind a context tag)
//!   whose content it cannot read comes back as absent; a SEQUENCE OF whose
//!   last element it cannot read comes back without that element; octets after
//!   the value are ignored. A `RoutingInfoForSM-Res` whose second serving node
//!   it could not read decodes as an answer with one serving node;
//! * it **refuses valid messages**. A SEQUENCE carrying a member from a later
//!   release than this crate models fails to decode, although TS 29.002
//!   17.1.4 says a receiver "shall not reject an unsupported extension
//!   following "..."".
//!
//! [`decode`] is this crate's own decoder. A member the crate models that
//! cannot be read is an error, as are a list element that cannot be read, an
//! unknown CHOICE alternative (no CHOICE in TS 29.002 is extensible), a member
//! that is repeated or out of order, and trailing octets. Members after the
//! last one the crate models, in a SEQUENCE that has an extension marker, are
//! skipped; [`decode_with_extensions`] returns them as [`UnknownExtension`] so
//! that a peer on a newer release does not go unnoticed. Extensible
//! ENUMERATED types keep a value they have no name for (an `Unrecognised`
//! variant or [`types::OpenEnumerated`]), because what a receiver does with it
//! is specified per type.
//!
//! Members the crate does not interpret are carried as [`types::Opaque`] and
//! survive a round trip.

pub mod address;
pub mod application_context;
pub mod dialogue;
pub mod error;
pub mod operations;
mod strict;
pub mod types;

/// PyO3 bindings (`--features python`). The default crate build is pyo3-free.
#[cfg(feature = "python")]
pub mod python;

#[cfg(feature = "python")]
pub use python::register;

pub use error::MapError;
pub use strict::{Decoded, UnknownExtension};
pub use types::{
    op_codes, operation_name, AddressString, Imsi, IsdnAddressString, Lmsi, LocationInfoWithLmsi,
    SmRpDa, SmRpOa, OPERATION_REGISTRY,
};

/// BER-encode a MAP operation argument, result or error parameter.
pub fn encode<T: rasn::Encode>(value: &T) -> Result<Vec<u8>, MapError> {
    Ok(rasn::ber::encode(value)?)
}

/// BER-decode a MAP operation argument, result or error parameter. This is
/// the way to decode anything a peer sent.
///
/// `bytes` has to hold exactly one value of `T`. A member this crate models
/// whose content cannot be read, a list element that cannot be read, an
/// unknown CHOICE alternative and octets after the value are all errors.
/// Members a later release of TS 29.002 added after the extension marker of
/// a SEQUENCE are skipped, as clause 17.1.4 requires; use
/// [`decode_with_extensions`] to learn that there were any.
///
/// Do not call `rasn::ber::decode` on this crate's types for anything that
/// came off a signalling link. See the crate documentation for what it loses
/// and what it refuses.
pub fn decode<T: rasn::Decode>(bytes: &[u8]) -> Result<T, MapError> {
    Ok(strict::decode(bytes)?.0)
}

/// [`decode`], also returning the extension additions that were skipped: the
/// members of an extensible SEQUENCE that this crate does not model. A
/// receiver that wants to know when a peer speaks a newer release than this
/// crate reads them here.
pub fn decode_with_extensions<T: rasn::Decode>(bytes: &[u8]) -> Result<Decoded<T>, MapError> {
    let (value, unknown_extensions) = strict::decode(bytes)?;
    Ok(Decoded {
        value,
        unknown_extensions,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rasn::types::{BitString, Integer, OctetString};

    /// Round-trip a value through BER and assert it comes back equal.
    fn round_trip<T: rasn::Decode + rasn::Encode + std::fmt::Debug + PartialEq>(val: &T) {
        let encoded = rasn::ber::encode(val).expect("encode failed");
        let decoded: T = rasn::ber::decode(&encoded).expect("decode failed");
        assert_eq!(&decoded, val);
        // The crate's own decoder has to agree with rasn on everything the
        // crate itself encodes, and find nothing it does not know.
        let strict = decode_with_extensions::<T>(&encoded).expect("strict decode failed");
        assert_eq!(&strict.value, val);
        assert_eq!(strict.unknown_extensions, []);
    }

    fn oct(bytes: &[u8]) -> OctetString {
        OctetString::from_slice(bytes)
    }

    /// A one-member opaque SEQUENCE, standing in for a sub-structure this crate
    /// carries but does not interpret.
    fn opaque() -> types::Opaque {
        types::Opaque::new(vec![0x80, 0x01, 0x2A])
    }

    fn bits(values: &[bool]) -> BitString {
        let mut out = BitString::new();
        for v in values {
            out.push(*v);
        }
        out
    }

    const MSISDN: &[u8] = &[0x91, 0x51, 0x55, 0x10, 0x00, 0x99, 0xF9];
    const SC_ADDR: &[u8] = &[0x91, 0x51, 0x55, 0x10, 0x99];
    const IMSI: &[u8] = &[0x00, 0x01, 0x01, 0x21, 0x43, 0x65, 0x87, 0xF9];

    // ── SMS ──

    use operations::alert_sc::{AlertServiceCentreArg, SmsGmscAlertEvent};
    use operations::inform_sc::InformServiceCentreArg;
    use operations::mo_forward_sm::{MoForwardSmArg, MoForwardSmRes};
    use operations::mt_forward_sm::{MtForwardSmArg, MtForwardSmRes};
    use operations::ready_for_sm::{AlertReason, ReadyForSmArg, ReadyForSmRes};
    use operations::report_sm::{
        ReportSmDeliveryStatusArg, ReportSmDeliveryStatusRes, SmDeliveryOutcome,
    };
    use operations::sri_sm::{
        CorrelationId, IpSmGwGuidance, RoutingInfoForSmArg, RoutingInfoForSmRes,
        SmDeliveryNotIntended,
    };

    #[test]
    fn sri_sm_arg() {
        round_trip(&RoutingInfoForSmArg::new(
            MSISDN.into(),
            true,
            SC_ADDR.into(),
        ));
        round_trip(&RoutingInfoForSmArg {
            extension_container: Some(types::ExtensionContainer::default()),
            gprs_support_indicator: Some(()),
            sm_rp_mti: Some(0.into()),
            sm_rp_smea: Some(oct(&[0x01])),
            sm_delivery_not_intended: Some(SmDeliveryNotIntended::OnlyMccMncRequested),
            ip_sm_gw_guidance_indicator: Some(()),
            imsi: Some(IMSI.into()),
            t4_trigger_indicator: Some(()),
            single_attempt_delivery: Some(()),
            correlation_id: Some(CorrelationId {
                hlr_id: Some(oct(&[0x01])),
                sip_uri_a: Some(oct(b"sip:a@example.net")),
                sip_uri_b: oct(b"sip:b@example.net"),
            }),
            smsf_support_indicator: Some(()),
            ..RoutingInfoForSmArg::new(MSISDN.into(), true, SC_ADDR.into())
        });
    }

    #[test]
    fn sri_sm_res() {
        round_trip(&RoutingInfoForSmRes {
            extension_container: Some(types::ExtensionContainer::default()),
            ip_sm_gw_guidance: Some(IpSmGwGuidance {
                minimum_delivery_time_value: 30.into(),
                recommended_delivery_time_value: 300.into(),
                extension_container: None,
            }),
            ..RoutingInfoForSmRes::new(
                IMSI.into(),
                LocationInfoWithLmsi {
                    lmsi: Some(oct(&[0, 0, 0, 1])),
                    gprs_node_indicator: Some(()),
                    additional_number: Some(types::AdditionalNumber::MscNumber(SC_ADDR.into())),
                    network_node_diameter_address: Some(types::NetworkNodeDiameterAddress {
                        diameter_name: oct(b"msc.example.net"),
                        diameter_realm: oct(b"example.net"),
                    }),
                    third_number: Some(types::AdditionalNumber::SgsnNumber(SC_ADDR.into())),
                    ims_node_indicator: Some(()),
                    smsf_3gpp_number: Some(SC_ADDR.into()),
                    smsf_non_3gpp_address_indicator: Some(()),
                    ..LocationInfoWithLmsi::new(SC_ADDR.into())
                },
            )
        });
    }

    #[test]
    fn mo_forward_sm() {
        round_trip(&MoForwardSmArg {
            extension_container: Some(types::ExtensionContainer::default()),
            imsi: Some(IMSI.into()),
            correlation_id: Some(CorrelationId {
                hlr_id: None,
                sip_uri_a: None,
                sip_uri_b: oct(b"sip:b@example.net"),
            }),
            sm_delivery_outcome: Some(SmDeliveryOutcome::SuccessfulTransfer),
            ..MoForwardSmArg::new(
                SmRpDa::ServiceCentreAddressDa(SC_ADDR.into()),
                SmRpOa::MsIsdn(MSISDN.into()),
                oct(&[0x01, 0x00, 0x0B]),
            )
        });
        round_trip(&MoForwardSmRes {
            sm_rp_ui: Some(oct(&[0x01])),
            extension_container: Some(types::ExtensionContainer::default()),
        });
    }

    #[test]
    fn mt_forward_sm() {
        round_trip(&MtForwardSmArg {
            more_messages_to_send: Some(()),
            extension_container: Some(types::ExtensionContainer::default()),
            sm_delivery_timer: Some(30.into()),
            sm_delivery_start_time: Some(oct(&[0x22, 0x01, 0x01])),
            sms_over_ip_only_indicator: Some(()),
            maximum_retransmission_time: Some(oct(&[0x22, 0x01, 0x02])),
            sms_gmsc_address: Some(SC_ADDR.into()),
            sms_gmsc_diameter_address: Some(types::NetworkNodeDiameterAddress {
                diameter_name: oct(b"gmsc.example.net"),
                diameter_realm: oct(b"example.net"),
            }),
            ..MtForwardSmArg::new(
                SmRpDa::Imsi(IMSI.into()),
                SmRpOa::ServiceCentreAddressOa(SC_ADDR.into()),
                oct(&[0x04, 0x0B, 0x91]),
            )
        });
        round_trip(&MtForwardSmRes::default());
    }

    #[test]
    fn report_sm_delivery_status() {
        round_trip(&ReportSmDeliveryStatusArg {
            absent_subscriber_diagnostic_sm: Some(5.into()),
            extension_container: Some(types::ExtensionContainer::default()),
            gprs_support_indicator: Some(()),
            delivery_outcome_indicator: Some(()),
            additional_sm_delivery_outcome: Some(SmDeliveryOutcome::AbsentSubscriber),
            ip_sm_gw_indicator: Some(()),
            ip_sm_gw_sm_delivery_outcome: Some(SmDeliveryOutcome::SuccessfulTransfer),
            imsi: Some(IMSI.into()),
            single_attempt_delivery: Some(()),
            smsf_non_3gpp_absent_subscriber_diag_sm: Some(9.into()),
            ..ReportSmDeliveryStatusArg::new(
                MSISDN.into(),
                SC_ADDR.into(),
                SmDeliveryOutcome::SuccessfulTransfer,
            )
        });
        round_trip(&ReportSmDeliveryStatusRes {
            stored_msisdn: Some(MSISDN.into()),
            extension_container: Some(types::ExtensionContainer::default()),
        });
    }

    #[test]
    fn alert_service_centre() {
        round_trip(&AlertServiceCentreArg {
            imsi: Some(IMSI.into()),
            maximum_ue_availability_time: Some(oct(&[0x22, 0x01])),
            sms_gmsc_alert_event: Some(SmsGmscAlertEvent::MsUnderNewServingNode),
            new_sgsn_number: Some(SC_ADDR.into()),
            new_mme_number: Some(SC_ADDR.into()),
            new_msc_number: Some(SC_ADDR.into()),
            ..AlertServiceCentreArg::new(MSISDN.into(), SC_ADDR.into())
        });
    }

    #[test]
    fn inform_service_centre() {
        round_trip(&InformServiceCentreArg {
            stored_msisdn: Some(MSISDN.into()),
            mw_status: Some(
                types::MwStatusFlags {
                    mnrf_set: true,
                    mcef_set: true,
                    ..Default::default()
                }
                .to_bits(),
            ),
            extension_container: Some(types::ExtensionContainer::default()),
            absent_subscriber_diagnostic_sm: Some(5.into()),
            additional_absent_subscriber_diagnostic_sm: Some(6.into()),
            smsf_3gpp_absent_subscriber_diagnostic_sm: Some(7.into()),
            smsf_non_3gpp_absent_subscriber_diagnostic_sm: Some(8.into()),
        });
    }

    #[test]
    fn mw_status_flags_survive_the_bit_string() {
        let flags = types::MwStatusFlags {
            sc_address_not_included: true,
            mcef_set: true,
            mnr5gn3g_set: true,
            ..Default::default()
        };
        assert_eq!(types::MwStatusFlags::from_bits(&flags.to_bits()), flags);
    }

    #[test]
    fn ready_for_sm() {
        round_trip(&ReadyForSmArg {
            alert_reason_indicator: Some(()),
            extension_container: Some(types::ExtensionContainer::default()),
            additional_alert_reason_indicator: Some(()),
            maximum_ue_availability_time: Some(oct(&[0x22, 0x01])),
            ..ReadyForSmArg::new(IMSI.into(), AlertReason::MemoryAvailable)
        });
        round_trip(&ReadyForSmRes::default());
    }

    // ── Location management ──

    use operations::location::{
        CancelLocationArg, CancelLocationRes, CancellationType, Identity, ImsiWithLmsi, PurgeMsArg,
        PurgeMsRes, SendIdentificationArg, SendIdentificationRes, UpdateLocationArg,
        UpdateLocationRes,
    };

    #[test]
    fn update_location() {
        round_trip(&UpdateLocationArg {
            lmsi: Some(oct(&[0, 0, 0, 1])),
            extension_container: Some(types::ExtensionContainer::default()),
            vlr_capability: Some(opaque()),
            inform_previous_network_entity: Some(()),
            cs_lcs_not_supported_by_ue: Some(()),
            v_gmlc_address: Some(oct(&[10, 0, 0, 1])),
            add_info: Some(opaque()),
            paging_area: Some(opaque()),
            skip_subscriber_data_update: Some(()),
            restoration_indicator: Some(()),
            eplmn_list: Some(opaque()),
            mme_diameter_address: Some(types::NetworkNodeDiameterAddress {
                diameter_name: oct(b"mme.example.net"),
                diameter_realm: oct(b"example.net"),
            }),
            ..UpdateLocationArg::new(IMSI.into(), SC_ADDR.into(), SC_ADDR.into())
        });
        round_trip(&UpdateLocationRes {
            extension_container: Some(types::ExtensionContainer::default()),
            add_capability: Some(()),
            paging_area_capability: Some(()),
            ..UpdateLocationRes::new(SC_ADDR.into())
        });
    }

    #[test]
    fn cancel_location() {
        for identity in [
            Identity::Imsi(IMSI.into()),
            Identity::ImsiWithLmsi(ImsiWithLmsi {
                imsi: IMSI.into(),
                lmsi: oct(&[0, 0, 0, 1]),
            }),
        ] {
            round_trip(&CancelLocationArg {
                cancellation_type: Some(CancellationType::SubscriptionWithdraw),
                extension_container: Some(types::ExtensionContainer::default()),
                type_of_update: Some(1.into()),
                mtrf_supported_and_authorized: Some(()),
                new_msc_number: Some(SC_ADDR.into()),
                new_vlr_number: Some(SC_ADDR.into()),
                new_lmsi: Some(oct(&[0, 0, 0, 2])),
                reattach_required: Some(()),
                ..CancelLocationArg::new(identity)
            });
        }
        round_trip(&CancelLocationRes::default());
    }

    #[test]
    fn cancel_location_arg_carries_context_tag_3() {
        let wire = rasn::ber::encode(&CancelLocationArg::new(Identity::Imsi(IMSI.into()))).unwrap();
        assert_eq!(wire[0], 0xA3, "CancelLocationArg is a [3] SEQUENCE");
    }

    #[test]
    fn purge_ms() {
        round_trip(&PurgeMsArg {
            vlr_number: Some(SC_ADDR.into()),
            sgsn_number: Some(SC_ADDR.into()),
            extension_container: Some(types::ExtensionContainer::default()),
            ..PurgeMsArg::new(IMSI.into())
        });
        round_trip(&PurgeMsRes {
            freeze_tmsi: Some(()),
            freeze_p_tmsi: Some(()),
            extension_container: Some(types::ExtensionContainer::default()),
            freeze_m_tmsi: Some(()),
        });
    }

    #[test]
    fn send_identification() {
        round_trip(&SendIdentificationArg {
            number_of_requested_vectors: Some(3.into()),
            segmentation_prohibited: Some(()),
            extension_container: Some(types::ExtensionContainer::default()),
            msc_number: Some(SC_ADDR.into()),
            previous_lai: Some(oct(&[0, 1, 1, 0, 1])),
            hop_counter: Some(2.into()),
            mt_roaming_forwarding_supported: Some(()),
            new_vlr_number: Some(SC_ADDR.into()),
            new_lmsi: Some(oct(&[0, 0, 0, 1])),
            ..SendIdentificationArg::new(oct(&[0x11, 0x22, 0x33, 0x44]))
        });
        round_trip(&SendIdentificationRes {
            imsi: Some(IMSI.into()),
            current_security_context: Some(opaque()),
            extension_container: Some(types::ExtensionContainer::default()),
            last_used_lte_plmn_id: Some(oct(&[0, 0xF1, 0x10])),
            ..Default::default()
        });
        round_trip(&SendIdentificationRes {
            imsi: Some(IMSI.into()),
            triplet_list: Some(vec![AuthenticationTriplet {
                rand: oct(&[1; 16]),
                sres: oct(&[2; 4]),
                kc: oct(&[3; 8]),
            }]),
            extension_container: Some(types::ExtensionContainer::default()),
            ..Default::default()
        });
    }

    // ── Authentication ──

    use operations::auth::{
        AuthenticationQuintuplet, AuthenticationSetList, AuthenticationTriplet,
        ReSynchronisationInfo, SendAuthenticationInfoArg, SendAuthenticationInfoRes,
    };

    #[test]
    fn send_authentication_info() {
        round_trip(&SendAuthenticationInfoArg {
            segmentation_prohibited: Some(()),
            immediate_response_preferred: Some(()),
            re_synchronisation_info: Some(ReSynchronisationInfo {
                rand: oct(&[0x11; 16]),
                auts: oct(&[0x22; 14]),
            }),
            extension_container: Some(types::ExtensionContainer::default()),
            requesting_node_type: Some(3.into()),
            requesting_plmn_id: Some(oct(&[0, 0xF1, 0x10])),
            number_of_requested_additional_vectors: Some(2.into()),
            additional_vectors_are_for_eps: Some(()),
            ue_usage_type_request_indication: Some(()),
            ..SendAuthenticationInfoArg::new(IMSI.into(), 3.into())
        });

        let triplets: Vec<AuthenticationTriplet> = (0..3)
            .map(|i| AuthenticationTriplet {
                rand: oct(&[i; 16]),
                sres: oct(&[i; 4]),
                kc: oct(&[i; 8]),
            })
            .collect();
        let mut res = SendAuthenticationInfoRes {
            extension_container: Some(types::ExtensionContainer::default()),
            eps_authentication_set_list: Some(vec![operations::auth::EpcAv {
                rand: oct(&[0x01; 16]),
                xres: oct(&[0x02; 8]),
                autn: oct(&[0x03; 16]),
                kasme: oct(&[0x04; 32]),
                extension_container: Some(types::ExtensionContainer::default()),
            }]),
            ue_usage_type: Some(oct(&[0x00, 0x00, 0x00, 0x01])),
            ..Default::default()
        };
        res.set_authentication_set_list(AuthenticationSetList::TripletList(triplets.clone()));
        round_trip(&res);
        assert_eq!(
            res.authentication_set_list(),
            Some(AuthenticationSetList::TripletList(triplets))
        );

        let quintuplets = vec![AuthenticationQuintuplet {
            rand: oct(&[1; 16]),
            xres: oct(&[2; 8]),
            ck: oct(&[3; 16]),
            ik: oct(&[4; 16]),
            autn: oct(&[5; 16]),
        }];
        res.set_authentication_set_list(AuthenticationSetList::QuintupletList(quintuplets.clone()));
        assert_eq!(res.triplet_list, None);
        round_trip(&res);
        assert_eq!(
            res.authentication_set_list(),
            Some(AuthenticationSetList::QuintupletList(quintuplets))
        );

        // The vectors absent while later members are present: the shape that
        // an untagged optional CHOICE could not decode.
        round_trip(&SendAuthenticationInfoRes {
            ue_usage_type: Some(oct(&[0x00, 0x00, 0x00, 0x01])),
            ..Default::default()
        });
    }

    #[test]
    fn send_authentication_info_res_carries_context_tag_3() {
        let wire = rasn::ber::encode(&SendAuthenticationInfoRes::default()).unwrap();
        assert_eq!(wire[0], 0xA3, "SendAuthenticationInfoRes is a [3] SEQUENCE");
    }

    // ── Subscriber data ──

    use operations::subscriber_data::{
        DeleteSubscriberDataArg, DeleteSubscriberDataRes, InsertSubscriberDataArg,
        InsertSubscriberDataRes, NetworkAccessMode, SubscriberStatus,
    };

    #[test]
    fn insert_subscriber_data() {
        round_trip(&InsertSubscriberDataArg {
            imsi: Some(IMSI.into()),
            msisdn: Some(MSISDN.into()),
            category: Some(oct(&[0x0A])),
            subscriber_status: Some(SubscriberStatus::ServiceGranted),
            teleservice_list: Some(vec![oct(&[0x21])]),
            odb_data: Some(operations::subscriber_data::OdbData {
                odb_hplmn_data: Some(bits(&[false, true])),
                ..operations::subscriber_data::OdbData::new(bits(&[true, false, false, true]))
            }),
            roaming_restriction_due_to_unsupported_feature: Some(()),
            extension_container: Some(types::ExtensionContainer::default()),
            network_access_mode: Some(NetworkAccessMode::OnlyPacket),
            lmu_indicator: Some(()),
            ist_alert_timer: Some(30.into()),
            charging_characteristics: Some(oct(&[0x08, 0x00])),
            ics_indicator: Some(true),
            sgsn_number: Some(SC_ADDR.into()),
            mdt_user_consent: Some(false),
            additional_msisdn: Some(MSISDN.into()),
            ue_usage_type: Some(oct(&[0x00, 0x00, 0x00, 0x02])),
            iab_operation_allowed_indicator: Some(()),
            ..Default::default()
        });
        round_trip(&InsertSubscriberDataRes {
            teleservice_list: Some(vec![oct(&[0x21])]),
            odb_general_data: Some(bits(&[false, true])),
            regional_subscription_response: Some(1.into()),
            extension_container: Some(types::ExtensionContainer::default()),
            supported_features: Some(bits(&[true])),
            ..Default::default()
        });
    }

    #[test]
    fn delete_subscriber_data() {
        round_trip(&DeleteSubscriberDataArg {
            basic_service_list: Some(vec![oct(&[0x21])]),
            roaming_restriction_due_to_unsupported_feature: Some(()),
            extension_container: Some(types::ExtensionContainer::default()),
            gprs_subscription_data_withdraw: Some(types::Opaque::new(vec![0x05, 0x00])),
            subscribed_periodic_tau_rau_timer_withdraw: Some(()),
            subscribed_vsrvcc_withdraw: Some(()),
            iab_operation_withdraw: Some(()),
            ..DeleteSubscriberDataArg::new(IMSI.into())
        });
        round_trip(&DeleteSubscriberDataRes {
            regional_subscription_response: Some(0.into()),
            extension_container: Some(types::ExtensionContainer::default()),
        });
    }

    // ── Subscriber information ──

    use operations::subscriber_info::{
        AnyTimeInterrogationArg, AnyTimeInterrogationRes, AnyTimeModificationArg,
        AnyTimeModificationRes, CellGlobalIdOrServiceAreaIdOrLai, LocationInformation,
        ModificationInstruction, ModificationRequestForIpSmGwData, NotReachableReason,
        ProvideSubscriberInfoArg, ProvideSubscriberInfoRes, RequestedInfo, SubscriberIdentity,
        SubscriberInfo, SubscriberState,
    };

    fn requested_info() -> RequestedInfo {
        RequestedInfo {
            location_information: Some(()),
            subscriber_state: Some(()),
            extension_container: Some(types::ExtensionContainer::default()),
            current_location: Some(()),
            requested_domain: Some(1.into()),
            imei: Some(()),
            ms_classmark: Some(()),
            mnp_requested_info: Some(()),
            location_information_eps_supported: Some(()),
            t_ads_data: Some(()),
            requested_nodes: Some(bits(&[true, true])),
            serving_node_indication: Some(()),
            local_time_zone_request: Some(()),
        }
    }

    fn subscriber_info() -> SubscriberInfo {
        SubscriberInfo {
            location_information: Some(LocationInformation {
                age_of_location_information: Some(5.into()),
                geographical_information: Some(oct(&[0x10; 8])),
                vlr_number: Some(SC_ADDR.into()),
                location_number: Some(oct(&[0x01])),
                cell_global_id_or_service_area_id_or_lai: Some(
                    CellGlobalIdOrServiceAreaIdOrLai::LaiFixedLength(oct(&[0, 0xF1, 0x10, 0, 1])),
                ),
                extension_container: Some(types::ExtensionContainer::default()),
                selected_lsa_id: Some(oct(&[1, 2, 3])),
                msc_number: Some(SC_ADDR.into()),
                geodetic_information: Some(oct(&[0x20; 10])),
                current_location_retrieved: Some(()),
                sai_present: Some(()),
                location_information_eps: Some(opaque()),
                user_csg_information: Some(opaque()),
            }),
            subscriber_state: Some(SubscriberState::NetDetNotReachable(
                NotReachableReason::ImsiDetached,
            )),
            extension_container: Some(types::ExtensionContainer::default()),
            location_information_gprs: Some(opaque()),
            ps_subscriber_state: Some(types::Opaque::new(vec![0x80, 0x00])),
            imei: Some(oct(&[0x01; 8])),
            ms_classmark2: Some(oct(&[0x33, 0x19, 0xA2])),
            gprs_ms_class: Some(opaque()),
            mnp_info_res: Some(opaque()),
            ims_voice_over_ps_sessions_indication: Some(1.into()),
            last_ue_activity_time: Some(oct(&[0x22, 0x01])),
            last_rat_type: Some(5.into()),
            eps_subscriber_state: Some(types::Opaque::new(vec![0x80, 0x00])),
            location_information_eps: Some(opaque()),
            time_zone: Some(oct(&[0x40])),
            daylight_saving_time: Some(1.into()),
            location_information_5gs: Some(opaque()),
        }
    }

    #[test]
    fn provide_subscriber_info() {
        round_trip(&ProvideSubscriberInfoArg {
            lmsi: Some(oct(&[0, 0, 0, 1])),
            extension_container: Some(types::ExtensionContainer::default()),
            call_priority: Some(2.into()),
            ..ProvideSubscriberInfoArg::new(IMSI.into(), requested_info())
        });
        round_trip(&ProvideSubscriberInfoRes {
            subscriber_info: subscriber_info(),
            extension_container: Some(types::ExtensionContainer::default()),
        });
    }

    #[test]
    fn any_time_interrogation() {
        round_trip(&AnyTimeInterrogationArg {
            subscriber_identity: SubscriberIdentity::Msisdn(MSISDN.into()),
            requested_info: requested_info(),
            gsm_scf_address: SC_ADDR.into(),
            extension_container: Some(types::ExtensionContainer::default()),
        });
        round_trip(&AnyTimeInterrogationRes {
            subscriber_info: subscriber_info(),
            extension_container: Some(types::ExtensionContainer::default()),
        });
    }

    #[test]
    fn any_time_modification() {
        round_trip(&AnyTimeModificationArg {
            modification_request_for_cf_info: Some(opaque()),
            modification_request_for_cb_info: Some(opaque()),
            modification_request_for_csi: Some(opaque()),
            extension_container: Some(types::ExtensionContainer::default()),
            long_ftn_supported: Some(()),
            modification_request_for_odb_data: Some(opaque()),
            modification_request_for_ip_sm_gw_data: Some(ModificationRequestForIpSmGwData {
                modify_registration_status: Some(ModificationInstruction::Activate),
                extension_container: Some(types::ExtensionContainer::default()),
                ip_sm_gw_diameter_address: Some(types::NetworkNodeDiameterAddress {
                    diameter_name: oct(b"ipsmgw.example.net"),
                    diameter_realm: oct(b"example.net"),
                }),
            }),
            activation_request_for_ue_reachability: Some(bits(&[true, false])),
            modification_request_for_csg: Some(opaque()),
            modification_request_for_cw_data: Some(opaque()),
            modification_request_for_clip_data: Some(opaque()),
            modification_request_for_clir_data: Some(opaque()),
            modification_request_for_hold_data: Some(opaque()),
            modification_request_for_ect_data: Some(opaque()),
            ..AnyTimeModificationArg::new(SubscriberIdentity::Imsi(IMSI.into()), SC_ADDR.into())
        });
        round_trip(&AnyTimeModificationRes {
            ss_info_for_cse: Some(types::Opaque::new(vec![0xA0, 0x00])),
            camel_subscription_info: Some(opaque()),
            extension_container: Some(types::ExtensionContainer::default()),
            odb_info: Some(opaque()),
            cw_data: Some(opaque()),
            ch_data: Some(opaque()),
            clip_data: Some(opaque()),
            clir_data: Some(opaque()),
            ect_data: Some(opaque()),
            service_centre_address: Some(SC_ADDR.into()),
        });
    }

    // ── GPRS location ──

    use operations::gprs_location::{
        FailureReportArg, FailureReportRes, NoteMsPresentForGprsArg, NoteMsPresentForGprsRes,
        SendRoutingInfoForGprsArg, SendRoutingInfoForGprsRes, UpdateGprsLocationArg,
        UpdateGprsLocationRes,
    };

    #[test]
    fn update_gprs_location() {
        round_trip(&UpdateGprsLocationArg {
            extension_container: Some(types::ExtensionContainer::default()),
            sgsn_capability: Some(opaque()),
            inform_previous_network_entity: Some(()),
            ps_lcs_not_supported_by_ue: Some(()),
            eps_info: Some(operations::gprs_location::EpsInfo::IsrInformation(bits(&[
                true, false, true,
            ]))),
            used_rat_type: Some(4.into()),
            sms_only: Some(()),
            sgsn_name: Some(oct(b"sgsn.example.net")),
            sgsn_realm: Some(oct(b"example.net")),
            adjacent_plmn_list: Some(opaque()),
            ..UpdateGprsLocationArg::new(IMSI.into(), SC_ADDR.into(), oct(&[10, 0, 0, 1]))
        });
        round_trip(&UpdateGprsLocationRes {
            extension_container: Some(types::ExtensionContainer::default()),
            add_capability: Some(()),
            sgsn_mme_separation_supported: Some(()),
            mme_registered_for_sms: Some(()),
            ..UpdateGprsLocationRes::new(SC_ADDR.into())
        });
    }

    #[test]
    fn gprs_routing_and_reports() {
        round_trip(&SendRoutingInfoForGprsArg {
            imsi: IMSI.into(),
            ggsn_address: Some(oct(&[10, 0, 0, 2])),
            ggsn_number: SC_ADDR.into(),
            extension_container: Some(types::ExtensionContainer::default()),
        });
        round_trip(&SendRoutingInfoForGprsRes {
            sgsn_address: oct(&[10, 0, 0, 1]),
            ggsn_address: Some(oct(&[10, 0, 0, 2])),
            mobile_not_reachable_reason: Some(5.into()),
            extension_container: Some(types::ExtensionContainer::default()),
        });
        round_trip(&FailureReportArg {
            imsi: IMSI.into(),
            ggsn_number: SC_ADDR.into(),
            ggsn_address: Some(oct(&[10, 0, 0, 2])),
            extension_container: None,
        });
        round_trip(&FailureReportRes::default());
        round_trip(&NoteMsPresentForGprsArg {
            imsi: IMSI.into(),
            sgsn_address: oct(&[10, 0, 0, 1]),
            ggsn_address: None,
            extension_container: None,
        });
        round_trip(&NoteMsPresentForGprsRes::default());
    }

    // ── Call handling ──

    use operations::call_handling::{
        InterrogationType, ProvideRoamingNumberArg, ProvideRoamingNumberRes, SendRoutingInfoArg,
        SendRoutingInfoRes,
    };

    #[test]
    fn send_routing_info() {
        round_trip(&SendRoutingInfoArg {
            interrogation_type: Some(InterrogationType::BasicCall),
            or_interrogation: Some(()),
            call_reference_number: Some(oct(&[1, 2, 3])),
            basic_service_group: Some(types::Opaque::new(vec![0x82, 0x01, 0x11])),
            network_signal_info: Some(opaque()),
            extension_container: Some(types::ExtensionContainer::default()),
            long_ftn_supported: Some(()),
            mt_roaming_retry_supported: Some(()),
            call_priority: Some(1.into()),
            ..SendRoutingInfoArg::new(MSISDN.into(), SC_ADDR.into())
        });
        round_trip(&SendRoutingInfoRes {
            imsi: Some(IMSI.into()),
            extended_routing_info: Some(types::Opaque::new(vec![0xA0, 0x00])),
            subscriber_info: Some(subscriber_info()),
            vmsc_address: Some(SC_ADDR.into()),
            extension_container: Some(types::ExtensionContainer::default()),
            msisdn: Some(MSISDN.into()),
            release_resources_supported: Some(()),
            ..Default::default()
        });
    }

    #[test]
    fn send_routing_info_res_carries_context_tag_3() {
        let wire = rasn::ber::encode(&SendRoutingInfoRes::default()).unwrap();
        assert_eq!(wire[0], 0xA3, "SendRoutingInfoRes is a [3] SEQUENCE");
    }

    #[test]
    fn provide_roaming_number() {
        round_trip(&ProvideRoamingNumberArg {
            msisdn: Some(MSISDN.into()),
            lmsi: Some(oct(&[0, 0, 0, 1])),
            gmsc_address: Some(SC_ADDR.into()),
            or_interrogation: Some(()),
            extension_container: Some(types::ExtensionContainer::default()),
            pre_paging_supported: Some(()),
            paging_area: Some(opaque()),
            call_priority: Some(1.into()),
            mtrf_indicator: Some(()),
            old_msc_number: Some(SC_ADDR.into()),
            last_used_lte_plmn_id: Some(oct(&[0, 0xF1, 0x10])),
            ..ProvideRoamingNumberArg::new(IMSI.into(), SC_ADDR.into())
        });
        round_trip(&ProvideRoamingNumberRes {
            extension_container: Some(types::ExtensionContainer::default()),
            release_resources_supported: Some(()),
            vmsc_address: Some(SC_ADDR.into()),
            ..ProvideRoamingNumberRes::new(SC_ADDR.into())
        });
    }

    // ── Supplementary services ──

    use operations::supplementary::{
        BasicServiceCode, InterrogateSsRes, RegisterSsArg, SsForBsCode, SsInfo,
    };

    #[test]
    fn supplementary_services() {
        round_trip(&RegisterSsArg {
            teleservice: Some(oct(&[0x21])),
            forwarded_to_number: Some(SC_ADDR.into()),
            no_reply_condition_time: Some(20.into()),
            forwarded_to_subaddress: Some(oct(&[0x01])),
            default_priority: Some(2.into()),
            nbr_user: Some(3.into()),
            long_ftn_supported: Some(()),
            ..RegisterSsArg::new(oct(&[0x21]))
        });
        round_trip(&SsForBsCode {
            bearer_service: Some(oct(&[0x11])),
            long_ftn_supported: Some(()),
            ..SsForBsCode::new(oct(&[0x21]))
        });
        // basicService absent while [4] is present: the shape an untagged
        // optional CHOICE could not decode.
        round_trip(&SsForBsCode {
            long_ftn_supported: Some(()),
            ..SsForBsCode::new(oct(&[0x21]))
        });
        round_trip(&SsInfo::ForwardingInfo(opaque()));
        round_trip(&InterrogateSsRes::SsStatus(oct(&[0x05])));
        round_trip(&InterrogateSsRes::BasicServiceGroupList(vec![
            BasicServiceCode::Teleservice(oct(&[0x21])),
        ]));
    }

    // ── USSD ──

    use operations::ussd::{
        ProcessUnstructuredSsRequestArg, ProcessUnstructuredSsRequestRes, UnstructuredSsNotifyArg,
        UnstructuredSsNotifyRes, UnstructuredSsRequestArg, UnstructuredSsRequestRes,
    };

    #[test]
    fn ussd() {
        let dcs = oct(&[0x0F]);
        let text = oct(&[0xAA, 0x18, 0x0C, 0x36, 0x02]);
        round_trip(&ProcessUnstructuredSsRequestArg {
            alerting_pattern: Some(oct(&[0x01])),
            msisdn: Some(MSISDN.into()),
            ..ProcessUnstructuredSsRequestArg::new(dcs.clone(), text.clone())
        });
        round_trip(&ProcessUnstructuredSsRequestRes {
            ussd_data_coding_scheme: dcs.clone(),
            ussd_string: text.clone(),
        });
        round_trip(&UnstructuredSsRequestArg::new(dcs.clone(), text.clone()));
        round_trip(&UnstructuredSsRequestRes {
            ussd_data_coding_scheme: dcs.clone(),
            ussd_string: text.clone(),
        });
        round_trip(&UnstructuredSsNotifyArg::new(dcs, text));
        round_trip(&UnstructuredSsNotifyRes::default());
    }

    // ── Fault recovery ──

    use operations::fault_recovery::{ResetArg, RestoreDataArg, RestoreDataRes, SendingNodeNumber};

    #[test]
    fn fault_recovery() {
        round_trip(&ResetArg {
            hlr_list: Some(vec![oct(&[0x01, 0x02])]),
            extension_container: Some(types::ExtensionContainer::default()),
            reset_id_list: Some(opaque()),
            subscription_data: Some(opaque()),
            subscription_data_deletion: Some(opaque()),
            ..ResetArg::new(SendingNodeNumber::HlrNumber(SC_ADDR.into()))
        });
        round_trip(&RestoreDataArg {
            lmsi: Some(oct(&[0, 0, 0, 1])),
            extension_container: Some(types::ExtensionContainer::default()),
            vlr_capability: Some(opaque()),
            restoration_indicator: Some(()),
            ..RestoreDataArg::new(IMSI.into())
        });
        round_trip(&RestoreDataRes {
            ms_not_reachable: Some(()),
            extension_container: Some(types::ExtensionContainer::default()),
            ..RestoreDataRes::new(SC_ADDR.into())
        });
    }

    // ── OAM ──

    use operations::oam::{
        ActivateTraceModeArg, ActivateTraceModeRes, DeactivateTraceModeArg, DeactivateTraceModeRes,
    };

    #[test]
    fn oam() {
        round_trip(&ActivateTraceModeArg {
            imsi: Some(IMSI.into()),
            omc_id: Some(SC_ADDR.into()),
            extension_container: Some(types::ExtensionContainer::default()),
            trace_reference2: Some(oct(&[9, 8, 7])),
            trace_depth_list: Some(opaque()),
            trace_ne_type_list: Some(bits(&[true, false, true])),
            trace_interface_list: Some(opaque()),
            trace_event_list: Some(opaque()),
            trace_collection_entity: Some(oct(&[10, 0, 0, 9])),
            mdt_configuration: Some(opaque()),
            ..ActivateTraceModeArg::new(oct(&[1, 2, 3]), 1.into())
        });
        round_trip(&ActivateTraceModeRes {
            extension_container: Some(types::ExtensionContainer::default()),
            trace_support_indicator: Some(()),
        });
        round_trip(&DeactivateTraceModeArg {
            imsi: Some(IMSI.into()),
            extension_container: Some(types::ExtensionContainer::default()),
            trace_reference2: Some(oct(&[9, 8, 7])),
            ..DeactivateTraceModeArg::new(oct(&[1, 2, 3]))
        });
        round_trip(&DeactivateTraceModeRes::default());
    }

    // ── IMEI ──

    use operations::imei::{CheckImeiArg, CheckImeiRes, EquipmentStatus, UesbiIu};

    #[test]
    fn check_imei() {
        round_trip(&CheckImeiArg {
            extension_container: Some(types::ExtensionContainer::default()),
            ..CheckImeiArg::equipment_status_only(oct(&[0x01; 8]))
        });
        round_trip(&CheckImeiRes {
            equipment_status: Some(EquipmentStatus::GreyListed),
            bmuef: Some(UesbiIu {
                uesbi_iu_a: Some(bits(&[true, false])),
                uesbi_iu_b: Some(bits(&[false, true])),
            }),
            extension_container: Some(types::ExtensionContainer::default()),
        });
    }

    // ── Handover ──

    use operations::handover::{
        ExternalSignalInfo, PrepareHandoverArg, PrepareHandoverRes, PrepareSubsequentHandoverArg,
        PrepareSubsequentHandoverRes, SendEndSignalRes,
    };

    #[test]
    fn handover() {
        let apdu = ExternalSignalInfo::new(3.into(), oct(&[0x01, 0x02, 0x03]));
        assert_eq!(
            rasn::ber::encode(&apdu).unwrap()[2],
            0x0A,
            "protocolId is an untagged ENUMERATED"
        );
        round_trip(&PrepareHandoverArg {
            target_cell_id: Some(oct(&[0, 0xF1, 0x10, 0, 1, 0, 2])),
            ho_number_not_required: Some(()),
            bss_apdu: Some(apdu.clone()),
        });
        round_trip(&PrepareHandoverRes {
            handover_number: Some(SC_ADDR.into()),
            bss_apdu: Some(apdu.clone()),
        });
        round_trip(&apdu);
        round_trip(&SendEndSignalRes {
            extension_container: Some(types::ExtensionContainer::default()),
        });
        round_trip(&PrepareSubsequentHandoverArg {
            target_cell_id: Some(oct(&[0, 0xF1, 0x10, 0, 1, 0, 2])),
            an_apdu: Some(opaque()),
            selected_rab_id: Some(1.into()),
            extension_container: Some(types::ExtensionContainer::default()),
            geran_classmark: Some(oct(&[0x33])),
            rab_configuration_indicator: Some(()),
            ..PrepareSubsequentHandoverArg::new(SC_ADDR.into())
        });
        round_trip(&PrepareSubsequentHandoverRes {
            an_apdu: Some(operations::handover::AccessNetworkSignalInfo {
                extension_container: Some(types::ExtensionContainer::default()),
                ..operations::handover::AccessNetworkSignalInfo::new(
                    2.into(),
                    oct(&[0x01, 0x02, 0x03]),
                )
            }),
            extension_container: Some(types::ExtensionContainer::default()),
        });
    }

    // ── LCS ──

    use operations::lcs::{
        LcsEvent, ProvideSubscriberLocationArg, ProvideSubscriberLocationRes,
        SendRoutingInfoForLcsArg, SendRoutingInfoForLcsRes, SubscriberIdentityLcs,
        SubscriberLocationReportArg, SubscriberLocationReportRes,
    };

    #[test]
    fn lcs() {
        round_trip(&ProvideSubscriberLocationArg {
            lcs_client_id: Some(operations::lcs::LcsClientId {
                lcs_client_dialed_by_ms: Some(SC_ADDR.into()),
                lcs_client_internal_id: Some(1.into()),
                ..operations::lcs::LcsClientId::new(0.into())
            }),
            imsi: Some(IMSI.into()),
            msisdn: Some(MSISDN.into()),
            lcs_qos: Some(opaque()),
            extension_container: Some(types::ExtensionContainer::default()),
            supported_gad_shapes: Some(bits(&[true, false, true])),
            h_gmlc_address: Some(oct(&[10, 0, 0, 5])),
            reporting_plmn_list: Some(opaque()),
            ..ProvideSubscriberLocationArg::new(opaque(), SC_ADDR.into())
        });
        round_trip(&ProvideSubscriberLocationRes {
            age_of_location_estimate: Some(3.into()),
            extension_container: Some(types::ExtensionContainer::default()),
            cell_id_or_sai: Some(types::Opaque::new(vec![
                0x80, 0x07, 0, 0xF1, 0x10, 0, 1, 0, 2,
            ])),
            sai_present: Some(()),
            target_serving_node_for_handover: Some(types::Opaque::new(vec![0xA0, 0x00])),
            utran_baro_pressure_meas: Some(1000.into()),
            ..ProvideSubscriberLocationRes::new(oct(&[0x10; 8]))
        });
        round_trip(&SendRoutingInfoForLcsArg {
            mlc_number: SC_ADDR.into(),
            target_ms: SubscriberIdentityLcs::Msisdn(MSISDN.into()),
            extension_container: Some(types::ExtensionContainer::default()),
        });
        round_trip(&SendRoutingInfoForLcsRes {
            target_ms: SubscriberIdentityLcs::Imsi(IMSI.into()),
            lcs_location_info: opaque(),
            extension_container: None,
            v_gmlc_address: Some(oct(&[10, 0, 0, 6])),
            h_gmlc_address: None,
            ppr_address: None,
            additional_v_gmlc_address: None,
        });
        round_trip(&SubscriberLocationReportArg {
            lcs_event: LcsEvent::EmergencyCallOrigination,
            lcs_client_id: operations::lcs::LcsClientId::new(0.into()),
            lcs_location_info: opaque(),
            msisdn: Some(MSISDN.into()),
            imsi: Some(IMSI.into()),
            imei: None,
            na_esrd: None,
            na_esrk: None,
            location_estimate: Some(oct(&[0x10; 8])),
            age_of_location_estimate: Some(1.into()),
            slr_arg_extension_container: None,
            add_location_estimate: None,
            deferred_mt_lr_data: None,
            lcs_reference_number: Some(oct(&[0x07])),
            geran_positioning_data: None,
            utran_positioning_data: None,
            cell_id_or_sai: Some(types::Opaque::new(vec![0x81, 0x05, 0, 0xF1, 0x10, 0, 1])),
            h_gmlc_address: None,
            lcs_service_type_id: Some(1.into()),
            sai_present: Some(()),
            pseudonym_indicator: Some(()),
            accuracy_fulfilment_indicator: Some(0.into()),
        });
        round_trip(&SubscriberLocationReportRes {
            extension_container: Some(types::ExtensionContainer::default()),
            na_esrk: Some(SC_ADDR.into()),
            lcs_reference_number: Some(oct(&[0x07])),
            ..Default::default()
        });
    }

    // ── Operations added in 2.0.0 ──

    use operations::auth::{AuthenticationFailureReportArg, AuthenticationFailureReportRes};
    use operations::call_handling::{
        IstAlertArg, IstAlertRes, IstCommandArg, IstCommandRes, ReleaseResourcesArg,
        ReleaseResourcesRes, RemoteUserFreeArg, RemoteUserFreeRes, ResumeCallHandlingArg,
        ResumeCallHandlingRes, SetReportingStateArg, SetReportingStateRes, StatusReportArg,
        StatusReportRes,
    };
    use operations::group_call::{
        ForwardGroupCallSignallingArg, PrepareGroupCallArg, PrepareGroupCallRes,
        ProcessGroupCallSignallingArg, SendGroupCallEndSignalArg, SendGroupCallEndSignalRes,
        SendGroupCallInfoArg, SendGroupCallInfoRes,
    };
    use operations::lcs::{
        LcsAreaEventRequestArg, LcsLocationNotificationArg, LcsLocationNotificationRes,
        LcsLocationUpdateArg, LcsLocationUpdateRes, LcsMolrArg, LcsMolrRes,
        LcsPeriodicLocationCancellationArg, LcsPeriodicLocationRequestArg,
        LcsPeriodicLocationRequestRes,
    };
    use operations::location::{
        CancelVcsgLocationArg, CancelVcsgLocationRes, UpdateVcsgLocationArg, UpdateVcsgLocationRes,
    };
    use operations::mt_forward_sm::{MtForwardSmVgcsArg, MtForwardSmVgcsRes};
    use operations::notification::{
        NoteMmEventArg, NoteMmEventRes, NoteSubscriberDataModifiedArg,
        NoteSubscriberDataModifiedRes, SsInvocationNotificationArg, SsInvocationNotificationRes,
    };
    use operations::subscriber_info::{
        AnyTimeSubscriptionInterrogationArg, AnyTimeSubscriptionInterrogationRes,
    };
    use operations::supplementary::{
        AccessRegisterCcEntryArg, AccessRegisterCcEntryRes, CallDeflectionArg, EraseCcEntryArg,
        EraseCcEntryRes, NotifySsArg, RegisterCcEntryArg, RegisterCcEntryRes, UserUserServiceArg,
    };

    #[test]
    fn notifications() {
        round_trip(&NoteSubscriberDataModifiedArg {
            odb_info: Some(opaque()),
            all_information_sent: Some(()),
            extension_container: Some(types::ExtensionContainer::default()),
            ue_reachable: Some(bits(&[true, false, true])),
            ect_data: Some(opaque()),
            ..NoteSubscriberDataModifiedArg::new(IMSI.into(), MSISDN.into())
        });
        round_trip(&NoteSubscriberDataModifiedRes::default());
        round_trip(&SsInvocationNotificationArg {
            ss_event_specification: Some(opaque()),
            b_subscriber_number: Some(SC_ADDR.into()),
            ccbs_request_state: Some(2.into()),
            ..SsInvocationNotificationArg::new(IMSI.into(), MSISDN.into(), oct(&[0x41]))
        });
        round_trip(&SsInvocationNotificationRes::default());
        round_trip(&NoteMmEventArg {
            supported_camel_phases: Some(bits(&[true, true])),
            location_information_gprs: Some(opaque()),
            ..NoteMmEventArg::new(7.into(), oct(&[0x00]), IMSI.into(), MSISDN.into())
        });
        round_trip(&NoteMmEventRes::default());
    }

    #[test]
    fn authentication_failure_report() {
        round_trip(&AuthenticationFailureReportArg {
            re_attempt: Some(true),
            access_type: Some(4.into()),
            rand: Some(oct(&[0x11; 16])),
            vlr_number: Some(SC_ADDR.into()),
            sgsn_number: Some(SC_ADDR.into()),
            ..AuthenticationFailureReportArg::new(IMSI.into(), 0.into())
        });
        round_trip(&AuthenticationFailureReportRes::default());
    }

    #[test]
    fn vcsg_location() {
        round_trip(&UpdateVcsgLocationArg {
            msisdn: Some(MSISDN.into()),
            vlr_number: Some(SC_ADDR.into()),
            sgsn_number: Some(SC_ADDR.into()),
            extension_container: Some(types::ExtensionContainer::default()),
            ..UpdateVcsgLocationArg::new(IMSI.into())
        });
        round_trip(&UpdateVcsgLocationRes {
            temporary_empty_subscription_data_indicator: Some(()),
            extension_container: Some(types::ExtensionContainer::default()),
        });
        round_trip(&CancelVcsgLocationArg {
            identity: Identity::Imsi(IMSI.into()),
            extension_container: Some(types::ExtensionContainer::default()),
        });
        round_trip(&CancelVcsgLocationRes::default());
    }

    #[test]
    fn mt_forward_sm_vgcs() {
        round_trip(&MtForwardSmVgcsArg {
            asci_call_reference: oct(&[0x01, 0x02, 0x03]),
            sm_rp_oa: SmRpOa::MsIsdn(MSISDN.into()),
            sm_rp_ui: oct(&[0x01, 0x00]),
            extension_container: Some(types::ExtensionContainer::default()),
        });
        round_trip(&MtForwardSmVgcsRes {
            sm_rp_ui: Some(oct(&[0x01])),
            dispatcher_list: Some(vec![oct(SC_ADDR)]),
            ongoing_call: Some(()),
            extension_container: Some(types::ExtensionContainer::default()),
            additional_dispatcher_list: Some(vec![oct(SC_ADDR)]),
        });
    }

    #[test]
    fn call_handling_extras() {
        round_trip(&ResumeCallHandlingArg {
            call_reference_number: Some(oct(&[0x01, 0x02])),
            imsi: Some(IMSI.into()),
            o_csi: Some(opaque()),
            ccbs_possible: Some(()),
            msisdn: Some(MSISDN.into()),
            mt_roaming_retry: Some(()),
            ..Default::default()
        });
        round_trip(&ResumeCallHandlingRes::default());
        round_trip(&ReleaseResourcesArg {
            msrn: SC_ADDR.into(),
            extension_container: Some(types::ExtensionContainer::default()),
        });
        round_trip(&ReleaseResourcesRes::default());
        round_trip(&SetReportingStateArg {
            imsi: Some(IMSI.into()),
            lmsi: Some(oct(&[0, 0, 0, 1])),
            ccbs_monitoring: Some(1.into()),
            extension_container: Some(types::ExtensionContainer::default()),
        });
        round_trip(&SetReportingStateRes {
            ccbs_subscriber_status: Some(1.into()),
            extension_container: None,
        });
        round_trip(&StatusReportArg {
            event_report_data: Some(opaque()),
            call_report_data: Some(opaque()),
            ..StatusReportArg::new(IMSI.into())
        });
        round_trip(&StatusReportRes::default());
        round_trip(&RemoteUserFreeArg {
            call_info: Some(opaque()),
            ccbs_feature: Some(opaque()),
            translated_b_number: Some(SC_ADDR.into()),
            replace_b_number: Some(()),
            ..RemoteUserFreeArg::new(IMSI.into())
        });
        round_trip(&RemoteUserFreeRes {
            ruf_outcome: Some(0.into()),
            extension_container: None,
        });
        round_trip(&IstAlertArg {
            imsi: IMSI.into(),
            extension_container: Some(types::ExtensionContainer::default()),
        });
        round_trip(&IstAlertRes {
            ist_alert_timer: Some(30.into()),
            ist_information_withdraw: Some(()),
            call_termination_indicator: Some(1.into()),
            extension_container: None,
        });
        round_trip(&IstCommandArg {
            imsi: IMSI.into(),
            extension_container: None,
        });
        round_trip(&IstCommandRes::default());
    }

    #[test]
    fn supplementary_service_extras() {
        round_trip(&NotifySsArg {
            ss_code: Some(oct(&[0x21])),
            ss_status: Some(oct(&[0x05])),
            ss_notification: Some(bits(&[true, false, true])),
            call_is_waiting_indicator: Some(()),
            cug_index: Some(1.into()),
            multicall_indicator: Some(0.into()),
            ..Default::default()
        });
        round_trip(&RegisterCcEntryArg {
            ss_code: oct(&[0x21]),
            ccbs_data: Some(opaque()),
        });
        round_trip(&RegisterCcEntryRes {
            ccbs_feature: Some(opaque()),
        });
        round_trip(&EraseCcEntryArg {
            ss_code: oct(&[0x21]),
            ccbs_index: Some(1.into()),
        });
        round_trip(&EraseCcEntryRes {
            ss_code: Some(oct(&[0x21])),
            ss_status: Some(oct(&[0x05])),
        });
        round_trip(&AccessRegisterCcEntryArg::default());
        round_trip(&AccessRegisterCcEntryRes {
            ccbs_feature: Some(opaque()),
        });
        round_trip(&CallDeflectionArg {
            deflected_to_number: SC_ADDR.into(),
            deflected_to_subaddress: Some(oct(&[0x01])),
        });
        round_trip(&UserUserServiceArg {
            uus_service: 1.into(),
            uus_required: true,
        });
    }

    #[test]
    fn any_time_subscription_interrogation() {
        round_trip(&AnyTimeSubscriptionInterrogationArg {
            subscriber_identity: SubscriberIdentity::Msisdn(MSISDN.into()),
            requested_subscription_info: opaque(),
            gsm_scf_address: Some(SC_ADDR.into()),
            extension_container: Some(types::ExtensionContainer::default()),
            long_ftn_supported: Some(()),
        });
        round_trip(&AnyTimeSubscriptionInterrogationRes {
            odb_info: Some(opaque()),
            supported_vlr_camel_phases: Some(bits(&[true])),
            msisdn_bs_list: Some(opaque()),
            ect_data: Some(opaque()),
            ..Default::default()
        });
    }

    #[test]
    fn group_call() {
        round_trip(&PrepareGroupCallArg {
            group_key_number_vk_id: Some(1.into()),
            group_key: Some(oct(&[0x11; 8])),
            priority: Some(2.into()),
            uplink_free: Some(()),
            vstk_rand: Some(oct(&[0x01, 0x02, 0x03, 0x04, 0x50])),
            uplink_reply_indicator: Some(()),
            ..PrepareGroupCallArg::new(
                oct(&[0x11]),
                oct(&[0x01, 0x02, 0x03]),
                oct(&[0x01, 0x02]),
                oct(&[0x01]),
            )
        });
        round_trip(&PrepareGroupCallRes {
            group_call_number: SC_ADDR.into(),
            extension_container: Some(types::ExtensionContainer::default()),
        });
        round_trip(&SendGroupCallEndSignalArg {
            imsi: Some(IMSI.into()),
            talker_priority: Some(1.into()),
            additional_info: Some(bits(&[true, false])),
            ..Default::default()
        });
        round_trip(&SendGroupCallEndSignalRes::default());
        round_trip(&ProcessGroupCallSignallingArg {
            uplink_request: Some(()),
            release_group_call: Some(()),
            extension_container: Some(types::ExtensionContainer::default()),
            talker_priority: Some(1.into()),
            an_apdu: Some(opaque()),
            ..Default::default()
        });
        round_trip(&ForwardGroupCallSignallingArg {
            imsi: Some(IMSI.into()),
            uplink_request_ack: Some(()),
            uplink_release_command: Some(()),
            extension_container: Some(types::ExtensionContainer::default()),
            state_attributes: Some(opaque()),
            sm_rp_ui: Some(oct(&[0x01])),
            ..Default::default()
        });
        round_trip(&SendGroupCallInfoArg {
            cell_id: Some(oct(&[0x00, 0xF1, 0x10, 0x00, 0x01, 0x00, 0x02])),
            imsi: Some(IMSI.into()),
            cksn: Some(oct(&[0x01])),
            ..SendGroupCallInfoArg::new(0.into(), oct(&[0x01, 0x02, 0x03]), oct(&[0x11]))
        });
        round_trip(&SendGroupCallInfoRes {
            anchor_msc_address: Some(SC_ADDR.into()),
            imsi: Some(IMSI.into()),
            kc: Some(oct(&[0x33; 8])),
            ..Default::default()
        });
    }

    #[test]
    fn lcs_deferred_and_molr() {
        round_trip(&LcsPeriodicLocationCancellationArg {
            reference_number: oct(&[0x07]),
            h_gmlc_address: Some(oct(&[10, 0, 0, 5])),
        });
        round_trip(&LcsLocationUpdateArg {
            reference_number: oct(&[0x07]),
            add_location_estimate: Some(oct(&[0x11; 8])),
            velocity_estimate: Some(oct(&[0x22; 4])),
            sequence_number: Some(3.into()),
        });
        round_trip(&LcsLocationUpdateRes {
            termination_cause: Some(0.into()),
        });
        round_trip(&LcsPeriodicLocationRequestArg {
            reference_number: oct(&[0x07]),
            periodic_ldr_info: opaque(),
        });
        round_trip(&LcsPeriodicLocationRequestRes {
            mo_lr_short_circuit: Some(()),
        });
        round_trip(&LcsAreaEventRequestArg {
            reference_number: oct(&[0x07]),
            h_gmlc_address: Some(oct(&[10, 0, 0, 5])),
            deferred_location_event_type: Some(bits(&[true, false, true, false])),
            area_event_info: Some(opaque()),
        });
        round_trip(&LcsMolrArg {
            molr_type: Some(0.into()),
            location_method: Some(1.into()),
            mlc_number: Some(SC_ADDR.into()),
            supported_gad_shapes: Some(bits(&[true, false, true])),
            pseudonym_indicator: Some(()),
            ..Default::default()
        });
        round_trip(&LcsMolrRes {
            location_estimate: Some(oct(&[0x10; 8])),
            reference_number: Some(oct(&[0x07])),
            mo_lr_short_circuit: Some(()),
            ..Default::default()
        });
        round_trip(&LcsLocationNotificationArg {
            notification_type: Some(1.into()),
            location_type: Some(opaque()),
        });
        round_trip(&LcsLocationNotificationRes {
            verification_response: Some(1.into()),
            location_privacy_indication: Some(0.into()),
            valid_time_period: Some(opaque()),
        });
    }

    // ── Registry ──

    #[test]
    fn every_operation_code_has_a_name_and_every_name_is_distinct() {
        let mut codes = std::collections::HashSet::new();
        let mut names = std::collections::HashSet::new();
        for (code, name) in types::OPERATION_REGISTRY {
            assert_eq!(operation_name(*code), *name);
            assert_ne!(*name, "unknown");
            assert!(codes.insert(code), "duplicate operation code {code}");
            assert!(names.insert(name), "duplicate operation name {name}");
        }
    }

    #[test]
    fn operation_names_resolve() {
        for (code, name) in [
            (op_codes::SEND_ROUTING_INFO_FOR_SM, "sendRoutingInfoForSM"),
            (op_codes::MO_FORWARD_SM, "mo-forwardSM"),
            (op_codes::MT_FORWARD_SM, "mt-forwardSM"),
            (op_codes::READY_FOR_SM, "readyForSM"),
            (op_codes::ANY_TIME_MODIFICATION, "anyTimeModification"),
            (op_codes::PROVIDE_SUBSCRIBER_INFO, "provideSubscriberInfo"),
            (op_codes::ANY_TIME_INTERROGATION, "anyTimeInterrogation"),
            (op_codes::CHECK_IMEI, "checkIMEI"),
            (op_codes::SEND_IMSI, "sendIMSI"),
            (op_codes::UPDATE_GPRS_LOCATION, "updateGprsLocation"),
            (op_codes::PREPARE_HANDOVER, "prepareHandover"),
            (
                op_codes::PROVIDE_SUBSCRIBER_LOCATION,
                "provideSubscriberLocation",
            ),
        ] {
            assert_eq!(operation_name(code), name);
        }
        assert_eq!(operation_name(0xFF), "unknown");
    }

    #[test]
    fn integer_members_accept_the_full_range() {
        // The extensible ENUMERATEDs are carried as INTEGER so a value added in
        // a later release cannot make the whole operation undecodable.
        let arg = operations::subscriber_info::SubscriberInfo {
            last_rat_type: Some(Integer::from(99)),
            ..Default::default()
        };
        round_trip(&arg);
    }
}
