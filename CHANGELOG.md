# Changelog

All notable changes are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). See
[VERSIONING.md](VERSIONING.md) for the policy.

## [2.0.0]

Every operation the crate models was re-derived from TS 29.002 and checked, member
by member, against Wireshark's `gsm_map` dissector — which carries the compiled
ASN.1 and does not share our bugs. That found a lot: wrong tags, wrong member
order, members modelled as the wrong ASN.1 type, and types that could not decode
what a real peer sends. Most of the fixes change the BER an existing operation
produces, which [VERSIONING.md](VERSIONING.md) counts as breaking even where the
Rust surface is untouched, so this is a major bump. The 1.x encodings listed
under **Fixed** were not conformant; a peer was entitled to reject them, and in
several cases silently did.

### Added
- **Every MAP operation TS 29.002 defines is now in the operation registry** —
  97 codes, each name checked against the dissector — and the ~40 that had no
  types at all now have argument and result types: `noteSubscriberDataModified`,
  `ss-InvocationNotification`, `noteMM-Event` (new `operations::notification`),
  the VGCS/VBS set (new `operations::group_call`), `authenticationFailureReport`,
  `mt-ForwardSM-VGCS`, `alertServiceCentreWithoutResult`, `updateVcsgLocation` /
  `cancelVcsgLocation`, `resumeCallHandling`, `releaseResources`,
  `setReportingState`, `statusReport`, `remoteUserFree`, `ist-Alert` /
  `ist-Command`, `notifySS`, `registerCC-Entry` / `eraseCC-Entry` /
  `accessRegisterCCEntry`, `callDeflection`, `userUserService`,
  `anyTimeSubscriptionInterrogation`, and the eight deferred/MO-LR LCS
  operations. The v1-only operations (`performHandover`, `registerPassword`,
  `getPassword`, `noteSubscriberPresent`, …) get a code and a name but no type:
  their ASN.1 is gone from the current spec.
- **`dialogue` is now a thin layer over `tcap::DialoguePortion`** rather than a
  hand-rolled BER encoder that only built AARQ and AARE and could not read one
  back. `begin`, `end_accept`, `end_reject`, `abort` and `parse` cover all three
  PDUs in both directions, and `application_context` pulls the negotiated
  context straight out of a portion a peer sent.
- **Python**: the SMS operation set is complete — `ReadyForSmArg`,
  `AlertServiceCentreArg`, `InformServiceCentreArg` (with `mw_status` as named
  booleans rather than a packed byte) — plus `error_name()` and the whole
  `OPERATIONS` / `ERRORS` name-to-code registries, built from the same tables
  the Rust lookups use.
- `subscriber_data::OdbData` and `lcs::LcsClientId` are modelled rather than
  opaque: operator-determined barring decides whether a subscriber may originate
  an SMS at all, and the LCS client identity is what a privacy check turns on.
- **The application-context, operation-code and error-code registries are
  generated from one table each**, so a constant cannot exist without a name,
  and every entry in all three is checked against the dissector in CI (52
  operations, 44 application contexts, 60 error codes). `types::OPERATION_REGISTRY`
  and `errors::ERROR_REGISTRY` expose the tables.
- `application_context` now covers **every** context TS 29.002 defines, each
  documented with the versions it actually exists in — most are v3-only, and
  several (`networkFunctionalSsContext`, `networkUnstructuredSsContext`,
  `shortMsgAlertContext`, `imsiRetrievalContext`) have no v3 at all. New ones
  include `mwdMngtContext` (readyForSM), `subscriberInfoEnquiryContext`,
  `anyTimeInfoEnquiryContext`, `equipmentMngtContext`, `tracingContext`, the
  four GPRS contexts and the two LCS contexts.
- **MAP error parameters.** An error's parameter is what a gateway acts on —
  `absentSubscriberSM` carries the absent reason and a suggested retransmission
  time, `sm-DeliveryFailure` carries the enumerated cause and the
  SMS-DELIVER-REPORT TPDU, `callBarred` says whether the originator was
  unauthorised. 1.x modelled only the code. Thirteen parameter types are now
  modelled and dissector-checked, including
  `ExtensionContainerOnlyParam` for the several errors (`atm-NotAllowed` among
  them) whose parameter is just an extension container.
- `types::OpenEnumerated` — an extensible `ENUMERATED` carried as an integer. At
  an untagged position this is not cosmetic: `ENUMERATED` is universal tag
  `0x0A` and `INTEGER` is `0x02`, so a plain integer there produces bytes the
  peer walks past.
- 16 MAP error codes the crate never named, including **`atm-NotAllowed` (61)**
  and `informationNotAvailable` (62) — what an HLR returns when it refuses an
  IP-SM-GW registration — plus `subscriberBusyForMT-SMS` (31),
  `illegalSS-Operation` (16) and `forwardingFailed` (47).
- **anyTimeModification can now carry the IP-SM-GW registration.** New
  `ModificationRequestForIpSmGwData` and `ModificationInstruction` types, and the
  `[8]` member on `AnyTimeModificationArg`. This is the MAP mechanism by which a
  node registers itself as the MT-SMS routing node for a subscriber: `Activate`
  on registration, `Deactivate` on de-registration, after which the HLR hands
  that node out in `RoutingInfoForSM-Res` instead of the serving MSC
  (TS 23.204). The registering node's own address travels in `gsmSCF-Address`,
  because an IP-SM-GW acts in the gsmSCF role towards the HLR for this dialogue.
- `application_context::any_time_info_handling_context` (arc 43), the context
  anyTimeModification and anyTimeInterrogation run under.
- `types::op_codes` grew the GPRS-location, handover, IMEI, OAM, LCS and
  any-time operation codes, and `operation_name()` resolves all of them instead
  of returning `"unknown"`. Each `operations::*::op_codes` module now re-exports
  from that one registry rather than repeating the numbers.
- Shared `types`: `NetworkNodeDiameterAddress`, `DiameterIdentity`,
  `ExtensionContainer`, `AdditionalNumber`, `CorrelationId`, `MwStatus` +
  `MwStatusFlags`, `Time`, `SignalInfo`, `AbsentSubscriberDiagnosticSm`, and
  `Opaque` for elements the crate carries without interpreting.
- `new()` constructors taking only the mandatory members, on every type that
  grew a long optional tail, so the optional ones can be filled in with
  functional-record-update rather than a wall of `None`.
- Python: `AnyTimeModificationArg`, `SubscriberIdentity`, `AdditionalNumber`,
  `NetworkNodeDiameterAddress`, `OP_ANY_TIME_MODIFICATION`, and
  `MODIFY_ACTIVATE` / `MODIFY_DEACTIVATE`.
- [`scripts/wireshark_check.sh`](scripts/wireshark_check.sh) +
  [`examples/wireshark_vectors.rs`](examples/wireshark_vectors.rs): emit one
  maximal instance of **every** operation as MAP over TCAP over SCCP and assert
  the dissector names back every member of every frame. Wired into CI.

### Fixed
- **`operation_name()` mis-spelled two operations.** TS 29.002 (and every
  dissector) says `mo-forwardSM` and `mt-forwardSM`; the crate said
  `mo-ForwardSM` / `mt-ForwardSM`. Anything matching on those strings needs
  updating.
- **Two application-context arcs were wrong.** `infoRetrievalContext` (used by
  sendAuthenticationInfo) was arc 5, which is `locationInfoRetrievalContext`;
  it is arc **14**. `authenticationFailureReportContext` was arc 27, which is
  `msPurgingContext`; it is arc **39**. A dialogue opened on either would have
  been aborted by the peer, or worse, accepted as the wrong operation set.
  `short_msg_relay_context` was a duplicate of the MO-relay context documented
  under the name of arc 41, and is gone; use `short_msg_mo_relay_context` or
  `short_msg_mt_relay_vgcs_context`.
- **`error_name()` answered `"unknown"` for error codes the crate defined
  itself.** `ss-Incompatibility` (20) collided with a bogus `INITIATING_RELEASE`
  constant that is not a MAP error at all, and neither had a name arm;
  `targetCellOutsideGroupCallArea` (42) had a constant and no name. Both
  registries are now table-generated, which makes that impossible.
- **Every type now models every member TS 29.002 defines.** BER decoding is not
  tolerant of unmodelled members: `rasn` fails the *whole* operation with
  `UnexpectedExtraData` rather than skipping a tag it does not know. So a
  `RoutingInfoForSM-Res` carrying `[4] extensionContainer` or a serving-node
  Diameter address, an `MT-ForwardSM-Arg` carrying `smsOverIP-OnlyIndicator`, or
  an `InsertSubscriberData-Arg` carrying anything past `[14]` — all of which a
  Rel-18 peer sends — used to fail outright. Members the crate does not
  interpret are carried opaquely and survive the round trip.
- **CHOICE members were implicitly tagged.** ASN.1 forbids an implicit tag on a
  CHOICE, so `[0] SubscriberIdentity` on `AnyTimeModificationArg` and
  `AnyTimeInterrogationArg`, `targetMS` on both sendRoutingInfoForLCS types,
  `[6] Additional-Number` on `LocationInfoWithLmsi`, `subscriberState` and the
  PS/EPS states on `SubscriberInfo`, `cellGlobalIdOrServiceAreaIdOrLAI` on
  `LocationInformation`, and several others all need an explicit tag. With the
  implicit form the alternative's own tag was overwritten and Wireshark dropped
  the member **silently** — an anyTimeModification arrived at the HLR with no
  subscriber identity at all.
- **`ReadyForSmArg.imsi` was missing its context tag.** It encoded with the
  universal OCTET STRING tag `0x04` where TS 29.002's `IMPLICIT TAGS` requires
  context `[0]`, so a conformant HLR rejected every readyForSM this crate
  produced. readyForSM is the MAP form of Alert-SC, so a store-and-forward
  gateway's queue drain depended on it.
- **Members were emitted in ascending tag order where the ASN.1 declares them
  otherwise.** BER encodes in declaration order, and a member that arrives out
  of order is skipped rather than rejected. `RequestedInfo` (`[6]` before `[5]`,
  `[11]` between `[7]` and `[8]`), `RegisterSsArg` (`[6]` before `[5]`),
  `UpdateGprsLocationArg` (`[22]` before `[19]`), `DeleteSubscriberDataArg`
  (`[22]`/`[23]` before `[21]`), `RoutingInfoForSmArg` (`[14]` before `[13]`)
  and `InsertSubscriberDataArg` (fifteen members out of ascending order) are all
  now in the order TS 29.002 declares.
- **Members were modelled as the wrong ASN.1 type.** `InformServiceCentreArg`'s
  `mw-Status` is an untagged BIT STRING numbered from the most significant bit,
  not a `[0]`-tagged packed byte — the 1.x encoding put the flags in a different
  member entirely. `SubscriberState` is a CHOICE, not an ENUMERATED.
  `SendingNode-Number`'s `hlr-Number` alternative is untagged (and the second
  alternative is `css-Number [1]`, not `ms-Number`). `LocationInformation`'s tags
  were off by one from `geographicalInformation` onwards, and
  `ageOfLocationInformation` is untagged. `SubscriberInfo`'s `imei`,
  `ms-Classmark2` and `gprs-MS-Class` were one tag low. `SendAuthenticationInfoArg`
  had `re-synchronisationInfo` and `requestingNodeType` at `[1]`/`[2]`, which are
  `immediateResponsePreferred` and `extensionContainer`.
- **Operation arguments that carry a `[3]` wrapper.** `CancelLocationArg`,
  `PurgeMsArg`, `SendAuthenticationInfoRes`, `SendRoutingInfoRes`,
  `PrepareSubsequentHandoverArg` and `PrepareSubsequentHandoverRes` are
  `[3] SEQUENCE` in TS 29.002; the crate emitted a bare universal SEQUENCE,
  which is the v1/v2 form and decodes as a different type.
- **`ExternalSignalInfo.protocolId`** (and `AccessNetworkSignalInfo`'s protocol
  id) were `INTEGER` where the ASN.1 says untagged `ENUMERATED` — tag `0x02`
  instead of `0x0A`, so every handover message carried an unreadable protocol
  id. `AccessNetworkSignalInfo` is also now a real type rather than an opaque
  blob, because it sits at an untagged optional position where an opaque value
  swallows the member after it.
- **Untagged optional CHOICE members are split into their alternatives.**
  `authenticationSetList` on the sendAuthenticationInfo and sendIdentification
  results, and `basicService` on the supplementary-service arguments, have no tag
  of their own, so `rasn` had nothing to test before committing and an absent
  one swallowed the next member. Each alternative is now its own field carrying
  its own tag — identical on the wire, since only one may be present — with
  `SendAuthenticationInfoRes::authentication_set_list()` reassembling the ASN.1
  view.

### Changed
- `dialogue::build_begin_dialogue` / `build_end_dialogue` are gone; they returned
  raw EXTERNAL bytes a caller had to wrap by hand. Use `dialogue::begin` /
  `dialogue::end_accept`, which return a `tcap::DialoguePortion` directly.
- `LocationInfoWithLmsi.additional_number` is an `AdditionalNumber` CHOICE, not
  an `IsdnAddressString` (same in the Python binding).
- The 1.0.0 entry below lists CAMEL/CAP (TS 29.078) operations. Those types are
  not in the crate and have not been since the standalone-build cleanup; the
  entry was wrong when it was written. This crate is MAP only. Correcting it
  here rather than rewriting a released changelog.
- `SubscriberLocationInfo` is renamed `LocationInformation`, after the ASN.1.
- Nearly every operation type gained public fields, so struct-literal
  construction needs updating. The `new()` constructors above are the short path.

## [1.1.0]

### Added
- `address` module: build the TBCD address / identity OCTET STRINGs from a digit
  string (`isdn_address_string`, `international_e164`, `imsi`) instead of
  hand-packing semi-octets. TBCD packing reuses `sccp::bcd`. Exposed to Python as
  `gsm_map.international_e164` / `.isdn_address_string` / `.imsi`, with the
  `NATURE_*` / `PLAN_*` nature-of-address and numbering-plan values.

### Changed
- `sccp` moves from a dev-dependency (bench only) to a runtime dependency; it is
  a lean sibling (only `thiserror`).

## [1.0.0]

First release — GSM MAP and CAMEL/CAP operations as BER-codable ASN.1 types.

### Added
- **SMS** operations: `sendRoutingInfoForSM`, `mo-forwardSM`, `mt-forwardSM`,
  `reportSM-DeliveryStatus`, `alertServiceCentre`, `informServiceCentre`,
  `readyForSM`.
- **Mobility**: `updateLocation`, `cancelLocation`, `purgeMS`,
  `sendIdentification`, `updateGprsLocation`, `sendRoutingInfoForGprs`, and the
  related GPRS/fault-recovery operations (`reset`, `restoreData`).
- **Authentication**: `sendAuthenticationInfo` with GSM triplets and UMTS
  quintuplets.
- **Subscriber data / info**: `insertSubscriberData`, `deleteSubscriberData`,
  `provideSubscriberInfo`, `anyTimeInterrogation`, `anyTimeModification`.
- **Call handling**: `sendRoutingInfo`, `provideRoamingNumber`.
- **Supplementary services**: `registerSS`, `eraseSS`, `activateSS`,
  `deactivateSS`, `interrogateSS`.
- **USSD**: `processUnstructuredSS-Request`, `unstructuredSS-Request`,
  `unstructuredSS-Notify`.
- **Handover / IMEI / LCS / OAM** operation types.
- **CAMEL / CAP** (TS 29.078): `initialDP`, `connect`, `releaseCall`,
  `requestReportBCSMEvent`, `eventReportBCSM`, `applyCharging`,
  `applyChargingReport`, `furnishChargingInformation`, `cancel`,
  `playAnnouncement`, `connectToResource`, and the SMS CAP set.
- **`op_codes`** + `operation_name()`, **`operations::errors`** +
  `error_name()`, **`application_context`** (MAP v1/v2/v3 and CAP phase OIDs),
  and **`dialogue`** (TCAP dialogue-portion builders).
- **`types`**: `Imsi`, `IsdnAddressString`, `AddressString`, `Lmsi`, `SmRpDa`,
  `SmRpOa`, `LocationInfoWithLmsi`; **`MapError`** wrapping `tcap::TcapError`.
- Test suite: in-crate round-trip tests plus a self-contained
  [`tests/vectors.rs`](tests/vectors.rs) exercising the public API with purely
  synthetic data.

[1.0.0]: https://github.com/Real-Time-Telecom-B-V/gsm_map/releases/tag/v1.0.0
