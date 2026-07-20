# Changelog

All notable changes are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). See
[VERSIONING.md](VERSIONING.md) for the policy.

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
- **SMS** operations: `sendRoutingInfoForSM`, `mo-ForwardSM`, `mt-ForwardSM`,
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
