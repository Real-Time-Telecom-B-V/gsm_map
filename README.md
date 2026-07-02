# gsm_map

[![crates.io](https://img.shields.io/crates/v/gsm_map.svg)](https://crates.io/crates/gsm_map)
[![docs.rs](https://docs.rs/gsm_map/badge.svg)](https://docs.rs/gsm_map)
[![CI](https://github.com/Real-Time-Telecom-B-V/gsm_map/actions/workflows/ci.yml/badge.svg)](https://github.com/Real-Time-Telecom-B-V/gsm_map/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**GSM MAP** — the Mobile Application Part of the SS7 protocol suite
(**3GPP TS 29.002**), plus the **CAMEL Application Part** (CAP, **TS 29.078**),
as a set of `rasn`-derived ASN.1 types you can **BER-encode and -decode**.

Each MAP/CAP operation is an ordinary Rust struct or enum that round-trips
through `rasn::ber`; the TCAP layer above and the SCCP/M3UA/MTP3 transports below
are somebody else's job. Pure and I/O-free: no sockets, no async runtime — so it
drops into an SMSC, HLR, VLR, MSC, STP, or gsmSCF and stays unit-testable.

```rust
use gsm_map::operations::sri_sm::RoutingInfoForSmArg;
use gsm_map::types::*;

// SMS-SC asks the HLR to route a message to a subscriber (sendRoutingInfoForSM).
// Addresses are TBCD in an OCTET STRING: byte 0 is TON/NPI, the rest are the
// swapped-nibble digits. This one is the fictional +1 555 0100 999.
let arg = RoutingInfoForSmArg {
    msisdn: vec![0x91, 0x51, 0x55, 0x10, 0x00, 0x99, 0xF9].into(),
    sm_rp_pri: true,
    service_centre_address: vec![0x91, 0x51, 0x55, 0x10, 0x99].into(),
    gprs_support_indicator: None,
    sm_rp_mti: None,
    sm_rp_smea: None,
};

// Encode to BER for the TCAP Invoke parameter …
let ber = rasn::ber::encode(&arg).unwrap();
// … and the peer decodes it straight back into the typed struct.
let decoded: RoutingInfoForSmArg = rasn::ber::decode(&ber).unwrap();
assert_eq!(decoded, arg);
```

## What's covered

Every operation below is a BER-codable argument/result type (see
[`src/operations/`](src/operations/)):

| Group | Operations |
|---|---|
| **SMS** | `sendRoutingInfoForSM`, `mo-ForwardSM`, `mt-ForwardSM`, `reportSM-DeliveryStatus`, `alertServiceCentre`, `informServiceCentre`, `readyForSM` |
| **Mobility** | `updateLocation`, `cancelLocation`, `purgeMS`, `sendIdentification`, `updateGprsLocation`, `sendRoutingInfoForGprs` |
| **Authentication** | `sendAuthenticationInfo` (GSM triplets + UMTS quintuplets) |
| **Subscriber data** | `insertSubscriberData`, `deleteSubscriberData` |
| **Subscriber info** | `provideSubscriberInfo`, `anyTimeInterrogation`, `anyTimeModification` |
| **Call handling** | `sendRoutingInfo`, `provideRoamingNumber` |
| **Supplementary services** | `registerSS`, `eraseSS`, `activateSS`, `deactivateSS`, `interrogateSS` |
| **USSD** | `processUnstructuredSS-Request`, `unstructuredSS-Request`, `unstructuredSS-Notify` |
| **Fault recovery** | `reset`, `restoreData` |
| **Handover / IMEI / LCS / OAM** | `prepareHandover`, `checkIMEI`, `provideSubscriberLocation`, `activateTraceMode`, … |
| **CAMEL / CAP** | `initialDP`, `connect`, `releaseCall`, `requestReportBCSMEvent`, `applyCharging`, plus the SMS CAP set |

Plus the connective tissue a stack needs:

- **`op_codes`** and `operation_name()` — the MAP operation-code registry.
- **`operations::errors`** — MAP error codes and `error_name()`.
- **`application_context`** — the MAP/CAP application-context OIDs (v1/v2/v3,
  CAP phases) for TCAP dialogue negotiation.
- **`dialogue`** — builds the TCAP dialogue portion (AARQ/AARE) that carries the
  application context, so a decoder can pick the right ASN.1 module.
- **`MapError`** — the crate error type (wraps `tcap::TcapError`).

## Where it fits

```
   TCAP dialogue + components        (the `tcap` crate)
              ▲
   MAP / CAP operation types         (this crate; pure, I/O-free)
              ▼
   SCCP ▸ M3UA / MTP3 ▸ SCTP         (transport; separate crates)
```

More: [`docs/OVERVIEW.md`](docs/OVERVIEW.md).

## Development

```bash
cargo test
cargo clippy --all-targets -- -D warnings
cargo deny check
```

## License

MIT — see [LICENSE](LICENSE).
