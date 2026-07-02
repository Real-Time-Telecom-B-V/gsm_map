# gsm_map

[![crates.io](https://img.shields.io/crates/v/gsm_map.svg)](https://crates.io/crates/gsm_map)
[![docs.rs](https://docs.rs/gsm_map/badge.svg)](https://docs.rs/gsm_map)
[![CI](https://github.com/Real-Time-Telecom-B-V/gsm_map/actions/workflows/ci.yml/badge.svg)](https://github.com/Real-Time-Telecom-B-V/gsm_map/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**GSM MAP** — the Mobile Application Part of the SS7 protocol suite
(**3GPP TS 29.002**) — as a set of `rasn`-derived ASN.1 types you can
**BER-encode and -decode**, from Rust **or** Python.

Each MAP operation is an ordinary Rust struct or enum that round-trips through
`rasn::ber`; the TCAP layer above and the SCCP/M3UA/MTP3 transports below are
somebody else's job. Pure and I/O-free: no sockets, no async runtime — so it
drops into an SMSC, HLR, VLR, MSC, STP, or gsmSCF and stays unit-testable.

The same codec ships **two ways from one source tree, one version**: the Rust
crate (`cargo add gsm_map`, pyo3-free) and a Rust-backed Python wheel
(`pip install gsm_map`) exposing the SMS operation set.

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

Plus the connective tissue a stack needs:

- **`op_codes`** and `operation_name()` — the MAP operation-code registry.
- **`operations::errors`** — MAP error codes and `error_name()`.
- **`application_context`** — the MAP application-context OIDs (v1/v2/v3) for
  TCAP dialogue negotiation.
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

## Python

`pip install gsm_map` gives a Rust-backed wheel exposing the SMS operation set.
Each operation has `.encode() -> bytes` (the BER Invoke parameter) and a
`.decode(bytes)` classmethod; addresses/identities cross the boundary as `bytes`
(TBCD in an OCTET STRING). All examples use synthetic `+1 555 01xx` numbers and
the reserved test PLMN `001/01`.

```python
import gsm_map

# SMS-GMSC asks the HLR to route a message (sendRoutingInfoForSM, op 45).
arg = gsm_map.RoutingInfoForSmArg(
    msisdn=bytes([0x91, 0x51, 0x55, 0x10, 0x00, 0x99, 0xF9]),  # +1 555 0100 999
    service_centre_address=bytes([0x91, 0x51, 0x55, 0x10, 0x00]),
    sm_rp_pri=True,
)
ber = arg.encode()                                   # → the TCAP Invoke parameter
again = gsm_map.RoutingInfoForSmArg.decode(ber)
assert again.encode() == ber

# mo-ForwardSM (op 46): the SM-RP-DA / -OA are CHOICEs.
mo = gsm_map.MoForwardSmArg(
    gsm_map.SmRpDa.service_centre(bytes([0x91, 0x51, 0x55, 0x10, 0x00])),
    gsm_map.SmRpOa.msisdn(bytes([0x91, 0x51, 0x55, 0x10, 0x00, 0x99, 0xF9])),
    sm_rp_ui=b"...SMS-SUBMIT TPDU...",
)
```

The wheel is built for regular CPython 3.9+ (abi3) and, version-specific, for
free-threaded (`3.13t`/`3.14t`) CPython — the module is `gil_used = false`, so it
loads without re-enabling the GIL.

## Performance

`cargo bench` runs two suites (criterion):

- **`codec`** — BER encode/decode of the core SMS ops. Indicative
  (x86-64, release): SRI-SM arg ~99 ns encode / ~72 ns decode; MO-ForwardSM
  ~147 ns / ~120 ns.
- **`integration`** — the **full SS7 stack**, end to end: it assembles a real
  connectionless message — MAP op arg → TCAP `Invoke` in a `Begin` → SCCP `UDT`
  with GT/SSN addresses → wire bytes — and measures **both** directions at volume
  (encode `MAP → TCAP → SCCP`, decode `SCCP → TCAP → MAP`), reporting
  **messages/sec**. Indicative: SRI-SM ~1.7 M msg/s encode, ~2.9 M msg/s decode;
  MO-ForwardSM ~1.4 M msg/s encode, ~2.8 M msg/s decode.

```text
   MAP operation arg        (gsm_map — BER-encode the typed struct)
            │
   TCAP Invoke in a Begin   (tcap)
            │
   SCCP UnitData (UDT)      (sccp — GT/SSN addresses, TCAP as user data)
            ▼
         wire bytes
```

`scripts/mem_leak_test.sh` runs `examples/leak_check.rs`: a counting global
allocator asserts live bytes stay flat across codec **and** full-stack churn.

## Development

```bash
# Rust
cargo test                                      # pyo3-free
cargo test --features python                    # + PyO3 bindings
cargo clippy --all-targets -- -D warnings
cargo clippy --features python --lib -- -D warnings
cargo bench --no-run                            # incl. the integration bench
cargo run --release --example leak_check        # prints PASS
cargo deny check

# Python wheel
python -m venv .venv && . .venv/bin/activate
pip install maturin pytest
maturin develop
pytest python/tests -q
```

## License

MIT — see [LICENSE](LICENSE).
