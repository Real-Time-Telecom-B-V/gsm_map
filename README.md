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

// SMS-SC asks the HLR to route a message to a subscriber (sendRoutingInfoForSM).
// Addresses are TBCD in an OCTET STRING: byte 0 is TON/NPI, the rest are the
// swapped-nibble digits. This one is the fictional +1 555 0100 999.
// `new` takes the mandatory members; fill an optional one in with
// `RoutingInfoForSmArg { sm_rp_mti: Some(0.into()), ..RoutingInfoForSmArg::new(..) }`.
let arg = RoutingInfoForSmArg::new(
    vec![0x91, 0x51, 0x55, 0x10, 0x00, 0x99, 0xF9].into(),
    true,                                       // sm-RP-PRI
    vec![0x91, 0x51, 0x55, 0x10, 0x99].into(),  // service centre
);

// Encode to BER for the TCAP Invoke parameter …
let ber = rasn::ber::encode(&arg).unwrap();
// … and the peer decodes it straight back into the typed struct.
let decoded: RoutingInfoForSmArg = rasn::ber::decode(&ber).unwrap();
assert_eq!(decoded, arg);
```

Every type models **every** member TS 29.002 defines, including ones the crate
does not interpret. That is not tidiness: BER decoding is not tolerant of
unmodelled members, so a `RoutingInfoForSM-Res` carrying an `extensionContainer`
or a serving-node Diameter address would otherwise fail to decode outright,
rather than come back with that one member empty. Members the crate does not
interpret are carried opaquely and survive the round trip.

## What's covered

Every operation below is a BER-codable argument/result type (see
[`src/operations/`](src/operations/)):

| Group | Operations |
|---|---|
| **SMS** | `sendRoutingInfoForSM`, `mo-forwardSM`, `mt-forwardSM`, `reportSM-DeliveryStatus`, `alertServiceCentre`, `informServiceCentre`, `readyForSM` |
| **Mobility** | `updateLocation`, `cancelLocation`, `purgeMS`, `sendIdentification`, `updateGprsLocation`, `sendRoutingInfoForGprs` |
| **Authentication** | `sendAuthenticationInfo` (GSM triplets + UMTS quintuplets) |
| **Subscriber data** | `insertSubscriberData`, `deleteSubscriberData` |
| **Subscriber info** | `provideSubscriberInfo`, `anyTimeInterrogation`, `anyTimeModification` (incl. the IP-SM-GW registration) |
| **Call handling** | `sendRoutingInfo`, `provideRoamingNumber` |
| **Supplementary services** | `registerSS`, `eraseSS`, `activateSS`, `deactivateSS`, `interrogateSS` |
| **USSD** | `processUnstructuredSS-Request`, `unstructuredSS-Request`, `unstructuredSS-Notify` |
| **Fault recovery** | `reset`, `restoreData` |
| **Handover / IMEI / OAM** | `prepareHandover`, `sendEndSignal`, `prepareSubsequentHandover`, `checkIMEI`, `activateTraceMode`, `sendIMSI`, … |
| **Location services (LCS)** | `provideSubscriberLocation`, `sendRoutingInfoForLCS`, `subscriberLocationReport`, `lcs-MOLR`, the deferred-location set |
| **Group call (VGCS/VBS)** | `prepareGroupCall`, `sendGroupCallEndSignal`, `processGroupCallSignalling`, `forwardGroupCallSignalling`, `sendGroupCallInfo` |
| **Notifications** | `noteSubscriberDataModified`, `ss-InvocationNotification`, `noteMM-Event` |

Every MAP operation code TS 29.002 defines resolves through `operation_name()`;
the handful that exist only in v1 (`performHandover`, `registerPassword`, …) have
a code and a name but no argument type, because their ASN.1 is gone from the
current spec.

Plus the connective tissue a stack needs:

- **`op_codes`** / `operation_name()` and **`operations::errors`** — the
  operation-code and error-code registries. Both are generated from one table
  per registry, so a code cannot exist without a name, and both are checked
  against the dissector.
- **`application_context`** — every MAP application-context OID TS 29.002
  defines, each documented with the versions it actually exists in.
- **`dialogue`** — the TCAP dialogue portion (AARQ / AARE / ABRT) that carries
  the application context, in both directions: build one, or read the context
  and outcome out of one a peer sent.
- **`MapError`** — the crate error type (wraps `tcap::TcapError`).

## Where it fits

```
   TCAP dialogue + components        (the `tcap` crate)
              ▲
   MAP operation types               (this crate; pure, I/O-free)
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

# anyTimeModification (op 65): register as the MT-SMS routing node for a
# subscriber. The HLR then hands `gsm_scf_address` out in RoutingInfoForSmRes
# instead of the serving MSC, so MT traffic for that subscriber arrives here
# (TS 23.204). MODIFY_DEACTIVATE undoes it.
atm = gsm_map.AnyTimeModificationArg(
    gsm_map.SubscriberIdentity.msisdn(gsm_map.international_e164("15550100999")),
    gsm_map.international_e164("15550142"),          # this node, in the gsmSCF role
    modify_registration_status=gsm_map.MODIFY_ACTIVATE,
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

## Checking the encoder against something that isn't us

A BER round-trip cannot catch a tag that is wrong in both directions, and a
member encoded out of the order the ASN.1 declares is skipped by a peer rather
than rejected — so a round-trip alone will happily bless an operation no HLR can
read. Wireshark carries the TS 29.002 ASN.1 compiled into its `gsm_map`
dissector and does not share our bugs.

`scripts/wireshark_check.sh` runs `examples/wireshark_vectors.rs`, which emits
one maximal instance of **every** operation as a full MAP → TCAP → SCCP frame,
pipes them through `text2pcap -l 142` (the SS7 SCCP link type) and asserts that
the dissector names back every member of every frame. It needs `tshark` and
`text2pcap`, so it runs in CI rather than under `cargo test`.

The dissector is only a valid reference if its compiled ASN.1 is at least as new
as the spec revision the vectors target, so the script requires **Wireshark
4.6+** and refuses to run on anything older. 4.2 spells two operations
differently, does not know the `resetContext-v3` context, and rejects the newer
members of `sendRoutingInfo`, `lcs-MOLR` and `lcs-LocationNotification` — gaps in
the reference, indistinguishable in the output from real encoder bugs.

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
./scripts/wireshark_check.sh                    # needs tshark 4.6+ + text2pcap

# Python wheel
python -m venv .venv && . .venv/bin/activate
pip install maturin pytest
maturin develop
pytest python/tests -q
```

## License

MIT — see [LICENSE](LICENSE).
