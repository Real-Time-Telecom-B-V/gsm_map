# gsm_map — overview

The **Mobile Application Part** of SS7 (**3GPP TS 29.002**) and the **CAMEL
Application Part** (CAP, **TS 29.078**), expressed as `rasn`-derived ASN.1 types
that BER-encode and -decode. Pure and I/O-free — no sockets, no async runtime —
so it plugs into any network function and stays unit-testable.

## The idea

A MAP dialogue is a TCAP transaction carrying components (Invoke, ReturnResult,
ReturnError). Each component's *parameter* is a BER-encoded MAP operation
argument or result. This crate is exactly those parameters: one Rust type per
operation, deriving `rasn`'s `AsnType`/`Encode`/`Decode`, so:

```rust
let ber = rasn::ber::encode(&arg)?;          // build the Invoke parameter
let arg: MoForwardSmArg = rasn::ber::decode(&ber)?;  // decode a peer's
```

The transaction machinery (TIDs, Begin/Continue/End) and the transports below
(SCCP, M3UA/MTP3, SCTP) live in their own crates; this one owns only the
application-layer vocabulary.

## Layout

- **`operations/`** — one module per operation group. Each `…Arg` / `…Res` is a
  standalone BER-codable type. SMS, mobility, authentication, subscriber
  data/info, call handling, supplementary services, USSD, fault recovery,
  handover, IMEI, LCS, OAM, GPRS location, and CAMEL/CAP.
- **`types`** — the shared address types (`Imsi`, `IsdnAddressString`,
  `AddressString`, `Lmsi`), the SM-RP addressing choices (`SmRpDa` / `SmRpOa`),
  `LocationInfoWithLmsi`, and the `op_codes` registry with `operation_name()`.
- **`operations::errors`** — MAP error codes and `error_name()`.
- **`application_context`** — MAP and CAP application-context OIDs (versions
  v1/v2/v3 and CAP phases 1–4) used to negotiate the dialogue's ASN.1 module.
- **`dialogue`** — assembles the TCAP dialogue portion (AARQ on Begin, AARE on
  End) so a decoder knows which application context — and therefore which ASN.1
  definitions — a message belongs to.
- **`MapError`** — the crate error type; wraps `tcap::TcapError`.

## Addressing (TBCD)

MAP numbers (`IsdnAddressString`, `AddressString`) are an OCTET STRING: byte 0
holds the type-of-number and numbering-plan indicator; the remaining bytes hold
BCD digits with the nibbles **swapped**, an odd count padded with `0xF`. IMSIs
are the same swapped-nibble BCD without the leading TON/NPI byte.

## Why it's separate + pure

Keeping MAP/CAP as plain codable types — with no transaction state and no
transport — means an SMSC, HLR, VLR, MSC, STP, or gsmSCF can compose it with
whatever TCAP and SS7 stack it already runs, and every operation is testable by
a single BER round-trip. See [`tests/vectors.rs`](../tests/vectors.rs) and the
in-crate `#[cfg(test)]` suite in `src/lib.rs`.

## Data hygiene

Every address, IMSI, and payload in the tests and docs is **synthetic**:
fictional `+1 555 01xx` numbers and the reserved test PLMN `001/01`. No captured
traffic, real subscriber identities, or operator addresses appear anywhere in
this repository.
