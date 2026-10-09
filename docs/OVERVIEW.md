# gsm_map — overview

The **Mobile Application Part** of SS7 (**3GPP TS 29.002**), expressed as
`rasn`-derived ASN.1 types that BER-encode and -decode. Pure and I/O-free — no
sockets, no async runtime — so it plugs into any network function and stays
unit-testable.

MAP only: there are no CAMEL/CAP (TS 29.078) types here.

## The idea

A MAP dialogue is a TCAP transaction carrying components (Invoke, ReturnResult,
ReturnError). Each component's *parameter* is a BER-encoded MAP operation
argument or result. This crate is exactly those parameters: one Rust type per
operation, deriving `rasn`'s `AsnType`/`Encode`/`Decode`, so:

```rust
let ber = gsm_map::encode(&arg)?;                    // build the Invoke parameter
let arg: MoForwardSmArg = gsm_map::decode(&ber)?;    // decode a peer's
```

Decode with `gsm_map::decode`, not with `rasn::ber::decode`: see "Decoding"
below.

The transaction machinery (TIDs, Begin/Continue/End) and the transports below
(SCCP, M3UA/MTP3, SCTP) live in their own crates; this one owns only the
application-layer vocabulary.

## Layout

- **`operations/`** — one module per operation group. Each `…Arg` / `…Res` is a
  standalone BER-codable type. SMS, mobility, authentication, subscriber
  data/info, call handling, supplementary services, USSD, fault recovery,
  handover, IMEI, LCS, OAM and GPRS location.
- **`types`** — the shared address types (`Imsi`, `IsdnAddressString`,
  `AddressString`, `Lmsi`, `DiameterIdentity`), the SM-RP addressing choices
  (`SmRpDa` / `SmRpOa`), `LocationInfoWithLmsi` with its `AdditionalNumber` and
  `NetworkNodeDiameterAddress`, the opaque `ExtensionContainer`, and the
  `op_codes` registry with `operation_name()`.
- **`operations::errors`** — MAP error codes and `error_name()`.
- **`application_context`** — every MAP application-context OID TS 29.002
  defines, with the versions each one is actually available in, used to
  negotiate the dialogue's ASN.1 module. Getting the arc or the version wrong
  makes a conformant peer abort before any operation is decoded, so these are
  checked against the dissector too.
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

A round-trip alone is not enough, though. A tag that is wrong in both directions
still round-trips cleanly, and so does a member emitted out of the order the
ASN.1 declares — a peer skips that one silently rather than rejecting the
message. `scripts/wireshark_check.sh` feeds one maximal instance of every
operation, as full MAP over TCAP over SCCP frames, to Wireshark's `gsm_map`
dissector and asserts that an independent decoder names back every member.

## Decoding

`gsm_map::decode` is the crate's own BER decoder (`src/strict.rs`). It
implements `rasn`'s `Decoder` trait, so the derived types drive it like any
other, and it differs from `rasn::ber::decode` in the two places where that one
is unsafe on signalling.

It does not lose data. `rasn` 0.28 reports an OPTIONAL member behind an EXPLICIT
tag as absent when its content cannot be read, returns a SEQUENCE OF without a
last element it cannot read, and ignores octets after the value. All three are
errors here, as are a member that is repeated or out of order and an unknown
CHOICE alternative.

It does not refuse a newer peer. TS 29.002 17.1.4: "An entity supporting a
version greater than 1 shall not reject an unsupported extension following
"..." of that SEQUENCE or ENUMERATED data type." Elements after the last member
the crate models, in a SEQUENCE with an extension marker, are skipped, and
`gsm_map::decode_with_extensions` returns them. `CorrelationID` and
`NetworkNodeDiameterAddress` have no marker and accept nothing extra. An
extensible ENUMERATED keeps a value it has no name for; the specification says
per type what a receiver does with it.

## Modelling members we do not use

The operations a short message, location or authentication exchange depends on
model every member TS 29.002 (Rel-18) defines, even ones with no use here.
Members the crate does not interpret are carried as `types::Opaque`, always
constructed on the wire, and survive the round trip.

Two consequences worth knowing. BER encodes members in **declaration order**, so
where TS 29.002 declares a later tag first — `RequestedInfo` puts `[6]` before
`[5]`, `InsertSubscriberDataArg` interleaves fifteen members — the types follow
the spec's order, not ascending tag order. And ASN.1 forbids an implicit tag on
a CHOICE, so `[n] SomeChoice` is an **explicit** tag even inside an
`IMPLICIT TAGS` module; get that wrong and the member vanishes from a peer's
dissection without any error.

## Data hygiene

Every address, IMSI, and payload in the tests and docs is **synthetic**:
fictional `+1 555 01xx` numbers and the reserved test PLMN `001/01`. No captured
traffic, real subscriber identities, or operator addresses appear anywhere in
this repository.
