//! Helpers shared by the integration tests. All values are synthetic: IMSIs
//! are in the test network 001/01 and numbers are in a range no one is
//! assigned.
#![allow(dead_code)]

use std::fmt::Debug;

/// IMSI 001 01 0123456789 as TBCD: digits are packed two to an octet, the
/// first in the low nibble, and an odd count is padded with 0xF.
///
/// ```text
/// 0 0 | 1 0 | 1 0 | 1 2 | 3 4 | 5 6 | 7 8 | 9 F
///  00    01    01    21    43    65    87    f9
/// ```
pub const IMSI: &[u8] = &[0x00, 0x01, 0x01, 0x21, 0x43, 0x65, 0x87, 0xf9];

/// Bytes from a string of hex octets; spaces and line breaks are ignored.
pub fn vector(hex_octets: &str) -> Vec<u8> {
    let compact: String = hex_octets.split_whitespace().collect();
    hex::decode(compact).expect("test vector is not valid hex")
}

/// An ISDN-AddressString in international format, numbering plan E.164:
/// 0x91 followed by the digits as TBCD.
pub fn isdn(digits: &str) -> Vec<u8> {
    gsm_map::address::international_e164(digits).expect("valid digits")
}

/// `rasn` alone, without this crate's decoder.
pub fn lenient<T: rasn::Decode>(bytes: &[u8]) -> T {
    rasn::ber::decode(bytes).expect(
        "rasn refused these octets: it no longer has the leniency this test documents, \
         which is good news; adjust the first half of the test",
    )
}

/// Assert that [`gsm_map::decode`] refuses `bytes` and return the message.
pub fn refused<T: rasn::Decode + Debug>(bytes: &[u8]) -> String {
    match gsm_map::decode::<T>(bytes) {
        Ok(value) => panic!("decoded although it must be refused: {value:?}"),
        Err(error) => error.to_string(),
    }
}

/// Decode with [`gsm_map::decode_with_extensions`], require that nothing was
/// skipped, and cross-check the result with a method that shares no code with
/// the decoder: encode the value again and walk both encodings element by
/// element.
pub fn accepted<T: rasn::Decode + rasn::Encode + Debug>(bytes: &[u8]) -> T {
    let decoded = gsm_map::decode_with_extensions::<T>(bytes)
        .unwrap_or_else(|error| panic!("refused: {error}\n{}", hex::encode(bytes)));
    assert_eq!(
        decoded.unknown_extensions,
        [],
        "nothing in this vector is unknown to the crate"
    );
    let canonical = gsm_map::encode(&decoded.value).expect("encode");
    if let Err(lost) = nothing_dropped(bytes, &canonical) {
        panic!("decoded with data missing: {lost}\n{:?}", decoded.value);
    }
    decoded.value
}

/// Encode `value` and require exactly `expected`, then decode `expected` and
/// require `value` back. `expected` is written by hand from the ASN.1, so the
/// first half checks the encoder against the specification and the second
/// half decodes octets this crate did not produce.
pub fn pinned<T>(value: &T, expected: &str)
where
    T: rasn::Decode + rasn::Encode + Debug + PartialEq,
{
    let expected = vector(expected);
    let encoded = gsm_map::encode(value).expect("encode");
    assert_eq!(
        hex::encode(&encoded),
        hex::encode(&expected),
        "encoding differs from the hand-derived vector"
    );
    assert_eq!(&accepted::<T>(&expected), value);
}

// ── An independent check that nothing on the wire went missing ──────────────
//
// The same structural comparison the sibling CAP and INAP codecs use as their
// decoder guard: every element of `wire` has to be met by an element with the
// same tag in `canonical`, the encoding of the decoded value.

struct Element<'a> {
    tag: (u8, u32),
    constructed: bool,
    content: &'a [u8],
    rest: &'a [u8],
}

fn element(input: &[u8]) -> Result<Element<'_>, String> {
    let (&first, mut rest) = input.split_first().ok_or("truncated identifier")?;
    let mut number = u32::from(first & 0x1f);
    if number == 0x1f {
        number = 0;
        loop {
            let (&octet, tail) = rest.split_first().ok_or("truncated tag number")?;
            rest = tail;
            number = number * 128 + u32::from(octet & 0x7f);
            if octet & 0x80 == 0 {
                break;
            }
        }
    }
    let (&length_octet, rest) = rest.split_first().ok_or("truncated length")?;
    let tag = (first >> 6, number);
    let constructed = first & 0x20 != 0;
    if length_octet == 0x80 {
        let mut cursor = rest;
        loop {
            if let Some(after) = cursor.strip_prefix(&[0x00, 0x00]) {
                let content = &rest[..rest.len() - cursor.len()];
                return Ok(Element {
                    tag,
                    constructed,
                    content,
                    rest: after,
                });
            }
            cursor = element(cursor)?.rest;
        }
    }
    let (length, rest) = if length_octet < 0x80 {
        (usize::from(length_octet), rest)
    } else {
        let count = usize::from(length_octet & 0x7f);
        if rest.len() < count {
            return Err("truncated length".into());
        }
        let length = rest[..count]
            .iter()
            .fold(0usize, |value, &octet| (value << 8) | usize::from(octet));
        (length, &rest[count..])
    };
    if rest.len() < length {
        return Err("truncated content".into());
    }
    let (content, rest) = rest.split_at(length);
    Ok(Element {
        tag,
        constructed,
        content,
        rest,
    })
}

pub fn nothing_dropped(mut wire: &[u8], mut canonical: &[u8]) -> Result<(), String> {
    while !canonical.is_empty() {
        let expected = element(canonical)?;
        if wire.is_empty() {
            return Err(format!("{:?} is missing on the wire", expected.tag));
        }
        let found = element(wire)?;
        if found.tag != expected.tag {
            return Err(format!("{:?} is on the wire and was dropped", found.tag));
        }
        if expected.constructed {
            if !found.constructed {
                return Err(format!("{:?} is primitive on the wire", found.tag));
            }
            nothing_dropped(found.content, expected.content)?;
        }
        wire = found.rest;
        canonical = expected.rest;
    }
    if wire.is_empty() {
        Ok(())
    } else {
        Err(format!("{} octets on the wire were dropped", wire.len()))
    }
}
