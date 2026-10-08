//! The decoder behind [`crate::decode`].
//!
//! `rasn` 0.28 (checked on 0.28.14 and 0.28.15) cannot be used directly on
//! MAP, for two opposite reasons.
//!
//! It loses data without an error:
//!
//! * An OPTIONAL member behind an EXPLICIT tag is decoded by trying, and if
//!   anything inside fails the member is reported as absent
//!   (`decode_optional_with_explicit_prefix`: `.or_else(|_| Ok(None))`). Its
//!   octets have been consumed by then, so nothing else complains. In MAP
//!   every CHOICE-typed member behind a context tag is explicit:
//!   `additional-Number` and `thirdNumber` of `LocationInfoWithLMSI`,
//!   `eps-info`, `identity`, `subscriberIdentity` and many more.
//! * A SEQUENCE OF stops at the first element that fails and returns the
//!   elements before it (`decode_sequence_of`: `Err(_) => break`). When the
//!   failed element is the last one, the list comes back one short, or empty.
//! * Octets after the outermost value are ignored.
//!
//! And it refuses what TS 29.002 obliges a receiver to accept: a SEQUENCE
//! carrying a member added in a later release fails with
//! `UnexpectedExtraData`, and inside a list or behind an explicit tag that
//! failure then turns into the silent loss described above.
//!
//! # What this decoder does instead
//!
//! It implements [`rasn::Decoder`] itself. The derived `Decode` impls of the
//! crate's types drive it exactly as they drive `rasn`'s own BER decoder, the
//! value of every primitive element is still read by `rasn`, and only the
//! framing is done here: SEQUENCE, SEQUENCE OF, SET OF, CHOICE, OPTIONAL and
//! EXPLICIT. That is where the knowledge needed to tell the cases apart is
//! available, because a SEQUENCE is decoded with its list of members at hand.
//!
//! * A member this crate models whose content cannot be decoded is an error,
//!   wherever it sits.
//! * Every element of a SEQUENCE OF or SET OF has to decode.
//! * Nothing may follow the outermost value, the value inside an EXPLICIT
//!   tag, or the last member of a SEQUENCE that is not extensible.
//! * SEQUENCE, SEQUENCE OF, SET OF and EXPLICIT have to be constructed on the
//!   wire (X.690 8.9.1, 8.10.1, 8.12.1, 8.14.2).
//! * Elements left over after the last modelled member of an extensible
//!   SEQUENCE, with tags that SEQUENCE does not define, are extension
//!   additions from a later release. They are skipped and reported as
//!   [`UnknownExtension`]. An element with a tag the SEQUENCE does define that
//!   is left over is a repeated or misplaced member and is an error.
//!
//! # Which SEQUENCEs are extensible
//!
//! TS 29.002 clause 17.1.4: "An extension marker ("...") is used wherever
//! future protocol extensions are foreseen. The "..." construct applies only
//! to SEQUENCE and ENUMERATED data types. An entity supporting a version
//! greater than 1 shall not reject an unsupported extension following "..."
//! of that SEQUENCE or ENUMERATED data type."
//!
//! In the Rel-18 modules 320 of the 326 SEQUENCE types carry the marker, so
//! extensible is the default here and the exceptions this crate models are
//! named in `is_closed`. The marker is always the last thing before the
//! additions and no type has a second one, so additions unknown to this crate
//! can only arrive after every member it models: that is the only place they
//! are accepted (X.680 clause 52 on the extension insertion point).
//!
//! No CHOICE in TS 29.002 has an extension marker, so an alternative this
//! crate does not know is a decoding error. Extensible ENUMERATED types are
//! carried so that an unknown value survives decoding, see
//! [`crate::types::OpenEnumerated`] and the enums with an `Unrecognised`
//! variant: what a receiver does with such a value is laid down per type in
//! the ASN.1 comments and is not the codec's decision.

use rasn::ber::de::{Decoder as BerDecoder, DecoderOptions};
use rasn::de::Error as _;
use rasn::error::DecodeError;
use rasn::types::{self, Class, Constraints, Constructed, Enumerated, Tag, TagTree};
use rasn::{Codec, Decode};

/// Nesting allowed while decoding. MAP parameters nest about a dozen levels
/// deep; the bound keeps a hostile value from exhausting the stack.
const MAX_DEPTH: usize = 64;

const CODEC: Codec = Codec::Ber;

type Result<T> = core::result::Result<T, DecodeError>;

/// Whether `D` models one of the SEQUENCE types of TS 29.002 (Rel-18) that
/// have **no** extension marker: `CorrelationID` and
/// `NetworkNodeDiameterAddress`. Anything after their last member is an
/// error.
///
/// `SubscriberData` (only used through `COMPONENTS OF`), `GPRSMSClass`,
/// `StateAttributes` and `PrivateExtension` are the other SEQUENCE types
/// without a marker; this crate carries the members that hold them opaquely.
///
/// The decoder is handed `D` with nothing but its member list, so the type is
/// recognised by that list.
fn is_closed<const RC: usize, const EC: usize, D: Constructed<RC, EC>>() -> bool {
    fn same<const RC: usize, const EC: usize, const N: usize, D, C>() -> bool
    where
        D: Constructed<RC, EC>,
        C: Constructed<N, 0>,
    {
        D::EXTENDED_FIELDS.is_none()
            && D::FIELDS.len() == C::FIELDS.len()
            && D::FIELDS
                .iter()
                .zip(C::FIELDS.iter())
                .all(|(a, b)| a.name == b.name && a.tag == b.tag)
    }
    same::<RC, EC, 3, D, crate::types::CorrelationId>()
        || same::<RC, EC, 2, D, crate::types::NetworkNodeDiameterAddress>()
}

/// The name of a Rust type without its module path, for messages.
fn short_name<T>() -> &'static str {
    let full = core::any::type_name::<T>();
    let base = full.split('<').next().unwrap_or(full);
    base.rsplit("::").next().unwrap_or(base)
}

/// A member of an extensible SEQUENCE that this crate does not model: an
/// extension addition from a later release of TS 29.002, or a private
/// extension outside the extension container.
///
/// It was skipped as clause 17.1.4 requires. It is reported so that a caller
/// can log it or count it, rather than it disappearing without a trace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownExtension {
    /// Name of the Rust type modelling the SEQUENCE that carried the element,
    /// for example `"LocationInfoWithLmsi"`. For logs, not for matching on.
    pub container: &'static str,
    /// The tag of the element.
    pub tag: Tag,
    /// Whether the element is constructed.
    pub constructed: bool,
    /// The complete element as received: identifier, length and content.
    pub encoding: Vec<u8>,
}

impl core::fmt::Display for UnknownExtension {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "{} in {} ({} octets)",
            tag_name(self.tag),
            self.container,
            self.encoding.len()
        )
    }
}

/// A decoded value together with the extension additions that were skipped
/// while decoding it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decoded<T> {
    /// The value, with every member this crate models.
    pub value: T,
    /// Elements this crate does not model, in the order they were met. Empty
    /// when the peer sent nothing beyond what this crate knows.
    pub unknown_extensions: Vec<UnknownExtension>,
}

fn error(message: impl core::fmt::Display) -> DecodeError {
    DecodeError::custom(message, CODEC)
}

/// A tag the way the ASN.1 writes it: `[5]`, `[PRIVATE 2]`, `[UNIVERSAL 16]`.
fn tag_name(tag: Tag) -> String {
    let class = match tag.class {
        Class::Universal => "UNIVERSAL ",
        Class::Application => "APPLICATION ",
        Class::Context => "",
        Class::Private => "PRIVATE ",
    };
    format!("[{class}{}]", tag.value)
}

struct Element<'a> {
    tag: Tag,
    constructed: bool,
    content: &'a [u8],
    /// Identifier, length and content, with the end-of-contents octets when
    /// the length is indefinite.
    encoding: &'a [u8],
    rest: &'a [u8],
}

/// Read the identifier octets at the front of `input`.
fn identifier(input: &[u8]) -> Result<(Tag, bool, &[u8])> {
    let (&first, mut rest) = input
        .split_first()
        .ok_or_else(|| error("truncated: no identifier octet"))?;
    let class = Class::from_u8(first >> 6);
    let constructed = first & 0x20 != 0;
    let mut number = u32::from(first & 0x1f);
    if number == 0x1f {
        // High tag number form: base 128, most significant group first.
        number = 0;
        loop {
            let (&octet, tail) = rest
                .split_first()
                .ok_or_else(|| error("truncated tag number"))?;
            rest = tail;
            number = number
                .checked_mul(128)
                .and_then(|n| n.checked_add(u32::from(octet & 0x7f)))
                .ok_or_else(|| error("tag number too large"))?;
            if octet & 0x80 == 0 {
                break;
            }
        }
    }
    Ok((Tag::new(class, number), constructed, rest))
}

/// Split one tag-length-value off the front of `input`.
fn element(input: &[u8], depth: usize) -> Result<Element<'_>> {
    if depth > MAX_DEPTH {
        return Err(error(format!("nesting deeper than {MAX_DEPTH} levels")));
    }
    let (tag, constructed, rest) = identifier(input)?;
    let (&length_octet, rest) = rest
        .split_first()
        .ok_or_else(|| error("truncated: no length octet"))?;

    if length_octet == 0x80 {
        // Indefinite form: the content runs to the matching end-of-contents.
        if !constructed {
            return Err(error(format!(
                "{} is primitive with an indefinite length",
                tag_name(tag)
            )));
        }
        let mut cursor = rest;
        loop {
            if let Some(after) = cursor.strip_prefix(&[0x00, 0x00]) {
                return Ok(Element {
                    tag,
                    constructed,
                    content: &rest[..rest.len() - cursor.len()],
                    encoding: &input[..input.len() - after.len()],
                    rest: after,
                });
            }
            if cursor.is_empty() {
                return Err(error(format!(
                    "{} has no end-of-contents octets",
                    tag_name(tag)
                )));
            }
            cursor = element(cursor, depth + 1)?.rest;
        }
    }

    let (length, rest) = if length_octet < 0x80 {
        (usize::from(length_octet), rest)
    } else {
        let count = usize::from(length_octet & 0x7f);
        if count > core::mem::size_of::<usize>() || rest.len() < count {
            return Err(error(format!("{} has an unusable length", tag_name(tag))));
        }
        let (octets, rest) = rest.split_at(count);
        let length = octets
            .iter()
            .fold(0usize, |value, &octet| (value << 8) | usize::from(octet));
        (length, rest)
    };
    if rest.len() < length {
        return Err(error(format!(
            "{} is truncated: {length} octets announced, {} present",
            tag_name(tag),
            rest.len()
        )));
    }
    let (content, rest) = rest.split_at(length);
    Ok(Element {
        tag,
        constructed,
        content,
        encoding: &input[..input.len() - rest.len()],
        rest,
    })
}

/// A BER decoder for MAP: strict where `rasn` loses data, and tolerant of
/// extension additions where TS 29.002 requires it. See the module
/// documentation.
pub(crate) struct Decoder<'a> {
    input: &'a [u8],
    depth: usize,
    unknown: Vec<UnknownExtension>,
}

impl<'a> Decoder<'a> {
    fn new(input: &'a [u8]) -> Self {
        Self {
            input,
            depth: 0,
            unknown: Vec::new(),
        }
    }

    /// The tag of the next element, or `None` at the end of the input.
    fn peek(&self) -> Result<Option<Tag>> {
        if self.input.is_empty() {
            return Ok(None);
        }
        identifier(self.input).map(|(tag, _, _)| Some(tag))
    }

    /// Take the next element, which has to carry `tag` unless `tag` is
    /// [`Tag::EOC`], the way `rasn` spells "any tag".
    fn next(&mut self, tag: Tag) -> Result<Element<'a>> {
        if self.input.is_empty() {
            return Err(error(format!("{} is missing: no more data", tag_name(tag))));
        }
        let found = element(self.input, self.depth)?;
        if tag != Tag::EOC && found.tag != tag {
            return Err(error(format!(
                "expected {}, found {}",
                tag_name(tag),
                tag_name(found.tag)
            )));
        }
        self.input = found.rest;
        Ok(found)
    }

    /// Hand the next element, and nothing after it, to `rasn` for its value.
    fn leaf<T>(
        &mut self,
        tag: Tag,
        decode: impl FnOnce(&mut BerDecoder<'a>) -> Result<T>,
    ) -> Result<T> {
        let found = self.next(tag)?;
        let mut inner = BerDecoder::new(found.encoding, DecoderOptions::ber());
        let value = decode(&mut inner)?;
        if !inner.remaining().is_empty() {
            return Err(error(format!(
                "{} was not read completely",
                tag_name(found.tag)
            )));
        }
        Ok(value)
    }

    /// Open the next element, which has to be constructed, and return a
    /// decoder over its content.
    fn constructed(&mut self, tag: Tag, what: &str) -> Result<Self> {
        let found = self.next(tag)?;
        if !found.constructed {
            return Err(error(format!(
                "{} is primitive on the wire, a {what} has to be constructed",
                tag_name(found.tag)
            )));
        }
        if self.depth >= MAX_DEPTH {
            return Err(error(format!("nesting deeper than {MAX_DEPTH} levels")));
        }
        Ok(Self {
            input: found.content,
            depth: self.depth + 1,
            unknown: Vec::new(),
        })
    }

    /// Account for whatever `decode_fn` left unread in a SEQUENCE.
    fn skip_extensions<const RC: usize, const EC: usize, D: Constructed<RC, EC>>(
        &mut self,
    ) -> Result<()> {
        let shown = short_name::<D>();
        while !self.input.is_empty() {
            let found = element(self.input, self.depth)?;
            let modelled = D::FIELDS
                .iter()
                .chain(D::EXTENDED_FIELDS.iter().flat_map(|fields| fields.iter()))
                .find(|field| {
                    field.tag == found.tag || TagTree::tag_contains(&found.tag, &[field.tag_tree])
                });
            if let Some(field) = modelled {
                return Err(error(format!(
                    "{shown}: member {} {} is repeated or out of order",
                    field.name,
                    tag_name(found.tag)
                )));
            }
            if !D::IS_EXTENSIBLE && is_closed::<RC, EC, D>() {
                return Err(error(format!(
                    "{shown} is not extensible and carries {}, which it does not define",
                    tag_name(found.tag)
                )));
            }
            self.unknown.push(UnknownExtension {
                container: shown,
                tag: found.tag,
                constructed: found.constructed,
                encoding: found.encoding.to_vec(),
            });
            self.input = found.rest;
        }
        Ok(())
    }

    /// Decode an OPTIONAL member: present when the next element carries
    /// `tag`. For an untagged CHOICE (`tag` is [`Tag::EOC`] and `tree` lists
    /// the alternatives) it is present when the next element is one of the
    /// alternatives; for an untagged open type it is present whenever
    /// anything is left, as in `rasn`.
    fn optional<T>(
        &mut self,
        tag: Tag,
        tree: TagTree,
        decode: impl FnOnce(&mut Self) -> Result<T>,
    ) -> Result<Option<T>> {
        let Some(upcoming) = self.peek()? else {
            return Ok(None);
        };
        let present = if tag != Tag::EOC {
            upcoming == tag
        } else {
            match tree {
                TagTree::Choice(_) => TagTree::tag_contains(&upcoming, &[tree]),
                TagTree::Leaf(_) => true,
            }
        };
        if present {
            decode(self).map(Some)
        } else {
            Ok(None)
        }
    }

    fn check_size(length: usize, constraints: &Constraints) -> Result<()> {
        match constraints.size() {
            Some(size) if !size.constraint.contains(&length) => Err(error(format!(
                "{length} elements, outside the SIZE constraint"
            ))),
            _ => Ok(()),
        }
    }
}

impl<'a> rasn::Decoder for Decoder<'a> {
    type Ok = ();
    type Error = DecodeError;
    type AnyDecoder<const R: usize, const E: usize> = Decoder<'a>;

    fn codec(&self) -> Codec {
        CODEC
    }

    fn decode_any(&mut self, tag: Tag) -> Result<types::Any> {
        self.leaf(tag, |ber| ber.decode_any(tag))
    }

    fn decode_bit_string(
        &mut self,
        tag: Tag,
        constraints: Constraints,
    ) -> Result<types::BitString> {
        self.leaf(tag, |ber| ber.decode_bit_string(tag, constraints))
    }

    fn decode_bool(&mut self, tag: Tag) -> Result<bool> {
        self.leaf(tag, |ber| ber.decode_bool(tag))
    }

    fn decode_enumerated<E: Enumerated>(&mut self, tag: Tag) -> Result<E> {
        self.leaf(tag, |ber| ber.decode_enumerated(tag))
    }

    fn decode_integer<I: types::IntegerType>(
        &mut self,
        tag: Tag,
        constraints: Constraints,
    ) -> Result<I> {
        self.leaf(tag, |ber| ber.decode_integer(tag, constraints))
    }

    fn decode_real<R: types::RealType>(&mut self, tag: Tag, constraints: Constraints) -> Result<R> {
        self.leaf(tag, |ber| ber.decode_real(tag, constraints))
    }

    fn decode_null(&mut self, tag: Tag) -> Result<()> {
        let found = self.next(tag)?;
        if found.constructed || !found.content.is_empty() {
            return Err(error(format!(
                "{} is a NULL and has to be primitive and empty",
                tag_name(found.tag)
            )));
        }
        Ok(())
    }

    fn decode_object_identifier(&mut self, tag: Tag) -> Result<types::ObjectIdentifier> {
        self.leaf(tag, |ber| ber.decode_object_identifier(tag))
    }

    fn decode_sequence<const RC: usize, const EC: usize, D, DF, F>(
        &mut self,
        tag: Tag,
        default_initializer_fn: Option<DF>,
        decode_fn: F,
    ) -> Result<D>
    where
        D: Constructed<RC, EC>,
        DF: FnOnce() -> D,
        F: FnOnce(&mut Self::AnyDecoder<RC, EC>) -> Result<D>,
    {
        let mut inner = self.constructed(tag, "SEQUENCE")?;
        // As in rasn: with no members to read, or nothing on the wire and
        // every member optional, the value is the default one.
        let nothing_to_read = D::FIELDS.is_empty() && D::EXTENDED_FIELDS.is_none()
            || (D::FIELDS.len() == D::FIELDS.number_of_optional_and_default_fields()
                && inner.input.is_empty());
        let value = match default_initializer_fn {
            Some(default) if nothing_to_read => default(),
            _ => decode_fn(&mut inner)?,
        };
        inner.skip_extensions::<RC, EC, D>()?;
        self.unknown.append(&mut inner.unknown);
        Ok(value)
    }

    fn decode_sequence_of<D: Decode>(
        &mut self,
        tag: Tag,
        constraints: Constraints,
    ) -> Result<Vec<D>> {
        let mut inner = self.constructed(tag, "SEQUENCE OF")?;
        let mut items = Vec::new();
        while !inner.input.is_empty() {
            items.push(D::decode(&mut inner)?);
        }
        self.unknown.append(&mut inner.unknown);
        Self::check_size(items.len(), &constraints)?;
        Ok(items)
    }

    fn decode_set_of<D: Decode + Eq + core::hash::Hash>(
        &mut self,
        tag: Tag,
        constraints: Constraints,
    ) -> Result<types::SetOf<D>> {
        let mut inner = self.constructed(tag, "SET OF")?;
        let mut items = types::SetOf::new();
        while !inner.input.is_empty() {
            items.insert(D::decode(&mut inner)?);
        }
        self.unknown.append(&mut inner.unknown);
        Self::check_size(items.len(), &constraints)?;
        Ok(items)
    }

    fn decode_octet_string<'buf, T>(&'buf mut self, tag: Tag, constraints: Constraints) -> Result<T>
    where
        T: From<&'buf [u8]> + From<Vec<u8>>,
    {
        // The usual case, and most of a MAP message: primitive, no SIZE
        // constraint to check. The content is the value.
        if constraints.size().is_none() {
            let rest = self.input;
            let found = self.next(tag)?;
            if !found.constructed {
                return Ok(T::from(found.content.to_vec()));
            }
            // Constructed (segmented) form: let rasn reassemble it.
            self.input = rest;
        }
        self.leaf(tag, |ber| {
            ber.decode_octet_string::<Vec<u8>>(tag, constraints)
        })
        .map(T::from)
    }

    fn decode_utf8_string(
        &mut self,
        tag: Tag,
        constraints: Constraints,
    ) -> Result<types::Utf8String> {
        self.leaf(tag, |ber| ber.decode_utf8_string(tag, constraints))
    }

    fn decode_visible_string(
        &mut self,
        tag: Tag,
        constraints: Constraints,
    ) -> Result<types::VisibleString> {
        self.leaf(tag, |ber| ber.decode_visible_string(tag, constraints))
    }

    fn decode_general_string(
        &mut self,
        tag: Tag,
        constraints: Constraints,
    ) -> Result<types::GeneralString> {
        self.leaf(tag, |ber| ber.decode_general_string(tag, constraints))
    }

    fn decode_graphic_string(
        &mut self,
        tag: Tag,
        constraints: Constraints,
    ) -> Result<types::GraphicString> {
        self.leaf(tag, |ber| ber.decode_graphic_string(tag, constraints))
    }

    fn decode_ia5_string(
        &mut self,
        tag: Tag,
        constraints: Constraints,
    ) -> Result<types::Ia5String> {
        self.leaf(tag, |ber| ber.decode_ia5_string(tag, constraints))
    }

    fn decode_printable_string(
        &mut self,
        tag: Tag,
        constraints: Constraints,
    ) -> Result<types::PrintableString> {
        self.leaf(tag, |ber| ber.decode_printable_string(tag, constraints))
    }

    fn decode_numeric_string(
        &mut self,
        tag: Tag,
        constraints: Constraints,
    ) -> Result<types::NumericString> {
        self.leaf(tag, |ber| ber.decode_numeric_string(tag, constraints))
    }

    fn decode_teletex_string(
        &mut self,
        tag: Tag,
        constraints: Constraints,
    ) -> Result<types::TeletexString> {
        self.leaf(tag, |ber| ber.decode_teletex_string(tag, constraints))
    }

    fn decode_bmp_string(
        &mut self,
        tag: Tag,
        constraints: Constraints,
    ) -> Result<types::BmpString> {
        self.leaf(tag, |ber| ber.decode_bmp_string(tag, constraints))
    }

    fn decode_explicit_prefix<D: Decode>(&mut self, tag: Tag) -> Result<D> {
        let mut inner = self.constructed(tag, "value behind an EXPLICIT tag")?;
        let value = D::decode(&mut inner)?;
        if !inner.input.is_empty() {
            return Err(error(format!(
                "{} holds {} octets after its value",
                tag_name(tag),
                inner.input.len()
            )));
        }
        self.unknown.append(&mut inner.unknown);
        Ok(value)
    }

    fn decode_optional_with_explicit_prefix<D: Decode>(&mut self, tag: Tag) -> Result<Option<D>> {
        // Present means present: once the tag matches, whatever is inside
        // either decodes or fails the whole value.
        self.optional(tag, TagTree::Leaf(tag), |decoder| {
            decoder.decode_explicit_prefix(tag)
        })
    }

    fn decode_utc_time(&mut self, tag: Tag) -> Result<types::UtcTime> {
        self.leaf(tag, |ber| ber.decode_utc_time(tag))
    }

    fn decode_generalized_time(&mut self, tag: Tag) -> Result<types::GeneralizedTime> {
        self.leaf(tag, |ber| ber.decode_generalized_time(tag))
    }

    fn decode_date(&mut self, tag: Tag) -> Result<types::Date> {
        self.leaf(tag, |ber| ber.decode_date(tag))
    }

    fn decode_set<const RC: usize, const EC: usize, FIELDS, SET, D, F>(
        &mut self,
        tag: Tag,
        _decode_fn: D,
        field_fn: F,
    ) -> Result<SET>
    where
        SET: Decode + Constructed<RC, EC>,
        FIELDS: Decode,
        D: Fn(&mut Self::AnyDecoder<RC, EC>, usize, Tag) -> Result<FIELDS>,
        F: FnOnce(Vec<FIELDS>) -> Result<SET>,
    {
        // TS 29.002 has no SET; every member present has to be one the type
        // defines.
        let mut inner = self.constructed(tag, "SET")?;
        let mut fields = Vec::new();
        while !inner.input.is_empty() {
            fields.push(FIELDS::decode(&mut inner)?);
        }
        self.unknown.append(&mut inner.unknown);
        field_fn(fields)
    }

    fn decode_choice<D>(&mut self, _: Constraints) -> Result<D>
    where
        D: types::DecodeChoice,
    {
        let tag = self
            .peek()?
            .ok_or_else(|| error("a CHOICE is missing: no more data"))?;
        // An alternative the type does not define is an error raised by
        // `from_tag`: no CHOICE in TS 29.002 is extensible.
        D::from_tag(self, tag)
    }

    fn decode_optional<D: Decode>(&mut self) -> Result<Option<D>> {
        self.optional(D::TAG, D::TAG_TREE, D::decode)
    }

    fn decode_optional_with_tag<D: Decode>(&mut self, tag: Tag) -> Result<Option<D>> {
        self.optional(tag, D::TAG_TREE, |decoder| D::decode_with_tag(decoder, tag))
    }

    fn decode_optional_with_constraints<D: Decode>(
        &mut self,
        constraints: Constraints,
    ) -> Result<Option<D>> {
        self.optional(D::TAG, D::TAG_TREE, |decoder| {
            D::decode_with_constraints(decoder, constraints)
        })
    }

    fn decode_optional_with_tag_and_constraints<D: Decode>(
        &mut self,
        tag: Tag,
        constraints: Constraints,
    ) -> Result<Option<D>> {
        self.optional(tag, D::TAG_TREE, |decoder| {
            D::decode_with_tag_and_constraints(decoder, tag, constraints)
        })
    }

    fn decode_extension_addition_with_explicit_tag_and_constraints<D: Decode>(
        &mut self,
        tag: Tag,
        _: Constraints,
    ) -> Result<Option<D>> {
        self.decode_optional_with_explicit_prefix(tag)
    }

    fn decode_extension_addition_with_tag_and_constraints<D: Decode>(
        &mut self,
        tag: Tag,
        constraints: Constraints,
    ) -> Result<Option<D>> {
        self.decode_optional_with_tag_and_constraints(tag, constraints)
    }

    fn decode_extension_addition_group<
        const RC: usize,
        const EC: usize,
        D: Decode + Constructed<RC, EC>,
    >(
        &mut self,
    ) -> Result<Option<D>> {
        self.decode_optional()
    }
}

/// Decode one value from `bytes`, which has to hold that value and nothing
/// else. Returns the value and the extension additions that were skipped.
pub(crate) fn decode<T: Decode>(bytes: &[u8]) -> Result<(T, Vec<UnknownExtension>)> {
    let mut decoder = Decoder::new(bytes);
    let value = T::decode(&mut decoder)?;
    if !decoder.input.is_empty() {
        return Err(error(format!(
            "{} octets follow the value",
            decoder.input.len()
        )));
    }
    Ok((value, decoder.unknown))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_element_is_split_with_its_whole_encoding() {
        let found = element(&[0x30, 0x03, 0x80, 0x01, 0x07, 0xff], 0).unwrap();
        assert_eq!(found.tag, Tag::new(Class::Universal, 16));
        assert!(found.constructed);
        assert_eq!(found.content, [0x80, 0x01, 0x07]);
        assert_eq!(found.encoding, [0x30, 0x03, 0x80, 0x01, 0x07]);
        assert_eq!(found.rest, [0xff]);
    }

    #[test]
    fn long_and_indefinite_lengths_are_read() {
        let long = element(&[0xa2, 0x81, 0x03, 0x80, 0x01, 0x02], 0).unwrap();
        assert_eq!(long.content, [0x80, 0x01, 0x02]);
        assert!(long.rest.is_empty());

        let wire = [0xa2, 0x80, 0x80, 0x01, 0x02, 0x00, 0x00, 0x05, 0x00];
        let indefinite = element(&wire, 0).unwrap();
        assert_eq!(indefinite.content, [0x80, 0x01, 0x02]);
        assert_eq!(indefinite.encoding, &wire[..7]);
        assert_eq!(indefinite.rest, [0x05, 0x00]);
    }

    #[test]
    fn high_tag_numbers_are_read() {
        let found = element(&[0x9f, 0x32, 0x00], 0).unwrap();
        assert_eq!(found.tag, Tag::new(Class::Context, 50));
        assert_eq!(tag_name(found.tag), "[50]");
        let private = element(&[0xdf, 0x81, 0x00, 0x00], 0).unwrap();
        assert_eq!(tag_name(private.tag), "[PRIVATE 128]");
    }

    #[test]
    fn truncated_elements_are_refused() {
        assert!(element(&[], 0).is_err());
        assert!(element(&[0x30], 0).is_err());
        assert!(element(&[0x30, 0x05, 0x00], 0).is_err());
        assert!(element(&[0x9f], 0).is_err());
        assert!(element(&[0x30, 0x82, 0x01], 0).is_err());
        // Indefinite length that never ends, and one on a primitive element.
        assert!(element(&[0x30, 0x80, 0x05, 0x00], 0).is_err());
        assert!(element(&[0x04, 0x80, 0x00, 0x00], 0).is_err());
    }

    #[test]
    fn octet_strings_are_read_in_both_forms() {
        let (primitive, _) = decode::<types::OctetString>(&[0x04, 0x02, 0xaa, 0xbb]).unwrap();
        assert_eq!(primitive, [0xaa, 0xbb].as_slice());
        // The constructed form is BER, although TS 29.002 17.1.1 asks senders
        // for the primitive one; it is read, not refused.
        let (segmented, _) =
            decode::<types::OctetString>(&[0x24, 0x06, 0x04, 0x01, 0xaa, 0x04, 0x01, 0xbb])
                .unwrap();
        assert_eq!(segmented, [0xaa, 0xbb].as_slice());
        assert!(decode::<types::OctetString>(&[0x05, 0x00]).is_err());
        assert!(decode::<types::OctetString>(&[0x04, 0x03, 0xaa]).is_err());
    }

    #[test]
    fn a_null_has_to_be_empty() {
        assert!(decode::<()>(&[0x05, 0x00]).is_ok());
        assert!(decode::<()>(&[0x05, 0x01, 0x00]).is_err());
        assert!(decode::<()>(&[0x25, 0x00]).is_err());
    }

    #[test]
    fn nesting_is_bounded() {
        let mut wire = Vec::new();
        for _ in 0..100 {
            wire.extend_from_slice(&[0x30, 0x80]);
        }
        for _ in 0..100 {
            wire.extend_from_slice(&[0x00, 0x00]);
        }
        assert!(element(&wire, 0).is_err());
        assert!(decode::<types::Any>(&wire).is_err());
    }
}
