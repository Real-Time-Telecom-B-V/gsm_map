//! MAP Dialogue helpers — builds the TCAP dialogue portion with application context.
//!
//! Wireshark needs the dialogue portion to decode MAP parameters correctly.
//! The dialogue portion contains an AARQ-apdu (for Begin) or AARE-apdu (for End)
//! with the application-context-name OID.

use rasn::types::ObjectIdentifier;

/// OID for dialogue-as-id: {itu-t recommendation q 773 as(1) dialogue-as(1) version1(1)}
/// = 0.0.17.773.1.1.1
const DIALOGUE_AS_ID: &[u32] = &[0, 0, 17, 773, 1, 1, 1];

/// Build the EXTERNAL content for a TCAP Begin dialogue portion (AARQ-apdu).
///
/// Returns BER-encoded EXTERNAL bytes (tag 0x28) containing:
/// - direct-reference: dialogue-as-id OID
/// - encoding: single-ASN1-type [0] AARQ-apdu with application-context-name
///
/// Use with `tcap::DialoguePortion { external: Any::new(bytes) }`.
pub fn build_begin_dialogue(ac_oid: &ObjectIdentifier) -> Vec<u8> {
    let ac_oid_bytes = encode_oid(ac_oid);

    // [1] EXPLICIT wrapping the application-context-name OID
    let mut ac_name_tlv = vec![0xA1]; // CONTEXT 1 CONSTRUCTED
    encode_length(&mut ac_name_tlv, ac_oid_bytes.len());
    ac_name_tlv.extend_from_slice(&ac_oid_bytes);

    // AARQ-apdu content: just application-context-name (protocol-version is DEFAULT)
    let aarq_content = ac_name_tlv;

    // [APPLICATION 0] IMPLICIT SEQUENCE = tag 0x60
    let mut aarq = vec![0x60];
    encode_length(&mut aarq, aarq_content.len());
    aarq.extend_from_slice(&aarq_content);

    // Wrap in [0] EXPLICIT for EXTERNAL.encoding single-ASN1-type
    let mut single_asn1 = vec![0xA0];
    encode_length(&mut single_asn1, aarq.len());
    single_asn1.extend_from_slice(&aarq);

    // Build EXTERNAL content:
    //   direct-reference: dialogue-as-id OID
    //   encoding: single-ASN1-type [0] AARQ
    let direct_ref_bytes = encode_oid_raw(DIALOGUE_AS_ID);
    let mut direct_ref_tlv = vec![0x06]; // OID tag
    encode_length(&mut direct_ref_tlv, direct_ref_bytes.len());
    direct_ref_tlv.extend_from_slice(&direct_ref_bytes);

    let mut external_content = Vec::new();
    external_content.extend_from_slice(&direct_ref_tlv);
    external_content.extend_from_slice(&single_asn1);

    // EXTERNAL: [UNIVERSAL 8] CONSTRUCTED = 0x28
    let mut external = vec![0x28];
    encode_length(&mut external, external_content.len());
    external.extend_from_slice(&external_content);

    external
}

/// Build the EXTERNAL content for a TCAP End dialogue portion (AARE-apdu).
///
/// Returns BER-encoded EXTERNAL bytes (tag 0x28).
pub fn build_end_dialogue(ac_oid: &ObjectIdentifier) -> Vec<u8> {
    let ac_oid_bytes = encode_oid(ac_oid);

    // [1] EXPLICIT wrapping the OID
    let mut ac_name_tlv = vec![0xA1];
    encode_length(&mut ac_name_tlv, ac_oid_bytes.len());
    ac_name_tlv.extend_from_slice(&ac_oid_bytes);

    // result [2] EXPLICIT: associate-result = accepted (0)
    let result_tlv = vec![0xA2, 0x03, 0x02, 0x01, 0x00];

    // result-source-diagnostic [3] EXPLICIT
    // dialogue-service-user [1] = null (0)
    let diag_tlv = vec![0xA3, 0x05, 0xA1, 0x03, 0x02, 0x01, 0x00];

    // AARE-apdu content
    let mut aare_content = Vec::new();
    aare_content.extend_from_slice(&ac_name_tlv);
    aare_content.extend_from_slice(&result_tlv);
    aare_content.extend_from_slice(&diag_tlv);

    // [APPLICATION 1] IMPLICIT SEQUENCE = tag 0x61
    let mut aare = vec![0x61];
    encode_length(&mut aare, aare_content.len());
    aare.extend_from_slice(&aare_content);

    // Wrap in [0] EXPLICIT for EXTERNAL.encoding single-ASN1-type
    let mut single_asn1 = vec![0xA0];
    encode_length(&mut single_asn1, aare.len());
    single_asn1.extend_from_slice(&aare);

    // Build EXTERNAL content
    let direct_ref_bytes = encode_oid_raw(DIALOGUE_AS_ID);
    let mut direct_ref_tlv = vec![0x06];
    encode_length(&mut direct_ref_tlv, direct_ref_bytes.len());
    direct_ref_tlv.extend_from_slice(&direct_ref_bytes);

    let mut external_content = Vec::new();
    external_content.extend_from_slice(&direct_ref_tlv);
    external_content.extend_from_slice(&single_asn1);

    // EXTERNAL: [UNIVERSAL 8] CONSTRUCTED = 0x28
    let mut external = vec![0x28];
    encode_length(&mut external, external_content.len());
    external.extend_from_slice(&external_content);

    external
}

/// Encode an OID as a full TLV (tag 0x06 + length + value).
fn encode_oid(oid: &ObjectIdentifier) -> Vec<u8> {
    let components: Vec<u32> = oid.iter().copied().collect();
    let raw = encode_oid_raw(&components);
    let mut tlv = vec![0x06];
    encode_length(&mut tlv, raw.len());
    tlv.extend_from_slice(&raw);
    tlv
}

/// Encode OID components to raw bytes (no tag/length).
fn encode_oid_raw(components: &[u32]) -> Vec<u8> {
    let mut bytes = Vec::new();
    if components.len() >= 2 {
        bytes.push((components[0] * 40 + components[1]) as u8);
        for &c in &components[2..] {
            encode_oid_component(&mut bytes, c);
        }
    }
    bytes
}

fn encode_oid_component(buf: &mut Vec<u8>, value: u32) {
    if value < 128 {
        buf.push(value as u8);
    } else {
        let mut temp = Vec::new();
        let mut v = value;
        temp.push((v & 0x7F) as u8);
        v >>= 7;
        while v > 0 {
            temp.push((v & 0x7F) as u8 | 0x80);
            v >>= 7;
        }
        temp.reverse();
        buf.extend_from_slice(&temp);
    }
}

fn encode_length(buf: &mut Vec<u8>, len: usize) {
    if len < 128 {
        buf.push(len as u8);
    } else if len < 256 {
        buf.push(0x81);
        buf.push(len as u8);
    } else {
        buf.push(0x82);
        buf.push((len >> 8) as u8);
        buf.push((len & 0xFF) as u8);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::application_context;

    #[test]
    fn begin_dialogue_has_correct_tags() {
        let bytes = build_begin_dialogue(
            &application_context::short_msg_gateway_context(application_context::V3),
        );

        // Should start with 0x28 (EXTERNAL = UNIVERSAL 8 CONSTRUCTED)
        assert_eq!(bytes[0], 0x28, "Expected EXTERNAL tag");

        // Should contain OID tag 0x06 (dialogue-as-id)
        assert!(bytes.contains(&0x06), "Should contain OID tag");

        // Should contain AARQ tag 0x60 (APPLICATION 0)
        assert!(bytes.contains(&0x60), "Should contain AARQ tag");
    }

    #[test]
    fn end_dialogue_has_correct_tags() {
        let bytes = build_end_dialogue(
            &application_context::short_msg_gateway_context(application_context::V3),
        );

        // Should start with 0x28 (EXTERNAL)
        assert_eq!(bytes[0], 0x28, "Expected EXTERNAL tag");
        assert!(bytes.contains(&0x61), "Should contain AARE tag");
    }
}
