//! Encoders for the TBCD address / identity OCTET STRINGs that MAP operations
//! carry as raw bytes.
//!
//! MAP keeps [`IsdnAddressString`](crate::types::IsdnAddressString),
//! [`AddressString`](crate::types::AddressString) and [`Imsi`](crate::types::Imsi)
//! as opaque OCTET STRINGs. These helpers build the bytes from a digit string so
//! a caller does not hand-pack semi-octets:
//!
//! * an AddressString is a leading nature-of-address / numbering-plan octet
//!   (TS 29.002 §17.7.8, ITU-T Q.713 §3.4) followed by the TBCD digits: the
//!   extension bit (`1`), the 3-bit nature of address, the 4-bit numbering plan;
//! * an IMSI is a bare TBCD-STRING (TS 29.002 §17.7.8) with no leading octet.
//!
//! The TBCD packing is [`sccp::bcd::encode_tbcd`]: two digits per byte, low
//! nibble first, `0xF` filler for an odd digit count.
//!
//! ```
//! use gsm_map::address;
//! // A service-centre / HLR number, international E.164 (leading octet 0x91).
//! assert_eq!(
//!     address::international_e164("15550190").unwrap(),
//!     vec![0x91, 0x51, 0x55, 0x10, 0x09],
//! );
//! ```

use crate::error::MapError;

/// Nature of address — international number (E.164 with country code).
pub const NATURE_INTERNATIONAL: u8 = 1;
/// Nature of address — national (significant) number.
pub const NATURE_NATIONAL: u8 = 2;
/// Nature of address — network-specific number.
pub const NATURE_NETWORK_SPECIFIC: u8 = 3;
/// Nature of address — subscriber number.
pub const NATURE_SUBSCRIBER: u8 = 4;

/// Numbering plan — ISDN / telephony (E.164).
pub const PLAN_ISDN: u8 = 1;
/// Numbering plan — land mobile (E.212).
pub const PLAN_LAND_MOBILE: u8 = 6;

/// Encode an ISDN-AddressString / AddressString from a digit string.
///
/// The leading octet is `0x80 | (nature << 4) | plan`: the extension bit set,
/// the 3-bit nature of address, and the 4-bit numbering plan. The TBCD digits
/// follow. `nature` must fit 3 bits (`0..=7`) and `plan` 4 bits (`0..=15`);
/// non-digit input is rejected.
pub fn isdn_address_string(digits: &str, nature: u8, plan: u8) -> Result<Vec<u8>, MapError> {
    if nature > 0x07 {
        return Err(MapError::InvalidAddress(format!(
            "nature of address {nature} does not fit 3 bits"
        )));
    }
    if plan > 0x0F {
        return Err(MapError::InvalidAddress(format!(
            "numbering plan {plan} does not fit 4 bits"
        )));
    }
    let leading = 0x80 | (nature << 4) | plan;
    let mut out = Vec::with_capacity(1 + digits.len().div_ceil(2));
    out.push(leading);
    out.extend(tbcd(digits)?);
    Ok(out)
}

/// Encode an international E.164 ISDN number (leading octet `0x91`): the common
/// HLR / MSC / service-centre address form.
pub fn international_e164(digits: &str) -> Result<Vec<u8>, MapError> {
    isdn_address_string(digits, NATURE_INTERNATIONAL, PLAN_ISDN)
}

/// Encode an IMSI as a bare TBCD-STRING (no leading octet), per TS 29.002.
pub fn imsi(digits: &str) -> Result<Vec<u8>, MapError> {
    tbcd(digits)
}

fn tbcd(digits: &str) -> Result<Vec<u8>, MapError> {
    sccp::bcd::encode_tbcd(digits).map_err(|e| MapError::InvalidAddress(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Known-answer vectors. Fictional `+1 555 01xx` documentation block; test
    // PLMN `001/01`. The bytes are the on-the-wire OCTET STRING content, checked
    // against the format, not a round-trip.

    #[test]
    fn international_e164_even_length() {
        // +1 555 0190 → leading 0x91 then TBCD(15550190).
        assert_eq!(
            international_e164("15550190").unwrap(),
            vec![0x91, 0x51, 0x55, 0x10, 0x09]
        );
    }

    #[test]
    fn international_e164_odd_length_gets_filler() {
        // +1 555 0100 999 (11 digits) → a trailing 0xF filler nibble.
        assert_eq!(
            international_e164("15550100999").unwrap(),
            vec![0x91, 0x51, 0x55, 0x10, 0x00, 0x99, 0xF9]
        );
    }

    #[test]
    fn national_number_sets_nature_and_plan() {
        // nature=national(2), plan=isdn(1) → leading 0x80|0x20|0x01 = 0xA1.
        assert_eq!(
            isdn_address_string("15550190", NATURE_NATIONAL, PLAN_ISDN).unwrap(),
            vec![0xA1, 0x51, 0x55, 0x10, 0x09]
        );
    }

    #[test]
    fn imsi_is_bare_tbcd_no_leading_octet() {
        // Test PLMN 001/01, MSIN 0123456789 → 15-digit IMSI, trailing 0xF filler.
        assert_eq!(
            imsi("001010123456789").unwrap(),
            vec![0x00, 0x01, 0x01, 0x21, 0x43, 0x65, 0x87, 0xF9]
        );
    }

    #[test]
    fn rejects_out_of_range_nature() {
        assert!(matches!(
            isdn_address_string("15550190", 8, PLAN_ISDN),
            Err(MapError::InvalidAddress(_))
        ));
    }

    #[test]
    fn rejects_out_of_range_plan() {
        assert!(matches!(
            isdn_address_string("15550190", NATURE_INTERNATIONAL, 16),
            Err(MapError::InvalidAddress(_))
        ));
    }

    #[test]
    fn rejects_non_digit() {
        assert!(matches!(
            international_e164("1555x190"),
            Err(MapError::InvalidAddress(_))
        ));
    }
}
