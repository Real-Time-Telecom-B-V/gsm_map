"""Codec parity / round-trip tests for the gsm_map wheel.

These exercise the same Rust ASN.1 BER codec the crate ships, through the Python
surface: ``encode`` must produce wire-correct BER, ``decode`` must recover the
fields, and the operation-code registry must match TS 29.002.

All identifiers are synthetic: fictional ``+1 555 01xx`` addresses (TBCD OCTET
STRING) and the reserved test PLMN ``001/01`` IMSI. No real subscriber data.
"""

from __future__ import annotations

import pytest

import gsm_map

# Synthetic TBCD addresses (byte 0 = TON/NPI, then swapped-nibble digits).
MSISDN = bytes([0x91, 0x51, 0x55, 0x10, 0x00, 0x99, 0xF9])  # +1 555 0100 999
SC_ADDR = bytes([0x91, 0x51, 0x55, 0x10, 0x00])  # +1 555 0100
IMSI = bytes([0x00, 0x10, 0x10, 0x00, 0x00, 0x00, 0x00, 0x01])  # test PLMN 001/01
NODE = bytes([0x91, 0x51, 0x55, 0x10, 0x12, 0x34, 0x56])
TPDU = bytes([0x04, 0x0B, 0x91, 0x51, 0x55, 0x10, 0x00, 0x99, 0xF9]) + bytes(20)


def test_operation_codes() -> None:
    assert gsm_map.OP_SEND_ROUTING_INFO_FOR_SM == 45
    assert gsm_map.OP_ANY_TIME_MODIFICATION == 65
    assert gsm_map.OP_MO_FORWARD_SM == 46
    assert gsm_map.OP_MT_FORWARD_SM == 44
    assert gsm_map.OP_REPORT_SM_DELIVERY_STATUS == 47
    assert gsm_map.OP_UPDATE_LOCATION == 2
    assert gsm_map.OP_SEND_AUTHENTICATION_INFO == 56


def test_op_name() -> None:
    assert gsm_map.op_name(45) == "sendRoutingInfoForSM"
    assert gsm_map.op_name(46) == "mo-forwardSM"
    assert gsm_map.op_name(44) == "mt-forwardSM"
    assert gsm_map.op_name(47) == "reportSM-DeliveryStatus"
    assert gsm_map.op_name(65) == "anyTimeModification"
    assert gsm_map.op_name(70) == "provideSubscriberInfo"
    assert gsm_map.op_name(71) == "anyTimeInterrogation"
    assert gsm_map.op_name(9999) == "unknown"


def test_sri_sm_arg_round_trip() -> None:
    arg = gsm_map.RoutingInfoForSmArg(MSISDN, SC_ADDR, sm_rp_pri=True)
    assert arg.op_code == 45
    wire = arg.encode()
    assert isinstance(wire, bytes)
    assert wire[0] == 0x30  # SEQUENCE

    decoded = gsm_map.RoutingInfoForSmArg.decode(wire)
    assert decoded.msisdn == MSISDN
    assert decoded.service_centre_address == SC_ADDR
    assert decoded.sm_rp_pri is True
    assert decoded.gprs_support_indicator is False
    # re-encoding reproduces the exact bytes
    assert decoded.encode() == wire


def test_sri_sm_arg_gprs_flag() -> None:
    arg = gsm_map.RoutingInfoForSmArg(
        MSISDN, SC_ADDR, sm_rp_pri=False, gprs_support_indicator=True
    )
    decoded = gsm_map.RoutingInfoForSmArg.decode(arg.encode())
    assert decoded.sm_rp_pri is False
    assert decoded.gprs_support_indicator is True


def test_sri_sm_res_round_trip() -> None:
    loc = gsm_map.LocationInfoWithLmsi(NODE, lmsi=bytes([0, 0, 0, 1]))
    res = gsm_map.RoutingInfoForSmRes(IMSI, loc)
    wire = res.encode()

    decoded = gsm_map.RoutingInfoForSmRes.decode(wire)
    assert decoded.imsi == IMSI
    assert decoded.location_info_with_lmsi.network_node_number == NODE
    assert decoded.location_info_with_lmsi.lmsi == bytes([0, 0, 0, 1])
    assert decoded.encode() == wire


def test_mo_forward_sm_round_trip() -> None:
    da = gsm_map.SmRpDa.service_centre(SC_ADDR)
    oa = gsm_map.SmRpOa.msisdn(MSISDN)
    arg = gsm_map.MoForwardSmArg(da, oa, TPDU)
    assert arg.op_code == 46

    decoded = gsm_map.MoForwardSmArg.decode(arg.encode())
    assert decoded.sm_rp_da.kind == "service_centre"
    assert decoded.sm_rp_da.value == SC_ADDR
    assert decoded.sm_rp_oa.kind == "msisdn"
    assert decoded.sm_rp_oa.value == MSISDN
    assert decoded.sm_rp_ui == TPDU


def test_mt_forward_sm_round_trip() -> None:
    da = gsm_map.SmRpDa.imsi(IMSI)
    oa = gsm_map.SmRpOa.service_centre(SC_ADDR)
    arg = gsm_map.MtForwardSmArg(da, oa, TPDU, more_messages_to_send=True)
    assert arg.op_code == 44

    decoded = gsm_map.MtForwardSmArg.decode(arg.encode())
    assert decoded.sm_rp_da.kind == "imsi"
    assert decoded.sm_rp_da.value == IMSI
    assert decoded.sm_rp_oa.kind == "service_centre"
    assert decoded.more_messages_to_send is True
    assert decoded.sm_rp_ui == TPDU


def test_sm_rp_da_no_da() -> None:
    da = gsm_map.SmRpDa.no_sm_rp_da()
    assert da.kind == "no_sm_rp_da"
    assert da.value is None


def test_report_sm_delivery_status_round_trip() -> None:
    arg = gsm_map.ReportSmDeliveryStatusArg(
        MSISDN, SC_ADDR, gsm_map.DELIVERY_OUTCOME_SUCCESSFUL_TRANSFER
    )
    assert arg.op_code == 47
    assert arg.outcome == 2

    decoded = gsm_map.ReportSmDeliveryStatusArg.decode(arg.encode())
    assert decoded.msisdn == MSISDN
    assert decoded.outcome == gsm_map.DELIVERY_OUTCOME_SUCCESSFUL_TRANSFER


def test_report_sm_delivery_status_rejects_bad_outcome() -> None:
    with pytest.raises(gsm_map.MapError):
        gsm_map.ReportSmDeliveryStatusArg(MSISDN, SC_ADDR, 99)


def test_update_location_round_trip() -> None:
    arg = gsm_map.UpdateLocationArg(IMSI, NODE, NODE, lmsi=bytes([0, 0, 0, 1]))
    assert arg.op_code == 2
    decoded = gsm_map.UpdateLocationArg.decode(arg.encode())
    assert decoded.imsi == IMSI


def test_send_authentication_info_round_trip() -> None:
    arg = gsm_map.SendAuthenticationInfoArg(IMSI, 5)
    assert arg.op_code == 56
    decoded = gsm_map.SendAuthenticationInfoArg.decode(arg.encode())
    assert decoded.imsi == IMSI


def test_decode_rejects_garbage() -> None:
    with pytest.raises(gsm_map.MapError):
        gsm_map.RoutingInfoForSmArg.decode(b"\xff\xff\xff")


def test_full_stack_interop_shape() -> None:
    # The Python-encoded MAP argument is exactly what would ride inside a TCAP
    # Invoke parameter: verify it is self-consistent BER that round-trips.
    arg = gsm_map.RoutingInfoForSmArg(MSISDN, SC_ADDR)
    param = arg.encode()
    again = gsm_map.RoutingInfoForSmArg.decode(param)
    assert again.encode() == param


def test_address_encoders() -> None:
    # The encoders reproduce the hand-written TBCD constant above.
    assert gsm_map.international_e164("15550100999") == MSISDN
    assert gsm_map.international_e164("15550190") == bytes([0x91, 0x51, 0x55, 0x10, 0x09])
    # nature/plan default to international E.164.
    assert gsm_map.isdn_address_string("15550190") == gsm_map.international_e164("15550190")
    # national (significant) number → leading 0xA1.
    assert gsm_map.isdn_address_string(
        "15550190", gsm_map.NATURE_NATIONAL, gsm_map.PLAN_ISDN
    ) == bytes([0xA1, 0x51, 0x55, 0x10, 0x09])
    # IMSI is a bare TBCD string, no leading octet.
    assert gsm_map.imsi("001010123456789") == bytes(
        [0x00, 0x01, 0x01, 0x21, 0x43, 0x65, 0x87, 0xF9]
    )
    with pytest.raises(gsm_map.MapError):
        gsm_map.international_e164("1555x190")


# ── anyTimeModification: the IP-SM-GW registration ──────────────────────────

IP_SM_GW_ADDR = bytes([0x91, 0x51, 0x55, 0x10, 0x24])  # +1 555 0142

def _atm(status: int | None = None, **kwargs: object) -> gsm_map.AnyTimeModificationArg:
    return gsm_map.AnyTimeModificationArg(
        gsm_map.SubscriberIdentity.msisdn(MSISDN),
        IP_SM_GW_ADDR,
        modify_registration_status=status,
        **kwargs,  # type: ignore[arg-type]
    )

def test_modification_instruction_values() -> None:
    assert gsm_map.MODIFY_DEACTIVATE == 0
    assert gsm_map.MODIFY_ACTIVATE == 1

def test_ip_sm_gw_registration_round_trip() -> None:
    for status in (gsm_map.MODIFY_ACTIVATE, gsm_map.MODIFY_DEACTIVATE):
        arg = _atm(status)
        assert arg.op_code == 65
        wire = arg.encode()
        assert wire[0] == 0x30

        decoded = gsm_map.AnyTimeModificationArg.decode(wire)
        assert decoded.modify_registration_status == status
        assert decoded.subscriber_identity.kind == "msisdn"
        assert decoded.subscriber_identity.value == MSISDN
        assert decoded.gsm_scf_address == IP_SM_GW_ADDR
        assert decoded.ip_sm_gw_diameter_address is None
        assert decoded.encode() == wire

def test_ip_sm_gw_registration_encodes_at_tag_8() -> None:
    # modificationRequestFor-IP-SM-GW-Data [8] constructed, holding
    # modifyRegistrationStatus [0] primitive with a one-byte value.
    assert bytes([0xA8, 0x03, 0x80, 0x01, 0x01]) in _atm(gsm_map.MODIFY_ACTIVATE).encode()
    assert bytes([0xA8, 0x03, 0x80, 0x01, 0x00]) in _atm(gsm_map.MODIFY_DEACTIVATE).encode()

def test_subscriber_identity_is_an_explicit_choice() -> None:
    # subscriberIdentity is a CHOICE: [0] is explicit, so A0 wraps the msisdn
    # alternative's own [1] tag. An implicit [0] would overwrite it and a peer
    # could not read the identity back.
    wire = _atm(gsm_map.MODIFY_ACTIVATE).encode()
    assert wire[2:6] == bytes([0xA0, 0x09, 0x81, 0x07])

def test_ip_sm_gw_registration_with_a_diameter_address() -> None:
    arg = _atm(
        gsm_map.MODIFY_ACTIVATE,
        ip_sm_gw_diameter_address=gsm_map.NetworkNodeDiameterAddress(
            b"ipsmgw.example.net", b"example.net"
        ),
    )
    decoded = gsm_map.AnyTimeModificationArg.decode(arg.encode())
    address = decoded.ip_sm_gw_diameter_address
    assert address is not None
    assert address.diameter_name == b"ipsmgw.example.net"
    assert address.diameter_realm == b"example.net"

def test_any_time_modification_without_a_registration() -> None:
    decoded = gsm_map.AnyTimeModificationArg.decode(_atm().encode())
    assert decoded.modify_registration_status is None
    assert decoded.ip_sm_gw_diameter_address is None

def test_any_time_modification_rejects_a_bad_instruction() -> None:
    with pytest.raises(gsm_map.MapError):
        _atm(7)

def test_subscriber_identity_by_imsi() -> None:
    arg = gsm_map.AnyTimeModificationArg(
        gsm_map.SubscriberIdentity.imsi(IMSI),
        IP_SM_GW_ADDR,
        modify_registration_status=gsm_map.MODIFY_ACTIVATE,
    )
    decoded = gsm_map.AnyTimeModificationArg.decode(arg.encode())
    assert decoded.subscriber_identity.kind == "imsi"
    assert decoded.subscriber_identity.value == IMSI

# ── SRI-SM response members a real HLR sends ────────────────────────────────

def test_additional_number_is_a_choice() -> None:
    loc = gsm_map.LocationInfoWithLmsi(
        NODE, additional_number=gsm_map.AdditionalNumber.sgsn_number(NODE)
    )
    res = gsm_map.RoutingInfoForSmRes(IMSI, loc)
    decoded = gsm_map.RoutingInfoForSmRes.decode(res.encode())
    additional = decoded.location_info_with_lmsi.additional_number
    assert additional is not None
    assert additional.kind == "sgsn_number"
    assert additional.value == NODE

def test_serving_node_diameter_address() -> None:
    loc = gsm_map.LocationInfoWithLmsi(
        NODE,
        network_node_diameter_address=gsm_map.NetworkNodeDiameterAddress(
            b"msc.example.net", b"example.net"
        ),
    )
    res = gsm_map.RoutingInfoForSmRes(IMSI, loc)
    decoded = gsm_map.RoutingInfoForSmRes.decode(res.encode())
    address = decoded.location_info_with_lmsi.network_node_diameter_address
    assert address is not None
    assert address.diameter_realm == b"example.net"

def test_sri_sm_response_tolerates_an_extension_container() -> None:
    # A real HLR commonly appends [4] extensionContainer. BER decoding is not
    # tolerant of unmodelled members, so this has to be modelled for the whole
    # response to decode at all.
    res = gsm_map.RoutingInfoForSmRes(IMSI, gsm_map.LocationInfoWithLmsi(NODE))
    wire = bytearray(res.encode())
    extension_container = bytes(
        [0xA4, 0x0C, 0xA0, 0x0A, 0x30, 0x08, 0x06, 0x06, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D]
    )
    assert wire[1] < 0x80  # short-form length
    wire[1] += len(extension_container)
    wire.extend(extension_container)

    decoded = gsm_map.RoutingInfoForSmRes.decode(bytes(wire))
    assert decoded.imsi == IMSI


# ── The rest of the SMS operation set ───────────────────────────────────────

def test_ready_for_sm_round_trip() -> None:
    arg = gsm_map.ReadyForSmArg(
        IMSI,
        gsm_map.ALERT_MEMORY_AVAILABLE,
        alert_reason_indicator=True,
        maximum_ue_availability_time=bytes([0x22, 0x01]),
    )
    assert arg.op_code == 66
    wire = arg.encode()
    # imsi carries context tag [0], not the universal OCTET STRING tag.
    assert wire[2] == 0x80

    decoded = gsm_map.ReadyForSmArg.decode(wire)
    assert decoded.imsi == IMSI
    assert decoded.alert_reason == gsm_map.ALERT_MEMORY_AVAILABLE
    assert decoded.maximum_ue_availability_time == bytes([0x22, 0x01])
    assert decoded.encode() == wire

def test_ready_for_sm_rejects_a_bad_alert_reason() -> None:
    with pytest.raises(gsm_map.MapError):
        gsm_map.ReadyForSmArg(IMSI, 7)

def test_alert_service_centre_round_trip() -> None:
    arg = gsm_map.AlertServiceCentreArg(MSISDN, SC_ADDR, imsi=IMSI, new_msc_number=NODE)
    assert arg.op_code == 64
    decoded = gsm_map.AlertServiceCentreArg.decode(arg.encode())
    assert decoded.msisdn == MSISDN
    assert decoded.imsi == IMSI
    assert decoded.new_msc_number == NODE

def test_inform_service_centre_mw_status_is_a_bit_string() -> None:
    arg = gsm_map.InformServiceCentreArg(
        stored_msisdn=MSISDN, mnrf_set=True, mcef_set=True,
        absent_subscriber_diagnostic_sm=5,
    )
    assert arg.op_code == 63
    wire = arg.encode()
    decoded = gsm_map.InformServiceCentreArg.decode(wire)
    assert decoded.stored_msisdn == MSISDN
    assert decoded.mw_status == {
        "sc_address_not_included": False,
        "mnrf_set": True,
        "mcef_set": True,
        "mnrg_set": False,
        "mnr5g_set": False,
        "mnr5gn3g_set": False,
    }
    assert decoded.absent_subscriber_diagnostic_sm == 5
    # No flags set at all means no mw-Status member.
    assert gsm_map.InformServiceCentreArg().mw_status is None

def test_registries_are_complete_and_agree_with_the_lookups() -> None:
    # Every MAP operation and error the crate knows, as name -> code.
    assert gsm_map.OPERATIONS["sendRoutingInfoForSM"] == 45
    assert gsm_map.OPERATIONS["anyTimeModification"] == 65
    assert gsm_map.OPERATIONS["mt-forwardSM"] == 44
    assert len(gsm_map.OPERATIONS) > 90
    for name, code in gsm_map.OPERATIONS.items():
        assert gsm_map.op_name(code) == name

    assert gsm_map.ERRORS["atm-NotAllowed"] == 61
    assert gsm_map.ERRORS["absentSubscriberSM"] == 6
    for name, code in gsm_map.ERRORS.items():
        assert gsm_map.error_name(code) == name

def test_error_name() -> None:
    assert gsm_map.error_name(61) == "atm-NotAllowed"
    assert gsm_map.error_name(32) == "sm-DeliveryFailure"
    assert gsm_map.error_name(9999) == "unknown"


# ── Strict decoding ─────────────────────────────────────────────────────────
#
# The vectors are written by hand from TS 29.002; tests/decoder_strictness.rs
# and tests/extensibility.rs have the derivations.

SRI_SM_RES_SECOND_NODE_UNREADABLE = bytes.fromhex(
    "3020040800010121436587f9"
    "a0148107915155100010f0"
    "a6098507915155100020f0"  # additional-Number [6] holding [5]: not an alternative
)

SRI_SM_ARG = bytes.fromhex("30138007915155100099f98101ff82059151551099")


def test_a_member_that_cannot_be_read_is_an_error_not_absent() -> None:
    # rasn alone decodes this with the second serving node missing.
    with pytest.raises(gsm_map.MapError):
        gsm_map.RoutingInfoForSmRes.decode(SRI_SM_RES_SECOND_NODE_UNREADABLE)


def test_octets_after_the_value_are_an_error() -> None:
    assert gsm_map.RoutingInfoForSmArg.decode(SRI_SM_ARG).sm_rp_pri is True
    with pytest.raises(gsm_map.MapError):
        gsm_map.RoutingInfoForSmArg.decode(SRI_SM_ARG + b"\x05\x00")


def test_an_extension_addition_from_a_later_release_is_skipped() -> None:
    # [30] after the last member Rel-18 defines; the length grows by three.
    extended = bytes([0x30, 0x16]) + SRI_SM_ARG[2:] + bytes.fromhex("9e012a")
    decoded = gsm_map.RoutingInfoForSmArg.decode(extended)
    assert decoded.sm_rp_pri is True
    # What this crate does not model is not carried along.
    assert decoded.encode() == SRI_SM_ARG


def test_a_repeated_member_is_an_error() -> None:
    # gprsSupportIndicator [7] twice.
    repeated = bytes([0x30, 0x17]) + SRI_SM_ARG[2:] + bytes.fromhex("87008700")
    with pytest.raises(gsm_map.MapError):
        gsm_map.RoutingInfoForSmArg.decode(repeated)
