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
    assert gsm_map.OP_MO_FORWARD_SM == 46
    assert gsm_map.OP_MT_FORWARD_SM == 44
    assert gsm_map.OP_REPORT_SM_DELIVERY_STATUS == 47
    assert gsm_map.OP_UPDATE_LOCATION == 2
    assert gsm_map.OP_SEND_AUTHENTICATION_INFO == 56


def test_op_name() -> None:
    assert gsm_map.op_name(45) == "sendRoutingInfoForSM"
    assert gsm_map.op_name(46) == "mo-ForwardSM"
    assert gsm_map.op_name(44) == "mt-ForwardSM"
    assert gsm_map.op_name(47) == "reportSM-DeliveryStatus"
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
