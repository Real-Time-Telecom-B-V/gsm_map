"""Type stubs for the Rust-backed ``gsm_map._gsm_map`` extension module."""

from __future__ import annotations

# ── Operation codes (3GPP TS 29.002) ─────────────────────────────────────────
OP_SEND_ROUTING_INFO_FOR_SM: int
OP_MO_FORWARD_SM: int
OP_MT_FORWARD_SM: int
OP_REPORT_SM_DELIVERY_STATUS: int
OP_ALERT_SERVICE_CENTRE: int
OP_INFORM_SERVICE_CENTRE: int
OP_READY_FOR_SM: int
OP_UPDATE_LOCATION: int
OP_SEND_AUTHENTICATION_INFO: int

# ── SM-DeliveryOutcome values ────────────────────────────────────────────────
DELIVERY_OUTCOME_MEMORY_CAPACITY_EXCEEDED: int
DELIVERY_OUTCOME_ABSENT_SUBSCRIBER: int
DELIVERY_OUTCOME_SUCCESSFUL_TRANSFER: int

class MapError(Exception):
    """GSM MAP protocol / BER codec error (3GPP TS 29.002)."""

def op_name(op_code: int) -> str:
    """The MAP operation name for an operation code (e.g. 45 -> 'sendRoutingInfoForSM')."""

class SmRpDa:
    """SM-RP-DA — SMS Relay Protocol Destination Address (a CHOICE).

    Build with the staticmethods; inspect via ``.kind`` and ``.value``.
    """

    @staticmethod
    def imsi(value: bytes) -> SmRpDa: ...
    @staticmethod
    def lmsi(value: bytes) -> SmRpDa: ...
    @staticmethod
    def service_centre(value: bytes) -> SmRpDa: ...
    @staticmethod
    def no_sm_rp_da() -> SmRpDa: ...
    @property
    def kind(self) -> str:
        """One of 'imsi', 'lmsi', 'service_centre', 'no_sm_rp_da'."""
    @property
    def value(self) -> bytes | None:
        """The carried OCTET STRING, or None for 'no_sm_rp_da'."""

class SmRpOa:
    """SM-RP-OA — SMS Relay Protocol Originating Address (a CHOICE)."""

    @staticmethod
    def msisdn(value: bytes) -> SmRpOa: ...
    @staticmethod
    def service_centre(value: bytes) -> SmRpOa: ...
    @staticmethod
    def no_sm_rp_oa() -> SmRpOa: ...
    @property
    def kind(self) -> str:
        """One of 'msisdn', 'service_centre', 'no_sm_rp_oa'."""
    @property
    def value(self) -> bytes | None:
        """The carried OCTET STRING, or None for 'no_sm_rp_oa'."""

class LocationInfoWithLmsi:
    """The serving-node routing info returned by SRI-SM."""

    def __init__(
        self,
        network_node_number: bytes,
        *,
        lmsi: bytes | None = None,
        gprs_node_indicator: bool = False,
        additional_number: bytes | None = None,
    ) -> None: ...
    @property
    def network_node_number(self) -> bytes: ...
    @property
    def lmsi(self) -> bytes | None: ...
    @property
    def gprs_node_indicator(self) -> bool: ...
    @property
    def additional_number(self) -> bytes | None: ...

class RoutingInfoForSmArg:
    """sendRoutingInfoForSM-Arg (op 45) — the SMS-GMSC's query to the HLR."""

    def __init__(
        self,
        msisdn: bytes,
        service_centre_address: bytes,
        *,
        sm_rp_pri: bool = True,
        gprs_support_indicator: bool = False,
        sm_rp_mti: int | None = None,
    ) -> None: ...
    @property
    def msisdn(self) -> bytes: ...
    @property
    def service_centre_address(self) -> bytes: ...
    @property
    def sm_rp_pri(self) -> bool: ...
    @property
    def gprs_support_indicator(self) -> bool: ...
    @property
    def op_code(self) -> int: ...
    def encode(self) -> bytes:
        """BER-encode to the TCAP Invoke parameter bytes."""
    @staticmethod
    def decode(data: bytes) -> RoutingInfoForSmArg: ...

class RoutingInfoForSmRes:
    """sendRoutingInfoForSM-Res (op 45) — the HLR's answer: IMSI + serving node."""

    def __init__(
        self, imsi: bytes, location_info_with_lmsi: LocationInfoWithLmsi
    ) -> None: ...
    @property
    def imsi(self) -> bytes: ...
    @property
    def location_info_with_lmsi(self) -> LocationInfoWithLmsi: ...
    def encode(self) -> bytes: ...
    @staticmethod
    def decode(data: bytes) -> RoutingInfoForSmRes: ...

class MoForwardSmArg:
    """mo-ForwardSM-Arg (op 46) — mobile-originated SMS, MSC → SMS-IWMSC."""

    def __init__(
        self,
        sm_rp_da: SmRpDa,
        sm_rp_oa: SmRpOa,
        sm_rp_ui: bytes,
        *,
        imsi: bytes | None = None,
    ) -> None: ...
    @property
    def sm_rp_da(self) -> SmRpDa: ...
    @property
    def sm_rp_oa(self) -> SmRpOa: ...
    @property
    def sm_rp_ui(self) -> bytes:
        """The raw TPDU (an SMS-SUBMIT)."""
    @property
    def op_code(self) -> int: ...
    def encode(self) -> bytes: ...
    @staticmethod
    def decode(data: bytes) -> MoForwardSmArg: ...

class MtForwardSmArg:
    """mt-ForwardSM-Arg (op 44) — mobile-terminated SMS, SMS-GMSC → serving MSC."""

    def __init__(
        self,
        sm_rp_da: SmRpDa,
        sm_rp_oa: SmRpOa,
        sm_rp_ui: bytes,
        *,
        more_messages_to_send: bool | None = None,
    ) -> None: ...
    @property
    def sm_rp_da(self) -> SmRpDa: ...
    @property
    def sm_rp_oa(self) -> SmRpOa: ...
    @property
    def sm_rp_ui(self) -> bytes:
        """The raw TPDU (an SMS-DELIVER)."""
    @property
    def more_messages_to_send(self) -> bool | None: ...
    @property
    def op_code(self) -> int: ...
    def encode(self) -> bytes: ...
    @staticmethod
    def decode(data: bytes) -> MtForwardSmArg: ...

class ReportSmDeliveryStatusArg:
    """reportSM-DeliveryStatus-Arg (op 47) — SMS-GMSC → HLR delivery report.

    ``outcome`` is one of the ``DELIVERY_OUTCOME_*`` module constants.
    """

    def __init__(
        self, msisdn: bytes, service_centre_address: bytes, outcome: int
    ) -> None: ...
    @property
    def msisdn(self) -> bytes: ...
    @property
    def service_centre_address(self) -> bytes: ...
    @property
    def outcome(self) -> int: ...
    @property
    def op_code(self) -> int: ...
    def encode(self) -> bytes: ...
    @staticmethod
    def decode(data: bytes) -> ReportSmDeliveryStatusArg: ...

class UpdateLocationArg:
    """updateLocation-Arg (op 2) — VLR → HLR location update."""

    def __init__(
        self,
        imsi: bytes,
        msc_number: bytes,
        vlr_number: bytes,
        *,
        lmsi: bytes | None = None,
    ) -> None: ...
    @property
    def imsi(self) -> bytes: ...
    @property
    def op_code(self) -> int: ...
    def encode(self) -> bytes: ...
    @staticmethod
    def decode(data: bytes) -> UpdateLocationArg: ...

class SendAuthenticationInfoArg:
    """sendAuthenticationInfo-Arg (op 56) — VLR/SGSN → HLR auth-vector request."""

    def __init__(self, imsi: bytes, number_of_requested_vectors: int) -> None: ...
    @property
    def imsi(self) -> bytes: ...
    @property
    def op_code(self) -> int: ...
    def encode(self) -> bytes: ...
    @staticmethod
    def decode(data: bytes) -> SendAuthenticationInfoArg: ...
