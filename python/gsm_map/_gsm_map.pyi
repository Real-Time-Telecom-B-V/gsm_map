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
OP_ANY_TIME_MODIFICATION: int

# ── AlertReason values (readyForSM) ──────────────────────────────────────────
ALERT_MS_PRESENT: int
ALERT_MEMORY_AVAILABLE: int

# ── The full registries, as name -> code maps ────────────────────────────────
OPERATIONS: dict[str, int]
ERRORS: dict[str, int]

# ── ModificationInstruction values (the IP-SM-GW registration) ───────────────
MODIFY_DEACTIVATE: int
MODIFY_ACTIVATE: int

# ── SM-DeliveryOutcome values ────────────────────────────────────────────────
DELIVERY_OUTCOME_MEMORY_CAPACITY_EXCEEDED: int
DELIVERY_OUTCOME_ABSENT_SUBSCRIBER: int
DELIVERY_OUTCOME_SUCCESSFUL_TRANSFER: int

# ── Address / identity nature-of-address + numbering-plan values ──────────────
NATURE_INTERNATIONAL: int
NATURE_NATIONAL: int
PLAN_ISDN: int
PLAN_LAND_MOBILE: int

class MapError(Exception):
    """GSM MAP protocol / BER codec error (3GPP TS 29.002)."""

def op_name(op_code: int) -> str:
    """The MAP operation name for an operation code (e.g. 45 -> 'sendRoutingInfoForSM')."""

def error_name(error_code: int) -> str:
    """The MAP error name for an error code (e.g. 61 -> 'atm-NotAllowed')."""

def isdn_address_string(
    digits: str, nature: int = ..., plan: int = ...
) -> bytes:
    """Encode an ISDN-AddressString / AddressString: the nature-of-address /
    numbering-plan octet then TBCD digits. Defaults to international E.164."""

def international_e164(digits: str) -> bytes:
    """Encode an international E.164 ISDN number (leading octet 0x91)."""

def imsi(digits: str) -> bytes:
    """Encode an IMSI as a bare TBCD-STRING (no leading octet)."""

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

class AdditionalNumber:
    """Additional-Number — the second serving node in a LocationInfoWithLmsi
    (a CHOICE). Build with the staticmethods; inspect via ``.kind``/``.value``.
    """

    @staticmethod
    def msc_number(value: bytes) -> AdditionalNumber: ...
    @staticmethod
    def sgsn_number(value: bytes) -> AdditionalNumber: ...
    @property
    def kind(self) -> str:
        """One of 'msc_number', 'sgsn_number'."""
    @property
    def value(self) -> bytes:
        """The carried ISDN-AddressString."""

class NetworkNodeDiameterAddress:
    """A node reached over Diameter (SGd/S6c) rather than MAP: a Diameter Name
    and Realm, each a DiameterIdentity per RFC 6733.
    """

    def __init__(self, diameter_name: bytes, diameter_realm: bytes) -> None: ...
    @property
    def diameter_name(self) -> bytes: ...
    @property
    def diameter_realm(self) -> bytes: ...

class SubscriberIdentity:
    """SubscriberIdentity — how an any-time operation names the subscriber
    (a CHOICE). Build with the staticmethods.
    """

    @staticmethod
    def imsi(value: bytes) -> SubscriberIdentity: ...
    @staticmethod
    def msisdn(value: bytes) -> SubscriberIdentity: ...
    @property
    def kind(self) -> str:
        """One of 'imsi', 'msisdn'."""
    @property
    def value(self) -> bytes: ...

class LocationInfoWithLmsi:
    """The serving-node routing info returned by SRI-SM."""

    def __init__(
        self,
        network_node_number: bytes,
        *,
        lmsi: bytes | None = None,
        gprs_node_indicator: bool = False,
        additional_number: AdditionalNumber | None = None,
        network_node_diameter_address: NetworkNodeDiameterAddress | None = None,
    ) -> None: ...
    @property
    def network_node_number(self) -> bytes: ...
    @property
    def lmsi(self) -> bytes | None: ...
    @property
    def gprs_node_indicator(self) -> bool: ...
    @property
    def additional_number(self) -> AdditionalNumber | None: ...
    @property
    def network_node_diameter_address(self) -> NetworkNodeDiameterAddress | None: ...

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

class AnyTimeModificationArg:
    """anyTimeModification-Arg (op 65) — register or de-register a node as the
    MT-SMS routing node for a subscriber.

    ``modify_registration_status`` is ``MODIFY_ACTIVATE`` to register and
    ``MODIFY_DEACTIVATE`` to de-register. The registering node's own address is
    ``gsm_scf_address``: an IP-SM-GW acts in the gsmSCF role towards the HLR for
    this dialogue, and that is the address the HLR then hands out in
    ``RoutingInfoForSmRes``.
    """

    def __init__(
        self,
        subscriber_identity: SubscriberIdentity,
        gsm_scf_address: bytes,
        *,
        modify_registration_status: int | None = None,
        ip_sm_gw_diameter_address: NetworkNodeDiameterAddress | None = None,
        long_ftn_supported: bool = False,
    ) -> None: ...
    @property
    def subscriber_identity(self) -> SubscriberIdentity: ...
    @property
    def gsm_scf_address(self) -> bytes: ...
    @property
    def modify_registration_status(self) -> int | None: ...
    @property
    def ip_sm_gw_diameter_address(self) -> NetworkNodeDiameterAddress | None: ...
    @property
    def long_ftn_supported(self) -> bool: ...
    @property
    def op_code(self) -> int: ...
    def encode(self) -> bytes: ...
    @staticmethod
    def decode(data: bytes) -> AnyTimeModificationArg: ...

class ReadyForSmArg:
    """readyForSM-Arg (op 66) — the serving node telling the HLR a subscriber
    became reachable or freed memory. This is the MAP form of Alert-SC.

    ``alert_reason`` is ``ALERT_MS_PRESENT`` or ``ALERT_MEMORY_AVAILABLE``.
    """

    def __init__(
        self,
        imsi: bytes,
        alert_reason: int,
        *,
        alert_reason_indicator: bool = False,
        additional_alert_reason_indicator: bool = False,
        maximum_ue_availability_time: bytes | None = None,
    ) -> None: ...
    @property
    def imsi(self) -> bytes: ...
    @property
    def alert_reason(self) -> int: ...
    @property
    def maximum_ue_availability_time(self) -> bytes | None: ...
    @property
    def op_code(self) -> int: ...
    def encode(self) -> bytes: ...
    @staticmethod
    def decode(data: bytes) -> ReadyForSmArg: ...

class AlertServiceCentreArg:
    """alertServiceCentre-Arg (op 64) — the HLR telling a service centre a
    subscriber is reachable again, so it can drain its queue.
    """

    def __init__(
        self,
        msisdn: bytes,
        service_centre_address: bytes,
        *,
        imsi: bytes | None = None,
        new_msc_number: bytes | None = None,
        new_sgsn_number: bytes | None = None,
        new_mme_number: bytes | None = None,
    ) -> None: ...
    @property
    def msisdn(self) -> bytes: ...
    @property
    def service_centre_address(self) -> bytes: ...
    @property
    def imsi(self) -> bytes | None: ...
    @property
    def new_msc_number(self) -> bytes | None: ...
    @property
    def op_code(self) -> int: ...
    def encode(self) -> bytes: ...
    @staticmethod
    def decode(data: bytes) -> AlertServiceCentreArg: ...

class InformServiceCentreArg:
    """informServiceCentre-Arg (op 63) — what the HLR already knows about the
    subscriber's message-waiting state.

    ``mw_status`` is a BIT STRING on the wire; pass the flags as keyword
    booleans and read them back as a dict.
    """

    def __init__(
        self,
        *,
        stored_msisdn: bytes | None = None,
        sc_address_not_included: bool = False,
        mnrf_set: bool = False,
        mcef_set: bool = False,
        mnrg_set: bool = False,
        mnr5g_set: bool = False,
        mnr5gn3g_set: bool = False,
        absent_subscriber_diagnostic_sm: int | None = None,
    ) -> None: ...
    @property
    def stored_msisdn(self) -> bytes | None: ...
    @property
    def mw_status(self) -> dict[str, bool] | None: ...
    @property
    def absent_subscriber_diagnostic_sm(self) -> int | None: ...
    @property
    def op_code(self) -> int: ...
    def encode(self) -> bytes: ...
    @staticmethod
    def decode(data: bytes) -> InformServiceCentreArg: ...
