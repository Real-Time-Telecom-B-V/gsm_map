"""gsm_map — Rust-backed GSM MAP (3GPP TS 29.002) SMS operation codec for Python.

GSM MAP (Mobile Application Part) is the SS7 application layer that carries HLR/VLR
mobility, authentication, and — the primary use here — **SMS** signalling
(``sendRoutingInfoForSM``, ``mo-ForwardSM``, ``mt-ForwardSM``,
``reportSM-DeliveryStatus``). This package exposes the same ASN.1 BER codec the Rust
crate (``cargo add gsm_map``) ships, from one source tree / one version.

Each operation is a small class with ``.encode() -> bytes`` (the TCAP Invoke
parameter, BER-encoded) and a ``.decode(bytes)`` classmethod. Addresses and
identities are passed and returned as ``bytes`` — TBCD in an OCTET STRING (byte 0 =
TON/NPI, then swapped-nibble digits). All examples use synthetic ``+1 555 01xx``
numbers and the reserved test PLMN ``001/01`` IMSI.

The BER pack/unpack runs in Rust (via ``rasn``); Python just builds and inspects the
typed operations.
"""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version

from ._gsm_map import (
    DELIVERY_OUTCOME_ABSENT_SUBSCRIBER,
    DELIVERY_OUTCOME_MEMORY_CAPACITY_EXCEEDED,
    DELIVERY_OUTCOME_SUCCESSFUL_TRANSFER,
    ALERT_MEMORY_AVAILABLE,
    ALERT_MS_PRESENT,
    ERRORS,
    MODIFY_ACTIVATE,
    MODIFY_DEACTIVATE,
    OPERATIONS,
    NATURE_INTERNATIONAL,
    NATURE_NATIONAL,
    OP_ALERT_SERVICE_CENTRE,
    OP_ANY_TIME_MODIFICATION,
    OP_INFORM_SERVICE_CENTRE,
    OP_MO_FORWARD_SM,
    OP_MT_FORWARD_SM,
    OP_READY_FOR_SM,
    OP_REPORT_SM_DELIVERY_STATUS,
    OP_SEND_AUTHENTICATION_INFO,
    OP_SEND_ROUTING_INFO_FOR_SM,
    OP_UPDATE_LOCATION,
    PLAN_ISDN,
    PLAN_LAND_MOBILE,
    AdditionalNumber,
    AlertServiceCentreArg,
    AnyTimeModificationArg,
    InformServiceCentreArg,
    LocationInfoWithLmsi,
    MapError,
    MoForwardSmArg,
    MtForwardSmArg,
    NetworkNodeDiameterAddress,
    ReportSmDeliveryStatusArg,
    RoutingInfoForSmArg,
    RoutingInfoForSmRes,
    SendAuthenticationInfoArg,
    ReadyForSmArg,
    SmRpDa,
    SmRpOa,
    SubscriberIdentity,
    UpdateLocationArg,
    error_name,
    imsi,
    international_e164,
    isdn_address_string,
    op_name,
)

try:
    __version__ = version("gsm_map")
except PackageNotFoundError:  # source checkout without an installed dist
    __version__ = "0.0.0+unknown"

__all__ = [
    # SMS operations
    "RoutingInfoForSmArg",
    "RoutingInfoForSmRes",
    "MoForwardSmArg",
    "MtForwardSmArg",
    "ReportSmDeliveryStatusArg",
    "ReadyForSmArg",
    "AlertServiceCentreArg",
    "InformServiceCentreArg",
    # mobility / auth
    "UpdateLocationArg",
    "SendAuthenticationInfoArg",
    # subscriber-data modification (the IP-SM-GW registration)
    "AnyTimeModificationArg",
    # shared address / identity types
    "SmRpDa",
    "SmRpOa",
    "SubscriberIdentity",
    "AdditionalNumber",
    "NetworkNodeDiameterAddress",
    "LocationInfoWithLmsi",
    # errors + helpers
    "MapError",
    "op_name",
    "error_name",
    "OPERATIONS",
    "ERRORS",
    # address / identity encoders
    "isdn_address_string",
    "international_e164",
    "imsi",
    "NATURE_INTERNATIONAL",
    "NATURE_NATIONAL",
    "PLAN_ISDN",
    "PLAN_LAND_MOBILE",
    # operation codes
    "OP_SEND_ROUTING_INFO_FOR_SM",
    "OP_MO_FORWARD_SM",
    "OP_MT_FORWARD_SM",
    "OP_REPORT_SM_DELIVERY_STATUS",
    "OP_ALERT_SERVICE_CENTRE",
    "OP_INFORM_SERVICE_CENTRE",
    "OP_READY_FOR_SM",
    "OP_UPDATE_LOCATION",
    "OP_SEND_AUTHENTICATION_INFO",
    "OP_ANY_TIME_MODIFICATION",
    # ModificationInstruction values
    "MODIFY_DEACTIVATE",
    "MODIFY_ACTIVATE",
    # AlertReason values
    "ALERT_MS_PRESENT",
    "ALERT_MEMORY_AVAILABLE",
    # SM-DeliveryOutcome values
    "DELIVERY_OUTCOME_MEMORY_CAPACITY_EXCEEDED",
    "DELIVERY_OUTCOME_ABSENT_SUBSCRIBER",
    "DELIVERY_OUTCOME_SUCCESSFUL_TRANSFER",
    "__version__",
]
