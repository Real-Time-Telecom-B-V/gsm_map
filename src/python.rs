//! PyO3 bindings — `pip install gsm_map` gives a Rust-backed wheel exposing the
//! **same** GSM MAP (3GPP TS 29.002) ASN.1 codec the crate ships.
//!
//! Compiled only with `--features python`; the default crate build is pyo3-free, so
//! `cargo add gsm_map` / crates.io consumers pull zero pyo3. Two entry points share
//! one `add_contents()`:
//! * `#[pymodule] fn _gsm_map` — the standalone wheel (maturin `module-name`).
//! * `pub fn register(py, parent)` — mount `gsm_map` as a submodule of another
//!   extension, so a host (e.g. an SS7 stack binary) can expose gsm_map without a
//!   second shared object.
//!
//! The surface covers the **SMS operation set** — the primary MAP use — plus the
//! shared address/identity types and the operation-code registry:
//!
//! * `RoutingInfoForSmArg` / `RoutingInfoForSmRes`  (sendRoutingInfoForSM, op 45)
//! * `MoForwardSmArg`                                (mo-ForwardSM,        op 46)
//! * `MtForwardSmArg`                                (mt-ForwardSM,        op 44)
//! * `ReportSmDeliveryStatusArg`                     (reportSM-DeliveryStatus, op 47)
//! * shared: `SmRpDa`, `SmRpOa`, `LocationInfoWithLmsi`
//! * a couple of mobility/auth ops: `UpdateLocationArg`, `SendAuthenticationInfoArg`
//! * `AnyTimeModificationArg` (op 65) — the IP-SM-GW registration: how a node
//!   makes itself the MT-SMS routing node for a subscriber, plus the
//!   `SubscriberIdentity` / `AdditionalNumber` / `NetworkNodeDiameterAddress`
//!   types it and the SRI-SM response need
//! * `op_codes` (int constants) + `operation_name(code)`
//!
//! Every operation class has `.encode() -> bytes` (BER) and a `decode(bytes)`
//! classmethod that returns the typed object. Addresses/identities are passed and
//! returned as raw `bytes` (TBCD in an OCTET STRING: byte 0 = TON/NPI, then the
//! swapped-nibble digits) — synthetic `+1 555 01xx` numbers in all examples/tests.

use pyo3::create_exception;
use pyo3::exceptions::PyException;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyModule};

use crate::operations::alert_sc::AlertServiceCentreArg;
use crate::operations::auth::SendAuthenticationInfoArg;
use crate::operations::inform_sc::InformServiceCentreArg;
use crate::operations::location::UpdateLocationArg;
use crate::operations::mo_forward_sm::MoForwardSmArg;
use crate::operations::mt_forward_sm::MtForwardSmArg;
use crate::operations::ready_for_sm::{AlertReason, ReadyForSmArg};
use crate::operations::report_sm::{ReportSmDeliveryStatusArg, SmDeliveryOutcome};
use crate::operations::sri_sm::{RoutingInfoForSmArg, RoutingInfoForSmRes};
use crate::operations::subscriber_info::{
    AnyTimeModificationArg, ModificationInstruction, ModificationRequestForIpSmGwData,
    SubscriberIdentity,
};
use crate::types::{
    op_codes, operation_name, AdditionalNumber, LocationInfoWithLmsi, NetworkNodeDiameterAddress,
    SmRpDa, SmRpOa,
};

// ── Error mapping ───────────────────────────────────────────────────────────
create_exception!(
    gsm_map,
    MapError,
    PyException,
    "GSM MAP protocol / BER codec error (3GPP TS 29.002)."
);

fn encode_err(e: rasn::error::EncodeError) -> PyErr {
    MapError::new_err(format!("BER encode error: {e}"))
}

fn ber_encode<T: rasn::Encode>(val: &T, py: Python<'_>) -> PyResult<Py<PyBytes>> {
    let bytes = rasn::ber::encode(val).map_err(encode_err)?;
    Ok(PyBytes::new(py, &bytes).unbind())
}

/// Decode through the crate's own decoder, never through `rasn` directly: a
/// member or list element that is on the wire and cannot be read raises
/// `MapError` instead of coming back as absent, as do octets after the value.
/// Extension additions this crate does not model are skipped, as TS 29.002
/// 17.1.4 requires.
fn ber_decode<T: rasn::Decode>(data: &[u8]) -> PyResult<T> {
    crate::decode(data).map_err(|error| MapError::new_err(error.to_string()))
}

// ── Shared address / identity types ─────────────────────────────────────────

/// SM-RP-DA — SMS Relay Protocol Destination Address (a CHOICE).
///
/// Construct via the classmethods (`SmRpDa.imsi(...)`, `.service_centre(...)`,
/// `.no_sm_rp_da()`); inspect via `.kind` and `.value`.
#[pyclass(name = "SmRpDa", module = "gsm_map._gsm_map", from_py_object)]
#[derive(Clone)]
pub struct PySmRpDa {
    inner: SmRpDa,
}

#[pymethods]
impl PySmRpDa {
    /// Destination is an IMSI (TBCD OCTET STRING).
    #[staticmethod]
    fn imsi(value: Vec<u8>) -> Self {
        Self {
            inner: SmRpDa::Imsi(value.into()),
        }
    }

    /// Destination is an LMSI (4-byte OCTET STRING).
    #[staticmethod]
    fn lmsi(value: Vec<u8>) -> Self {
        Self {
            inner: SmRpDa::Lmsi(value.into()),
        }
    }

    /// Destination is a service-centre AddressString.
    #[staticmethod]
    fn service_centre(value: Vec<u8>) -> Self {
        Self {
            inner: SmRpDa::ServiceCentreAddressDa(value.into()),
        }
    }

    /// No SM-RP-DA present.
    #[staticmethod]
    fn no_sm_rp_da() -> Self {
        Self {
            inner: SmRpDa::NoSmRpDa(()),
        }
    }

    /// Discriminant name: `"imsi" | "lmsi" | "service_centre" | "no_sm_rp_da"`.
    #[getter]
    fn kind(&self) -> &'static str {
        match self.inner {
            SmRpDa::Imsi(_) => "imsi",
            SmRpDa::Lmsi(_) => "lmsi",
            SmRpDa::ServiceCentreAddressDa(_) => "service_centre",
            SmRpDa::NoSmRpDa(()) => "no_sm_rp_da",
        }
    }

    /// The carried OCTET STRING, or `None` for `no_sm_rp_da`.
    #[getter]
    fn value<'py>(&self, py: Python<'py>) -> Option<Bound<'py, PyBytes>> {
        match &self.inner {
            SmRpDa::Imsi(v) | SmRpDa::Lmsi(v) | SmRpDa::ServiceCentreAddressDa(v) => {
                Some(PyBytes::new(py, v))
            }
            SmRpDa::NoSmRpDa(()) => None,
        }
    }

    fn __repr__(&self) -> String {
        format!("SmRpDa({})", self.inner)
    }
}

/// SM-RP-OA — SMS Relay Protocol Originating Address (a CHOICE).
#[pyclass(name = "SmRpOa", module = "gsm_map._gsm_map", from_py_object)]
#[derive(Clone)]
pub struct PySmRpOa {
    inner: SmRpOa,
}

#[pymethods]
impl PySmRpOa {
    /// Originator is an MSISDN (ISDN-AddressString).
    #[staticmethod]
    fn msisdn(value: Vec<u8>) -> Self {
        Self {
            inner: SmRpOa::MsIsdn(value.into()),
        }
    }

    /// Originator is a service-centre AddressString.
    #[staticmethod]
    fn service_centre(value: Vec<u8>) -> Self {
        Self {
            inner: SmRpOa::ServiceCentreAddressOa(value.into()),
        }
    }

    /// No SM-RP-OA present.
    #[staticmethod]
    fn no_sm_rp_oa() -> Self {
        Self {
            inner: SmRpOa::NoSmRpOa(()),
        }
    }

    /// Discriminant name: `"msisdn" | "service_centre" | "no_sm_rp_oa"`.
    #[getter]
    fn kind(&self) -> &'static str {
        match self.inner {
            SmRpOa::MsIsdn(_) => "msisdn",
            SmRpOa::ServiceCentreAddressOa(_) => "service_centre",
            SmRpOa::NoSmRpOa(()) => "no_sm_rp_oa",
        }
    }

    /// The carried OCTET STRING, or `None` for `no_sm_rp_oa`.
    #[getter]
    fn value<'py>(&self, py: Python<'py>) -> Option<Bound<'py, PyBytes>> {
        match &self.inner {
            SmRpOa::MsIsdn(v) | SmRpOa::ServiceCentreAddressOa(v) => Some(PyBytes::new(py, v)),
            SmRpOa::NoSmRpOa(()) => None,
        }
    }

    fn __repr__(&self) -> String {
        format!("SmRpOa({})", self.inner)
    }
}

/// Additional-Number — the second serving node in a `LocationInfoWithLmsi`
/// (a CHOICE). Construct with `AdditionalNumber.msc_number(...)` /
/// `.sgsn_number(...)`; inspect with `.kind` and `.value`.
#[pyclass(name = "AdditionalNumber", module = "gsm_map._gsm_map", from_py_object)]
#[derive(Clone)]
pub struct PyAdditionalNumber {
    inner: AdditionalNumber,
}

#[pymethods]
impl PyAdditionalNumber {
    /// The additional node is an MSC.
    #[staticmethod]
    fn msc_number(value: Vec<u8>) -> Self {
        Self {
            inner: AdditionalNumber::MscNumber(value.into()),
        }
    }

    /// The additional node is an SGSN.
    #[staticmethod]
    fn sgsn_number(value: Vec<u8>) -> Self {
        Self {
            inner: AdditionalNumber::SgsnNumber(value.into()),
        }
    }

    /// Discriminant name: `"msc_number" | "sgsn_number"`.
    #[getter]
    fn kind(&self) -> &'static str {
        match self.inner {
            AdditionalNumber::MscNumber(_) => "msc_number",
            AdditionalNumber::SgsnNumber(_) => "sgsn_number",
        }
    }

    /// The carried ISDN-AddressString.
    #[getter]
    fn value<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        match &self.inner {
            AdditionalNumber::MscNumber(v) | AdditionalNumber::SgsnNumber(v) => PyBytes::new(py, v),
        }
    }

    fn __repr__(&self) -> String {
        format!(
            "AdditionalNumber({}={})",
            self.kind(),
            match &self.inner {
                AdditionalNumber::MscNumber(v) | AdditionalNumber::SgsnNumber(v) => hex::encode(v),
            }
        )
    }
}

/// NetworkNodeDiameterAddress — a node reached over Diameter (SGd/S6c) rather
/// than MAP: a Diameter Name and Realm, each a DiameterIdentity per RFC 6733.
#[pyclass(
    name = "NetworkNodeDiameterAddress",
    module = "gsm_map._gsm_map",
    from_py_object
)]
#[derive(Clone)]
pub struct PyNetworkNodeDiameterAddress {
    inner: NetworkNodeDiameterAddress,
}

#[pymethods]
impl PyNetworkNodeDiameterAddress {
    #[new]
    fn new(diameter_name: Vec<u8>, diameter_realm: Vec<u8>) -> Self {
        Self {
            inner: NetworkNodeDiameterAddress {
                diameter_name: diameter_name.into(),
                diameter_realm: diameter_realm.into(),
            },
        }
    }

    #[getter]
    fn diameter_name<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.inner.diameter_name)
    }

    #[getter]
    fn diameter_realm<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.inner.diameter_realm)
    }

    fn __repr__(&self) -> String {
        format!(
            "NetworkNodeDiameterAddress(name={}, realm={})",
            String::from_utf8_lossy(&self.inner.diameter_name),
            String::from_utf8_lossy(&self.inner.diameter_realm)
        )
    }
}

/// SubscriberIdentity — how an any-time operation names the subscriber (a
/// CHOICE). Construct with `SubscriberIdentity.imsi(...)` / `.msisdn(...)`.
#[pyclass(
    name = "SubscriberIdentity",
    module = "gsm_map._gsm_map",
    from_py_object
)]
#[derive(Clone)]
pub struct PySubscriberIdentity {
    inner: SubscriberIdentity,
}

#[pymethods]
impl PySubscriberIdentity {
    /// Identify the subscriber by IMSI (TBCD OCTET STRING).
    #[staticmethod]
    fn imsi(value: Vec<u8>) -> Self {
        Self {
            inner: SubscriberIdentity::Imsi(value.into()),
        }
    }

    /// Identify the subscriber by MSISDN (ISDN-AddressString).
    #[staticmethod]
    fn msisdn(value: Vec<u8>) -> Self {
        Self {
            inner: SubscriberIdentity::Msisdn(value.into()),
        }
    }

    /// Discriminant name: `"imsi" | "msisdn"`.
    #[getter]
    fn kind(&self) -> &'static str {
        match self.inner {
            SubscriberIdentity::Imsi(_) => "imsi",
            SubscriberIdentity::Msisdn(_) => "msisdn",
        }
    }

    /// The carried OCTET STRING.
    #[getter]
    fn value<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        match &self.inner {
            SubscriberIdentity::Imsi(v) | SubscriberIdentity::Msisdn(v) => PyBytes::new(py, v),
        }
    }

    fn __repr__(&self) -> String {
        format!(
            "SubscriberIdentity({}={})",
            self.kind(),
            match &self.inner {
                SubscriberIdentity::Imsi(v) | SubscriberIdentity::Msisdn(v) => hex::encode(v),
            }
        )
    }
}

/// LocationInfoWithLMSI — the serving-node routing info returned by SRI-SM.
/// Used as an argument to `RoutingInfoForSmRes(...)`, so it is `from_py_object`.
#[pyclass(
    name = "LocationInfoWithLmsi",
    module = "gsm_map._gsm_map",
    from_py_object
)]
#[derive(Clone)]
pub struct PyLocationInfoWithLmsi {
    inner: LocationInfoWithLmsi,
}

#[pymethods]
impl PyLocationInfoWithLmsi {
    #[new]
    #[pyo3(signature = (network_node_number, *, lmsi = None, gprs_node_indicator = false, additional_number = None, network_node_diameter_address = None))]
    fn new(
        network_node_number: Vec<u8>,
        lmsi: Option<Vec<u8>>,
        gprs_node_indicator: bool,
        additional_number: Option<PyAdditionalNumber>,
        network_node_diameter_address: Option<PyNetworkNodeDiameterAddress>,
    ) -> Self {
        Self {
            inner: LocationInfoWithLmsi {
                lmsi: lmsi.map(Into::into),
                gprs_node_indicator: gprs_node_indicator.then_some(()),
                additional_number: additional_number.map(|a| a.inner),
                network_node_diameter_address: network_node_diameter_address.map(|a| a.inner),
                ..LocationInfoWithLmsi::new(network_node_number.into())
            },
        }
    }

    /// ISDN address of the serving MSC/SGSN.
    #[getter]
    fn network_node_number<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.inner.network_node_number)
    }

    #[getter]
    fn lmsi<'py>(&self, py: Python<'py>) -> Option<Bound<'py, PyBytes>> {
        self.inner.lmsi.as_ref().map(|v| PyBytes::new(py, v))
    }

    #[getter]
    fn gprs_node_indicator(&self) -> bool {
        self.inner.gprs_node_indicator.is_some()
    }

    /// The second serving node, as an `AdditionalNumber` CHOICE.
    #[getter]
    fn additional_number(&self) -> Option<PyAdditionalNumber> {
        self.inner
            .additional_number
            .clone()
            .map(|inner| PyAdditionalNumber { inner })
    }

    /// The serving node's Diameter address, when the HLR gave one.
    #[getter]
    fn network_node_diameter_address(&self) -> Option<PyNetworkNodeDiameterAddress> {
        self.inner
            .network_node_diameter_address
            .clone()
            .map(|inner| PyNetworkNodeDiameterAddress { inner })
    }

    fn __repr__(&self) -> String {
        format!(
            "LocationInfoWithLmsi(network_node_number={}, lmsi={})",
            hex::encode(&self.inner.network_node_number),
            self.inner
                .lmsi
                .as_ref()
                .map_or_else(|| "None".to_string(), hex::encode)
        )
    }
}

// ── SMS operations ──────────────────────────────────────────────────────────

/// RoutingInfoForSM-Arg — the SMS-GMSC's query to the HLR (sendRoutingInfoForSM,
/// op 45): "where is this MSISDN?".
#[pyclass(
    name = "RoutingInfoForSmArg",
    module = "gsm_map._gsm_map",
    skip_from_py_object
)]
#[derive(Clone)]
pub struct PyRoutingInfoForSmArg {
    inner: RoutingInfoForSmArg,
}

#[pymethods]
impl PyRoutingInfoForSmArg {
    #[new]
    #[pyo3(signature = (msisdn, service_centre_address, *, sm_rp_pri = true, gprs_support_indicator = false, sm_rp_mti = None))]
    fn new(
        msisdn: Vec<u8>,
        service_centre_address: Vec<u8>,
        sm_rp_pri: bool,
        gprs_support_indicator: bool,
        sm_rp_mti: Option<i64>,
    ) -> Self {
        Self {
            inner: RoutingInfoForSmArg {
                gprs_support_indicator: gprs_support_indicator.then_some(()),
                sm_rp_mti: sm_rp_mti.map(Into::into),
                ..RoutingInfoForSmArg::new(msisdn.into(), sm_rp_pri, service_centre_address.into())
            },
        }
    }

    #[getter]
    fn msisdn<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.inner.msisdn)
    }

    #[getter]
    fn service_centre_address<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.inner.service_centre_address)
    }

    #[getter]
    fn sm_rp_pri(&self) -> bool {
        self.inner.sm_rp_pri
    }

    #[getter]
    fn gprs_support_indicator(&self) -> bool {
        self.inner.gprs_support_indicator.is_some()
    }

    /// The MAP operation code for this argument (45).
    #[getter]
    fn op_code(&self) -> i64 {
        op_codes::SEND_ROUTING_INFO_FOR_SM
    }

    /// Encode to BER bytes (the TCAP Invoke parameter).
    fn encode(&self, py: Python<'_>) -> PyResult<Py<PyBytes>> {
        ber_encode(&self.inner, py)
    }

    /// Decode BER bytes into a `RoutingInfoForSmArg`.
    #[staticmethod]
    fn decode(data: &[u8]) -> PyResult<Self> {
        Ok(Self {
            inner: ber_decode(data)?,
        })
    }

    fn __repr__(&self) -> String {
        format!(
            "RoutingInfoForSmArg(msisdn={}, sc={}, sm_rp_pri={})",
            hex::encode(&self.inner.msisdn),
            hex::encode(&self.inner.service_centre_address),
            self.inner.sm_rp_pri
        )
    }
}

/// RoutingInfoForSM-Res — the HLR's answer: IMSI + serving-node location.
#[pyclass(
    name = "RoutingInfoForSmRes",
    module = "gsm_map._gsm_map",
    skip_from_py_object
)]
#[derive(Clone)]
pub struct PyRoutingInfoForSmRes {
    inner: RoutingInfoForSmRes,
}

#[pymethods]
impl PyRoutingInfoForSmRes {
    #[new]
    fn new(imsi: Vec<u8>, location_info_with_lmsi: PyLocationInfoWithLmsi) -> Self {
        Self {
            inner: RoutingInfoForSmRes::new(imsi.into(), location_info_with_lmsi.inner),
        }
    }

    #[getter]
    fn imsi<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.inner.imsi)
    }

    #[getter]
    fn location_info_with_lmsi(&self) -> PyLocationInfoWithLmsi {
        PyLocationInfoWithLmsi {
            inner: self.inner.location_info_with_lmsi.clone(),
        }
    }

    fn encode(&self, py: Python<'_>) -> PyResult<Py<PyBytes>> {
        ber_encode(&self.inner, py)
    }

    #[staticmethod]
    fn decode(data: &[u8]) -> PyResult<Self> {
        Ok(Self {
            inner: ber_decode(data)?,
        })
    }

    fn __repr__(&self) -> String {
        format!(
            "RoutingInfoForSmRes(imsi={}, node={})",
            hex::encode(&self.inner.imsi),
            hex::encode(&self.inner.location_info_with_lmsi.network_node_number)
        )
    }
}

/// MO-ForwardSM-Arg — mobile-originated SMS relayed MSC → SMS-IWMSC (op 46).
#[pyclass(
    name = "MoForwardSmArg",
    module = "gsm_map._gsm_map",
    skip_from_py_object
)]
#[derive(Clone)]
pub struct PyMoForwardSmArg {
    inner: MoForwardSmArg,
}

#[pymethods]
impl PyMoForwardSmArg {
    #[new]
    #[pyo3(signature = (sm_rp_da, sm_rp_oa, sm_rp_ui, *, imsi = None))]
    fn new(
        sm_rp_da: PySmRpDa,
        sm_rp_oa: PySmRpOa,
        sm_rp_ui: Vec<u8>,
        imsi: Option<Vec<u8>>,
    ) -> Self {
        Self {
            inner: MoForwardSmArg {
                imsi: imsi.map(Into::into),
                ..MoForwardSmArg::new(sm_rp_da.inner, sm_rp_oa.inner, sm_rp_ui.into())
            },
        }
    }

    #[getter]
    fn sm_rp_da(&self) -> PySmRpDa {
        PySmRpDa {
            inner: self.inner.sm_rp_da.clone(),
        }
    }

    #[getter]
    fn sm_rp_oa(&self) -> PySmRpOa {
        PySmRpOa {
            inner: self.inner.sm_rp_oa.clone(),
        }
    }

    /// SM-RP-UI — the raw TPDU (an SMS-SUBMIT), as `bytes`.
    #[getter]
    fn sm_rp_ui<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.inner.sm_rp_ui)
    }

    #[getter]
    fn op_code(&self) -> i64 {
        op_codes::MO_FORWARD_SM
    }

    fn encode(&self, py: Python<'_>) -> PyResult<Py<PyBytes>> {
        ber_encode(&self.inner, py)
    }

    #[staticmethod]
    fn decode(data: &[u8]) -> PyResult<Self> {
        Ok(Self {
            inner: ber_decode(data)?,
        })
    }

    fn __repr__(&self) -> String {
        format!(
            "MoForwardSmArg(da={}, oa={}, ui_len={})",
            self.inner.sm_rp_da,
            self.inner.sm_rp_oa,
            self.inner.sm_rp_ui.len()
        )
    }
}

/// MT-ForwardSM-Arg — mobile-terminated SMS relayed SMS-GMSC → serving MSC (op 44).
#[pyclass(
    name = "MtForwardSmArg",
    module = "gsm_map._gsm_map",
    skip_from_py_object
)]
#[derive(Clone)]
pub struct PyMtForwardSmArg {
    inner: MtForwardSmArg,
}

#[pymethods]
impl PyMtForwardSmArg {
    #[new]
    #[pyo3(signature = (sm_rp_da, sm_rp_oa, sm_rp_ui, *, more_messages_to_send = None))]
    fn new(
        sm_rp_da: PySmRpDa,
        sm_rp_oa: PySmRpOa,
        sm_rp_ui: Vec<u8>,
        more_messages_to_send: Option<bool>,
    ) -> Self {
        Self {
            inner: MtForwardSmArg {
                // moreMessagesToSend is an ASN.1 NULL: a truthy flag sets it
                // present, everything else omits it.
                more_messages_to_send: more_messages_to_send.filter(|&b| b).map(|_| ()),
                ..MtForwardSmArg::new(sm_rp_da.inner, sm_rp_oa.inner, sm_rp_ui.into())
            },
        }
    }

    #[getter]
    fn sm_rp_da(&self) -> PySmRpDa {
        PySmRpDa {
            inner: self.inner.sm_rp_da.clone(),
        }
    }

    #[getter]
    fn sm_rp_oa(&self) -> PySmRpOa {
        PySmRpOa {
            inner: self.inner.sm_rp_oa.clone(),
        }
    }

    /// SM-RP-UI — the raw TPDU (an SMS-DELIVER), as `bytes`.
    #[getter]
    fn sm_rp_ui<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.inner.sm_rp_ui)
    }

    #[getter]
    fn more_messages_to_send(&self) -> Option<bool> {
        // Present NULL -> True; absent -> None.
        self.inner.more_messages_to_send.map(|()| true)
    }

    #[getter]
    fn op_code(&self) -> i64 {
        op_codes::MT_FORWARD_SM
    }

    fn encode(&self, py: Python<'_>) -> PyResult<Py<PyBytes>> {
        ber_encode(&self.inner, py)
    }

    #[staticmethod]
    fn decode(data: &[u8]) -> PyResult<Self> {
        Ok(Self {
            inner: ber_decode(data)?,
        })
    }

    fn __repr__(&self) -> String {
        format!(
            "MtForwardSmArg(da={}, oa={}, ui_len={})",
            self.inner.sm_rp_da,
            self.inner.sm_rp_oa,
            self.inner.sm_rp_ui.len()
        )
    }
}

/// ReportSM-DeliveryStatus-Arg — SMS-GMSC → HLR delivery-outcome report (op 47).
#[pyclass(
    name = "ReportSmDeliveryStatusArg",
    module = "gsm_map._gsm_map",
    skip_from_py_object
)]
#[derive(Clone)]
pub struct PyReportSmDeliveryStatusArg {
    inner: ReportSmDeliveryStatusArg,
}

#[pymethods]
impl PyReportSmDeliveryStatusArg {
    /// `outcome` is one of the `DELIVERY_OUTCOME_*` module constants
    /// (0 = memory capacity exceeded, 1 = absent subscriber, 2 = successful).
    #[new]
    fn new(msisdn: Vec<u8>, service_centre_address: Vec<u8>, outcome: i64) -> PyResult<Self> {
        let sm_delivery_outcome = match outcome {
            0 => SmDeliveryOutcome::MemoryCapacityExceeded,
            1 => SmDeliveryOutcome::AbsentSubscriber,
            2 => SmDeliveryOutcome::SuccessfulTransfer,
            other => {
                return Err(MapError::new_err(format!(
                    "invalid SM-DeliveryOutcome: {other} (expected 0, 1, or 2)"
                )))
            }
        };
        Ok(Self {
            inner: ReportSmDeliveryStatusArg::new(
                msisdn.into(),
                service_centre_address.into(),
                sm_delivery_outcome,
            ),
        })
    }

    #[getter]
    fn msisdn<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.inner.msisdn)
    }

    #[getter]
    fn service_centre_address<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.inner.service_centre_address)
    }

    /// The delivery outcome as its wire integer (0/1/2).
    #[getter]
    fn outcome(&self) -> i64 {
        match self.inner.sm_delivery_outcome {
            SmDeliveryOutcome::MemoryCapacityExceeded => 0,
            SmDeliveryOutcome::AbsentSubscriber => 1,
            SmDeliveryOutcome::SuccessfulTransfer => 2,
        }
    }

    #[getter]
    fn op_code(&self) -> i64 {
        op_codes::REPORT_SM_DELIVERY_STATUS
    }

    fn encode(&self, py: Python<'_>) -> PyResult<Py<PyBytes>> {
        ber_encode(&self.inner, py)
    }

    #[staticmethod]
    fn decode(data: &[u8]) -> PyResult<Self> {
        Ok(Self {
            inner: ber_decode(data)?,
        })
    }

    fn __repr__(&self) -> String {
        format!(
            "ReportSmDeliveryStatusArg(msisdn={}, outcome={})",
            hex::encode(&self.inner.msisdn),
            self.outcome()
        )
    }
}

// ── A couple of mobility / auth ops (easy wins) ─────────────────────────────

/// UpdateLocation-Arg — VLR → HLR location update (op 2).
#[pyclass(
    name = "UpdateLocationArg",
    module = "gsm_map._gsm_map",
    skip_from_py_object
)]
#[derive(Clone)]
pub struct PyUpdateLocationArg {
    inner: UpdateLocationArg,
}

#[pymethods]
impl PyUpdateLocationArg {
    #[new]
    #[pyo3(signature = (imsi, msc_number, vlr_number, *, lmsi = None))]
    fn new(imsi: Vec<u8>, msc_number: Vec<u8>, vlr_number: Vec<u8>, lmsi: Option<Vec<u8>>) -> Self {
        Self {
            inner: UpdateLocationArg {
                lmsi: lmsi.map(Into::into),
                ..UpdateLocationArg::new(imsi.into(), msc_number.into(), vlr_number.into())
            },
        }
    }

    #[getter]
    fn imsi<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.inner.imsi)
    }

    #[getter]
    fn op_code(&self) -> i64 {
        op_codes::UPDATE_LOCATION
    }

    fn encode(&self, py: Python<'_>) -> PyResult<Py<PyBytes>> {
        ber_encode(&self.inner, py)
    }

    #[staticmethod]
    fn decode(data: &[u8]) -> PyResult<Self> {
        Ok(Self {
            inner: ber_decode(data)?,
        })
    }

    fn __repr__(&self) -> String {
        format!("UpdateLocationArg(imsi={})", hex::encode(&self.inner.imsi))
    }
}

/// SendAuthenticationInfo-Arg — VLR/SGSN → HLR auth-vector request (op 56).
#[pyclass(
    name = "SendAuthenticationInfoArg",
    module = "gsm_map._gsm_map",
    skip_from_py_object
)]
#[derive(Clone)]
pub struct PySendAuthenticationInfoArg {
    inner: SendAuthenticationInfoArg,
}

#[pymethods]
impl PySendAuthenticationInfoArg {
    #[new]
    #[pyo3(signature = (imsi, number_of_requested_vectors))]
    fn new(imsi: Vec<u8>, number_of_requested_vectors: i64) -> Self {
        Self {
            inner: SendAuthenticationInfoArg::new(imsi.into(), number_of_requested_vectors.into()),
        }
    }

    #[getter]
    fn imsi<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.inner.imsi)
    }

    #[getter]
    fn op_code(&self) -> i64 {
        op_codes::SEND_AUTHENTICATION_INFO
    }

    fn encode(&self, py: Python<'_>) -> PyResult<Py<PyBytes>> {
        ber_encode(&self.inner, py)
    }

    #[staticmethod]
    fn decode(data: &[u8]) -> PyResult<Self> {
        Ok(Self {
            inner: ber_decode(data)?,
        })
    }

    fn __repr__(&self) -> String {
        format!(
            "SendAuthenticationInfoArg(imsi={})",
            hex::encode(&self.inner.imsi)
        )
    }
}

// ── The rest of the SMS operation set ───────────────────────────────────────

/// ReadyForSM-Arg — the serving node telling the HLR a subscriber became
/// reachable or freed memory (readyForSM, op 66). This is the MAP form of
/// Alert-SC: it is what makes the HLR alert the queued service centres.
///
/// `alert_reason` is `ALERT_MS_PRESENT` or `ALERT_MEMORY_AVAILABLE`.
#[pyclass(
    name = "ReadyForSmArg",
    module = "gsm_map._gsm_map",
    skip_from_py_object
)]
#[derive(Clone)]
pub struct PyReadyForSmArg {
    inner: ReadyForSmArg,
}

#[pymethods]
impl PyReadyForSmArg {
    #[new]
    #[pyo3(signature = (imsi, alert_reason, *, alert_reason_indicator = false, additional_alert_reason_indicator = false, maximum_ue_availability_time = None))]
    fn new(
        imsi: Vec<u8>,
        alert_reason: i64,
        alert_reason_indicator: bool,
        additional_alert_reason_indicator: bool,
        maximum_ue_availability_time: Option<Vec<u8>>,
    ) -> PyResult<Self> {
        let reason = match alert_reason {
            0 => AlertReason::MsPresent,
            1 => AlertReason::MemoryAvailable,
            other => {
                return Err(MapError::new_err(format!(
                    "alert_reason must be ALERT_MS_PRESENT (0) or \
                     ALERT_MEMORY_AVAILABLE (1), got {other}"
                )))
            }
        };
        Ok(Self {
            inner: ReadyForSmArg {
                alert_reason_indicator: alert_reason_indicator.then_some(()),
                additional_alert_reason_indicator: additional_alert_reason_indicator.then_some(()),
                maximum_ue_availability_time: maximum_ue_availability_time.map(Into::into),
                ..ReadyForSmArg::new(imsi.into(), reason)
            },
        })
    }

    #[getter]
    fn imsi<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.inner.imsi)
    }

    #[getter]
    fn alert_reason(&self) -> i64 {
        match self.inner.alert_reason {
            AlertReason::MsPresent => 0,
            AlertReason::MemoryAvailable => 1,
        }
    }

    #[getter]
    fn maximum_ue_availability_time<'py>(&self, py: Python<'py>) -> Option<Bound<'py, PyBytes>> {
        self.inner
            .maximum_ue_availability_time
            .as_ref()
            .map(|v| PyBytes::new(py, v))
    }

    /// The MAP operation code for this argument (66).
    #[getter]
    fn op_code(&self) -> i64 {
        op_codes::READY_FOR_SM
    }

    fn encode(&self, py: Python<'_>) -> PyResult<Py<PyBytes>> {
        ber_encode(&self.inner, py)
    }

    #[staticmethod]
    fn decode(data: &[u8]) -> PyResult<Self> {
        Ok(Self {
            inner: ber_decode(data)?,
        })
    }

    fn __repr__(&self) -> String {
        format!(
            "ReadyForSmArg(imsi={}, alert_reason={})",
            hex::encode(&self.inner.imsi),
            self.alert_reason()
        )
    }
}

/// AlertServiceCentre-Arg — the HLR telling a service centre a subscriber is
/// reachable again, so it can drain its queue (alertServiceCentre, op 64).
#[pyclass(
    name = "AlertServiceCentreArg",
    module = "gsm_map._gsm_map",
    skip_from_py_object
)]
#[derive(Clone)]
pub struct PyAlertServiceCentreArg {
    inner: AlertServiceCentreArg,
}

#[pymethods]
impl PyAlertServiceCentreArg {
    #[new]
    #[pyo3(signature = (msisdn, service_centre_address, *, imsi = None, new_msc_number = None, new_sgsn_number = None, new_mme_number = None))]
    fn new(
        msisdn: Vec<u8>,
        service_centre_address: Vec<u8>,
        imsi: Option<Vec<u8>>,
        new_msc_number: Option<Vec<u8>>,
        new_sgsn_number: Option<Vec<u8>>,
        new_mme_number: Option<Vec<u8>>,
    ) -> Self {
        Self {
            inner: AlertServiceCentreArg {
                imsi: imsi.map(Into::into),
                new_sgsn_number: new_sgsn_number.map(Into::into),
                new_mme_number: new_mme_number.map(Into::into),
                new_msc_number: new_msc_number.map(Into::into),
                ..AlertServiceCentreArg::new(msisdn.into(), service_centre_address.into())
            },
        }
    }

    #[getter]
    fn msisdn<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.inner.msisdn)
    }

    #[getter]
    fn service_centre_address<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.inner.service_centre_address)
    }

    #[getter]
    fn imsi<'py>(&self, py: Python<'py>) -> Option<Bound<'py, PyBytes>> {
        self.inner.imsi.as_ref().map(|v| PyBytes::new(py, v))
    }

    /// Where the subscriber moved to, if the HLR said.
    #[getter]
    fn new_msc_number<'py>(&self, py: Python<'py>) -> Option<Bound<'py, PyBytes>> {
        self.inner
            .new_msc_number
            .as_ref()
            .map(|v| PyBytes::new(py, v))
    }

    /// The MAP operation code for this argument (64).
    #[getter]
    fn op_code(&self) -> i64 {
        op_codes::ALERT_SERVICE_CENTRE
    }

    fn encode(&self, py: Python<'_>) -> PyResult<Py<PyBytes>> {
        ber_encode(&self.inner, py)
    }

    #[staticmethod]
    fn decode(data: &[u8]) -> PyResult<Self> {
        Ok(Self {
            inner: ber_decode(data)?,
        })
    }

    fn __repr__(&self) -> String {
        format!(
            "AlertServiceCentreArg(msisdn={}, sc={})",
            hex::encode(&self.inner.msisdn),
            hex::encode(&self.inner.service_centre_address)
        )
    }
}

/// InformServiceCentre-Arg — what the HLR already knows about the subscriber's
/// message-waiting state (informServiceCentre, op 63).
///
/// `mw_status` is a **BIT STRING**; pass the flags as booleans and read them
/// back the same way rather than packing a byte.
#[pyclass(
    name = "InformServiceCentreArg",
    module = "gsm_map._gsm_map",
    skip_from_py_object
)]
#[derive(Clone)]
pub struct PyInformServiceCentreArg {
    inner: InformServiceCentreArg,
}

#[pymethods]
impl PyInformServiceCentreArg {
    #[new]
    #[pyo3(signature = (*, stored_msisdn = None, sc_address_not_included = false, mnrf_set = false, mcef_set = false, mnrg_set = false, mnr5g_set = false, mnr5gn3g_set = false, absent_subscriber_diagnostic_sm = None))]
    #[allow(clippy::too_many_arguments)]
    fn new(
        stored_msisdn: Option<Vec<u8>>,
        sc_address_not_included: bool,
        mnrf_set: bool,
        mcef_set: bool,
        mnrg_set: bool,
        mnr5g_set: bool,
        mnr5gn3g_set: bool,
        absent_subscriber_diagnostic_sm: Option<i64>,
    ) -> Self {
        let flags = crate::types::MwStatusFlags {
            sc_address_not_included,
            mnrf_set,
            mcef_set,
            mnrg_set,
            mnr5g_set,
            mnr5gn3g_set,
        };
        let any_flag = flags != crate::types::MwStatusFlags::default();
        Self {
            inner: InformServiceCentreArg {
                stored_msisdn: stored_msisdn.map(Into::into),
                mw_status: any_flag.then(|| flags.to_bits()),
                absent_subscriber_diagnostic_sm: absent_subscriber_diagnostic_sm.map(Into::into),
                ..Default::default()
            },
        }
    }

    #[getter]
    fn stored_msisdn<'py>(&self, py: Python<'py>) -> Option<Bound<'py, PyBytes>> {
        self.inner
            .stored_msisdn
            .as_ref()
            .map(|v| PyBytes::new(py, v))
    }

    /// The message-waiting flags as a dict, or `None` if `mw-Status` is absent.
    #[getter]
    fn mw_status(&self) -> Option<std::collections::BTreeMap<&'static str, bool>> {
        let flags = crate::types::MwStatusFlags::from_bits(self.inner.mw_status.as_ref()?);
        Some(
            [
                ("sc_address_not_included", flags.sc_address_not_included),
                ("mnrf_set", flags.mnrf_set),
                ("mcef_set", flags.mcef_set),
                ("mnrg_set", flags.mnrg_set),
                ("mnr5g_set", flags.mnr5g_set),
                ("mnr5gn3g_set", flags.mnr5gn3g_set),
            ]
            .into_iter()
            .collect(),
        )
    }

    #[getter]
    fn absent_subscriber_diagnostic_sm(&self) -> Option<i64> {
        self.inner
            .absent_subscriber_diagnostic_sm
            .as_ref()
            .and_then(|v| i64::try_from(v).ok())
    }

    /// The MAP operation code for this argument (63).
    #[getter]
    fn op_code(&self) -> i64 {
        op_codes::INFORM_SERVICE_CENTRE
    }

    fn encode(&self, py: Python<'_>) -> PyResult<Py<PyBytes>> {
        ber_encode(&self.inner, py)
    }

    #[staticmethod]
    fn decode(data: &[u8]) -> PyResult<Self> {
        Ok(Self {
            inner: ber_decode(data)?,
        })
    }

    fn __repr__(&self) -> String {
        format!("InformServiceCentreArg(mw_status={:?})", self.mw_status())
    }
}

// ── anyTimeModification: the IP-SM-GW registration ──────────────────────────

/// AnyTimeModification-Arg — how a node registers itself with the HLR as the
/// MT-SMS routing node for a subscriber (anyTimeModification, op 65).
///
/// `modify_registration_status` is `MODIFY_ACTIVATE` to register and
/// `MODIFY_DEACTIVATE` to de-register. The registering node's **own** address
/// is `gsm_scf_address`, not something inside the registration: the IP-SM-GW
/// acts in the gsmSCF role towards the HLR for this dialogue.
/// `ip_sm_gw_diameter_address` is the Diameter-realm variant, for a node reached
/// over SGd/S6c rather than MAP, and only belongs on an `activate`.
///
/// ```python
/// arg = gsm_map.AnyTimeModificationArg(
///     gsm_map.SubscriberIdentity.msisdn(gsm_map.international_e164("15550100999")),
///     gsm_map.international_e164("15550142"),
///     modify_registration_status=gsm_map.MODIFY_ACTIVATE,
/// )
/// arg.encode()
/// ```
#[pyclass(
    name = "AnyTimeModificationArg",
    module = "gsm_map._gsm_map",
    skip_from_py_object
)]
#[derive(Clone)]
pub struct PyAnyTimeModificationArg {
    inner: AnyTimeModificationArg,
}

impl PyAnyTimeModificationArg {
    /// `ModificationInstruction` from its ASN.1 ENUMERATED value.
    fn instruction(value: i64) -> PyResult<ModificationInstruction> {
        match value {
            0 => Ok(ModificationInstruction::Deactivate),
            1 => Ok(ModificationInstruction::Activate),
            other => Err(MapError::new_err(format!(
                "modify_registration_status must be MODIFY_DEACTIVATE (0) or \
                 MODIFY_ACTIVATE (1), got {other}"
            ))),
        }
    }
}

#[pymethods]
impl PyAnyTimeModificationArg {
    #[new]
    #[pyo3(signature = (subscriber_identity, gsm_scf_address, *, modify_registration_status = None, ip_sm_gw_diameter_address = None, long_ftn_supported = false))]
    fn new(
        subscriber_identity: PySubscriberIdentity,
        gsm_scf_address: Vec<u8>,
        modify_registration_status: Option<i64>,
        ip_sm_gw_diameter_address: Option<PyNetworkNodeDiameterAddress>,
        long_ftn_supported: bool,
    ) -> PyResult<Self> {
        let instruction = modify_registration_status
            .map(Self::instruction)
            .transpose()?;
        let diameter = ip_sm_gw_diameter_address.map(|a| a.inner);
        // The [8] member only goes on the wire if it would carry something.
        let ip_sm_gw_data = (instruction.is_some() || diameter.is_some()).then(|| {
            ModificationRequestForIpSmGwData {
                modify_registration_status: instruction,
                ip_sm_gw_diameter_address: diameter,
                ..Default::default()
            }
        });
        Ok(Self {
            inner: AnyTimeModificationArg {
                long_ftn_supported: long_ftn_supported.then_some(()),
                modification_request_for_ip_sm_gw_data: ip_sm_gw_data,
                ..AnyTimeModificationArg::new(subscriber_identity.inner, gsm_scf_address.into())
            },
        })
    }

    /// The subscriber whose record is being modified.
    #[getter]
    fn subscriber_identity(&self) -> PySubscriberIdentity {
        PySubscriberIdentity {
            inner: self.inner.subscriber_identity.clone(),
        }
    }

    /// The gsmSCF address — for an IP-SM-GW registration, the gateway's own
    /// address, which is what the HLR will hand out in `RoutingInfoForSM-Res`.
    #[getter]
    fn gsm_scf_address<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.inner.gsm_scf_address)
    }

    /// `MODIFY_ACTIVATE` / `MODIFY_DEACTIVATE`, or `None` if the argument
    /// carries no IP-SM-GW registration at all.
    #[getter]
    fn modify_registration_status(&self) -> Option<i64> {
        match self
            .inner
            .modification_request_for_ip_sm_gw_data
            .as_ref()?
            .modify_registration_status?
        {
            ModificationInstruction::Deactivate => Some(0),
            ModificationInstruction::Activate => Some(1),
        }
    }

    /// The Diameter-realm variant of the gateway address, when present.
    #[getter]
    fn ip_sm_gw_diameter_address(&self) -> Option<PyNetworkNodeDiameterAddress> {
        self.inner
            .modification_request_for_ip_sm_gw_data
            .as_ref()
            .and_then(|d| d.ip_sm_gw_diameter_address.clone())
            .map(|inner| PyNetworkNodeDiameterAddress { inner })
    }

    #[getter]
    fn long_ftn_supported(&self) -> bool {
        self.inner.long_ftn_supported.is_some()
    }

    /// The MAP operation code for this argument (65).
    #[getter]
    fn op_code(&self) -> i64 {
        op_codes::ANY_TIME_MODIFICATION
    }

    /// Encode to BER bytes (the TCAP Invoke parameter).
    fn encode(&self, py: Python<'_>) -> PyResult<Py<PyBytes>> {
        ber_encode(&self.inner, py)
    }

    /// Decode BER bytes into an `AnyTimeModificationArg`.
    #[staticmethod]
    fn decode(data: &[u8]) -> PyResult<Self> {
        Ok(Self {
            inner: ber_decode(data)?,
        })
    }

    fn __repr__(&self) -> String {
        format!(
            "AnyTimeModificationArg(subscriber_identity={}, gsm_scf_address={}, \
             modify_registration_status={:?})",
            self.subscriber_identity().__repr__(),
            hex::encode(&self.inner.gsm_scf_address),
            self.modify_registration_status()
        )
    }
}

// ── Free functions ──────────────────────────────────────────────────────────

/// The MAP operation name for an operation code (e.g. `45 -> "sendRoutingInfoForSM"`).
#[pyfunction]
fn op_name(op_code: i64) -> &'static str {
    operation_name(op_code)
}

/// The MAP error name for an error code (e.g. `61 -> "atm-NotAllowed"`).
#[pyfunction]
fn error_name(error_code: i64) -> &'static str {
    crate::operations::errors::error_name(error_code)
}

/// Encode an ISDN-AddressString / AddressString from a digit string: the
/// nature-of-address / numbering-plan octet then TBCD digits.
#[pyfunction]
#[pyo3(signature = (digits, nature=crate::address::NATURE_INTERNATIONAL, plan=crate::address::PLAN_ISDN))]
fn isdn_address_string(
    py: Python<'_>,
    digits: &str,
    nature: u8,
    plan: u8,
) -> PyResult<Py<PyBytes>> {
    let bytes = crate::address::isdn_address_string(digits, nature, plan)
        .map_err(|e| MapError::new_err(e.to_string()))?;
    Ok(PyBytes::new(py, &bytes).unbind())
}

/// Encode an international E.164 ISDN number (leading octet `0x91`).
#[pyfunction]
fn international_e164(py: Python<'_>, digits: &str) -> PyResult<Py<PyBytes>> {
    let bytes =
        crate::address::international_e164(digits).map_err(|e| MapError::new_err(e.to_string()))?;
    Ok(PyBytes::new(py, &bytes).unbind())
}

/// Encode an IMSI as a bare TBCD-STRING (no leading octet).
#[pyfunction]
fn imsi(py: Python<'_>, digits: &str) -> PyResult<Py<PyBytes>> {
    let bytes = crate::address::imsi(digits).map_err(|e| MapError::new_err(e.to_string()))?;
    Ok(PyBytes::new(py, &bytes).unbind())
}

fn operation_registry_pairs() -> std::collections::BTreeMap<&'static str, i64> {
    crate::types::OPERATION_REGISTRY
        .iter()
        .map(|(code, name)| (*name, *code))
        .collect()
}

// ── Module wiring ───────────────────────────────────────────────────────────
fn add_contents(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("MapError", m.py().get_type::<MapError>())?;

    // Shared address / identity types.
    m.add_class::<PySmRpDa>()?;
    m.add_class::<PySmRpOa>()?;
    m.add_class::<PyAdditionalNumber>()?;
    m.add_class::<PyNetworkNodeDiameterAddress>()?;
    m.add_class::<PySubscriberIdentity>()?;
    m.add_class::<PyLocationInfoWithLmsi>()?;

    // SMS operations.
    m.add_class::<PyRoutingInfoForSmArg>()?;
    m.add_class::<PyRoutingInfoForSmRes>()?;
    m.add_class::<PyMoForwardSmArg>()?;
    m.add_class::<PyMtForwardSmArg>()?;
    m.add_class::<PyReportSmDeliveryStatusArg>()?;

    // Mobility / auth.
    m.add_class::<PyUpdateLocationArg>()?;
    m.add_class::<PySendAuthenticationInfoArg>()?;

    // The rest of the SMS operation set.
    m.add_class::<PyReadyForSmArg>()?;
    m.add_class::<PyAlertServiceCentreArg>()?;
    m.add_class::<PyInformServiceCentreArg>()?;

    // Subscriber-data modification (the IP-SM-GW registration).
    m.add_class::<PyAnyTimeModificationArg>()?;

    m.add_function(wrap_pyfunction!(op_name, m)?)?;
    m.add_function(wrap_pyfunction!(error_name, m)?)?;

    // The full registries, as name -> code maps. Built from the same tables
    // `op_name()` / `error_name()` resolve against, so they cannot drift.
    let operations: std::collections::BTreeMap<&str, i64> = operation_registry_pairs();
    m.add("OPERATIONS", operations)?;
    let errors: std::collections::BTreeMap<&str, i64> = crate::operations::errors::ERROR_REGISTRY
        .iter()
        .map(|(code, name)| (*name, *code))
        .collect();
    m.add("ERRORS", errors)?;

    // AlertReason values (readyForSM).
    m.add("ALERT_MS_PRESENT", 0i64)?;
    m.add("ALERT_MEMORY_AVAILABLE", 1i64)?;

    // Address / identity encoders (digit string → TBCD OCTET STRING).
    m.add_function(wrap_pyfunction!(isdn_address_string, m)?)?;
    m.add_function(wrap_pyfunction!(international_e164, m)?)?;
    m.add_function(wrap_pyfunction!(imsi, m)?)?;
    m.add("NATURE_INTERNATIONAL", crate::address::NATURE_INTERNATIONAL)?;
    m.add("NATURE_NATIONAL", crate::address::NATURE_NATIONAL)?;
    m.add("PLAN_ISDN", crate::address::PLAN_ISDN)?;
    m.add("PLAN_LAND_MOBILE", crate::address::PLAN_LAND_MOBILE)?;

    // Operation-code registry (the SMS set + the two extra ops we expose).
    m.add(
        "OP_SEND_ROUTING_INFO_FOR_SM",
        op_codes::SEND_ROUTING_INFO_FOR_SM,
    )?;
    m.add("OP_MO_FORWARD_SM", op_codes::MO_FORWARD_SM)?;
    m.add("OP_MT_FORWARD_SM", op_codes::MT_FORWARD_SM)?;
    m.add(
        "OP_REPORT_SM_DELIVERY_STATUS",
        op_codes::REPORT_SM_DELIVERY_STATUS,
    )?;
    m.add("OP_ALERT_SERVICE_CENTRE", op_codes::ALERT_SERVICE_CENTRE)?;
    m.add("OP_INFORM_SERVICE_CENTRE", op_codes::INFORM_SERVICE_CENTRE)?;
    m.add("OP_READY_FOR_SM", op_codes::READY_FOR_SM)?;
    m.add("OP_UPDATE_LOCATION", op_codes::UPDATE_LOCATION)?;
    m.add(
        "OP_SEND_AUTHENTICATION_INFO",
        op_codes::SEND_AUTHENTICATION_INFO,
    )?;
    m.add("OP_ANY_TIME_MODIFICATION", op_codes::ANY_TIME_MODIFICATION)?;

    // ModificationInstruction enum values (the IP-SM-GW registration).
    m.add("MODIFY_DEACTIVATE", 0i64)?;
    m.add("MODIFY_ACTIVATE", 1i64)?;

    // SM-DeliveryOutcome enum values.
    m.add("DELIVERY_OUTCOME_MEMORY_CAPACITY_EXCEEDED", 0i64)?;
    m.add("DELIVERY_OUTCOME_ABSENT_SUBSCRIBER", 1i64)?;
    m.add("DELIVERY_OUTCOME_SUCCESSFUL_TRANSFER", 2i64)?;

    Ok(())
}

/// Standalone wheel entry point (maturin `module-name = "gsm_map._gsm_map"`).
#[pymodule]
fn _gsm_map(m: &Bound<'_, PyModule>) -> PyResult<()> {
    add_contents(m)
}

/// Embedding entry point: build a `gsm_map` submodule and attach it to `parent`,
/// so a host extension (e.g. an SS7 stack binary) can expose gsm_map without a
/// second shared object.
pub fn register(py: Python<'_>, parent: &Bound<'_, PyModule>) -> PyResult<()> {
    let m = PyModule::new(py, "gsm_map")?;
    add_contents(&m)?;
    parent.setattr("gsm_map", &m)?;
    Ok(())
}
