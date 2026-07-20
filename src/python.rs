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

use crate::operations::auth::SendAuthenticationInfoArg;
use crate::operations::location::UpdateLocationArg;
use crate::operations::mo_forward_sm::MoForwardSmArg;
use crate::operations::mt_forward_sm::MtForwardSmArg;
use crate::operations::report_sm::{ReportSmDeliveryStatusArg, SmDeliveryOutcome};
use crate::operations::sri_sm::{RoutingInfoForSmArg, RoutingInfoForSmRes};
use crate::types::{op_codes, operation_name, LocationInfoWithLmsi, SmRpDa, SmRpOa};

// ── Error mapping ───────────────────────────────────────────────────────────
create_exception!(
    gsm_map,
    MapError,
    PyException,
    "GSM MAP protocol / BER codec error (3GPP TS 29.002)."
);

fn decode_err(e: rasn::error::DecodeError) -> PyErr {
    MapError::new_err(format!("BER decode error: {e}"))
}

fn encode_err(e: rasn::error::EncodeError) -> PyErr {
    MapError::new_err(format!("BER encode error: {e}"))
}

fn ber_encode<T: rasn::Encode>(val: &T, py: Python<'_>) -> PyResult<Py<PyBytes>> {
    let bytes = rasn::ber::encode(val).map_err(encode_err)?;
    Ok(PyBytes::new(py, &bytes).unbind())
}

fn ber_decode<T: rasn::Decode>(data: &[u8]) -> PyResult<T> {
    rasn::ber::decode(data).map_err(decode_err)
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
    #[pyo3(signature = (network_node_number, *, lmsi = None, gprs_node_indicator = false, additional_number = None))]
    fn new(
        network_node_number: Vec<u8>,
        lmsi: Option<Vec<u8>>,
        gprs_node_indicator: bool,
        additional_number: Option<Vec<u8>>,
    ) -> Self {
        Self {
            inner: LocationInfoWithLmsi {
                network_node_number: network_node_number.into(),
                lmsi: lmsi.map(Into::into),
                gprs_node_indicator: gprs_node_indicator.then_some(()),
                additional_number: additional_number.map(Into::into),
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

    #[getter]
    fn additional_number<'py>(&self, py: Python<'py>) -> Option<Bound<'py, PyBytes>> {
        self.inner
            .additional_number
            .as_ref()
            .map(|v| PyBytes::new(py, v))
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
                msisdn: msisdn.into(),
                sm_rp_pri,
                service_centre_address: service_centre_address.into(),
                gprs_support_indicator: gprs_support_indicator.then_some(()),
                sm_rp_mti: sm_rp_mti.map(Into::into),
                sm_rp_smea: None,
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
            inner: RoutingInfoForSmRes {
                imsi: imsi.into(),
                location_info_with_lmsi: location_info_with_lmsi.inner,
            },
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
                sm_rp_da: sm_rp_da.inner,
                sm_rp_oa: sm_rp_oa.inner,
                sm_rp_ui: sm_rp_ui.into(),
                imsi: imsi.map(Into::into),
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
                sm_rp_da: sm_rp_da.inner,
                sm_rp_oa: sm_rp_oa.inner,
                sm_rp_ui: sm_rp_ui.into(),
                // moreMessagesToSend is an ASN.1 NULL: a truthy flag sets it
                // present, everything else omits it.
                more_messages_to_send: more_messages_to_send.filter(|&b| b).map(|_| ()),
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
            inner: ReportSmDeliveryStatusArg {
                msisdn: msisdn.into(),
                service_centre_address: service_centre_address.into(),
                sm_delivery_outcome,
            },
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
                imsi: imsi.into(),
                msc_number: msc_number.into(),
                vlr_number: vlr_number.into(),
                lmsi: lmsi.map(Into::into),
                vlr_capability: None,
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
            inner: SendAuthenticationInfoArg {
                imsi: imsi.into(),
                number_of_requested_vectors: number_of_requested_vectors.into(),
                re_synchronisation_info: None,
                requesting_node_type: None,
            },
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

// ── Free functions ──────────────────────────────────────────────────────────

/// The MAP operation name for an operation code (e.g. `45 -> "sendRoutingInfoForSM"`).
#[pyfunction]
fn op_name(op_code: i64) -> &'static str {
    operation_name(op_code)
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

// ── Module wiring ───────────────────────────────────────────────────────────
fn add_contents(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("MapError", m.py().get_type::<MapError>())?;

    // Shared address / identity types.
    m.add_class::<PySmRpDa>()?;
    m.add_class::<PySmRpOa>()?;
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

    m.add_function(wrap_pyfunction!(op_name, m)?)?;

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
