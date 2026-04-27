use anyhow::anyhow;
use log::*;
use registry::{Data, Hive, Security};
use std::{
    ffi::OsString,
    sync::{Arc, atomic::{AtomicBool, Ordering}},
    thread,
    time::Duration,
};
use windows_service::define_windows_service;
use windows_service::service::{
    ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_dispatcher;
use std::time::SystemTime;
use x509_cert::der::DecodePem;
use x509_cert::time::Time;
use x509_cert::Certificate;

use keysas_lib::keysas_key::{KeysasHybridPubKeys, PublicKeys};

use crate::controller::{SecurityPolicy, ServiceController};
use crate::Config;

define_windows_service!(ffi_keysas_service, keysas_service_main);

fn run_service(stop: Arc<AtomicBool>) {
    let config = Config::default();
    let result = thread::spawn(move || -> Result<(), anyhow::Error> {
        info!("run_service: loading security policy...");
        info!("run_service: loading certificates...");
        info!("run_service: initializing ServiceController...");

        if let Err(e) = ServiceController::init(&config) {
            error!("ServiceController::init failed: {e:#}");
            return Err(anyhow!("ServiceController::init failed: {e:#}"));
        }

        info!("run_service: ServiceController started, entering main loop");

        while !stop.load(Ordering::Relaxed) {
            thread::sleep(Duration::from_secs(1));
        }
        info!("run_service: stop signal received, exiting");
        Ok(())
    })
    .join();

    match result {
        Ok(Ok(())) => info!("run_service: thread exited normally"),
        Ok(Err(e)) => error!("run_service: thread exited with error: {e:#}"),
        Err(_) => error!("run_service: thread panicked"),
    }
}

fn keysas_service_main(_args: Vec<OsString>) {
    let stop = Arc::new(AtomicBool::new(false));
    let stop_for_handler = stop.clone();

    let event_handler = move |event| -> ServiceControlHandlerResult {
        match event {
            ServiceControl::Stop => {
                stop_for_handler.store(true, Ordering::Relaxed);
                ServiceControlHandlerResult::NoError
            },
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };

    // Register the service handler — MUST happen before any other SCM interaction.
    let status_handle = match service_control_handler::register("Keysas Service", event_handler) {
        Ok(h) => h,
        Err(_) => return,
    };

    // Report START_PENDING immediately so the SCM does not time out while we
    // initialise the logger and the rest of the service.
    let _ = status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::StartPending,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 1,
        wait_hint: Duration::from_secs(30),
        process_id: None,
    });

    // Initialise the Windows Event Log now that we are inside the service
    // entry point (running under LocalSystem, HKLM write is guaranteed).
    // Non-fatal: if eventlog fails we fall back to a no-op logger so the
    // service still starts.
    if eventlog::init("Keysas Service", Level::Info).is_err() {
        let _ = simple_logger::SimpleLogger::new()
            .with_level(LevelFilter::Info)
            .init();
    }

    info!("Keysas service: entry point reached, initialising…");

    // Report RUNNING before the heavy initialisation so the SCM is satisfied.
    if let Err(e) = status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Running,
        controls_accepted: ServiceControlAccept::STOP,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    }) {
        error!("Failed to set service status to Running: {e}");
        return;
    }

    info!("Keysas service started");

    // Start the service
    run_service(stop);

    // If the thread exits stop the service
    if let Err(e) = status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Stopped,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    }) {
        error!("Failed to set service status to stop: {e}");
        return;
    };

    warn!("Keysas service stopped");
}

pub fn start_windows_service(debug: bool) -> Result<(), anyhow::Error> {
    if debug {
        run_service(Arc::new(AtomicBool::new(false)));
    } else {
        service_dispatcher::start("Keysas Service", ffi_keysas_service)?;
    }

    Ok(())
}

/// Returns an error if `cert` has passed its `notAfter` validity date.
fn check_not_expired(cert: &Certificate, label: &str) -> Result<(), anyhow::Error> {
    let not_after_unix = match &cert.tbs_certificate.validity.not_after {
        Time::UtcTime(t) => t.to_unix_duration(),
        Time::GeneralTime(t) => t.to_unix_duration(),
    };
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    if now > not_after_unix {
        return Err(anyhow!("certificate '{label}' is expired"));
    }
    Ok(())
}

pub fn load_security_policy(_config: &Config) -> Result<SecurityPolicy, anyhow::Error> {
    // Set user language
    // TODO - Add it in the installation configuration
    rust_i18n::set_locale("fr");

    let regkey = match Hive::LocalMachine.open(
        r"SYSTEM\CurrentControlSet\Services\Keysas Service\config",
        Security::Read,
    ) {
        Ok(r) => r,
        Err(e) => {
            return Err(anyhow!(
                "Failed to open driver interface: Failed to open registry key {e}"
            ));
        }
    };

    let policy = SecurityPolicy {
        disable_unsigned_usb: matches!(regkey.value("DisableUnsignedUsb"), Ok(Data::U32(1))),
        allow_user_usb_authorization: matches!(
            regkey.value("AllowUserUsbAuthorization"),
            Ok(Data::U32(1))
        ),
        allow_user_file_read: matches!(regkey.value("AllowUserFileRead"), Ok(Data::U32(1))),
        allow_user_file_write: matches!(regkey.value("AllowUserFileWrite"), Ok(Data::U32(1))),
    };

    Ok(policy)
}

/// Persist the four policy flags to the registry.
/// The daemon runs as SYSTEM so it can write HKLM without UAC.
pub fn write_policy_settings(policy: &SecurityPolicy) -> Result<(), anyhow::Error> {
    let regkey = Hive::LocalMachine
        .open(
            r"SYSTEM\CurrentControlSet\Services\Keysas Service\config",
            Security::Write,
        )
        .map_err(|e| anyhow!("Failed to open registry key for write: {e}"))?;

    regkey.set_value(
        "DisableUnsignedUsb",
        &Data::U32(policy.disable_unsigned_usb as u32),
    )?;
    regkey.set_value(
        "AllowUserUsbAuthorization",
        &Data::U32(policy.allow_user_usb_authorization as u32),
    )?;
    regkey.set_value(
        "AllowUserFileRead",
        &Data::U32(policy.allow_user_file_read as u32),
    )?;
    regkey.set_value(
        "AllowUserFileWrite",
        &Data::U32(policy.allow_user_file_write as u32),
    )?;

    Ok(())
}

pub fn load_certificates(
    _config: &Config,
) -> Result<
    (
        KeysasHybridPubKeys,
        KeysasHybridPubKeys,
        Certificate,
        Certificate,
    ),
    anyhow::Error,
> {
    let regkey = match Hive::LocalMachine.open(
        r"SYSTEM\CurrentControlSet\Services\Keysas Service\config",
        Security::Read,
    ) {
        Ok(r) => r,
        Err(e) => {
            return Err(anyhow!(
                "Failed to open driver interface: Failed to open registry key {e}"
            ));
        }
    };

    let st_cl_path = match regkey.value("StCaClCert") {
        Ok(Data::String(s)) => s.to_string_lossy(),
        _ => {
            return Err(anyhow!("Failed to get value to path to ST CL certificate"));
        }
    };

    let st_pq_path = match regkey.value("StCaPqCert") {
        Ok(Data::String(s)) => s.to_string_lossy(),
        _ => {
            return Err(anyhow!("Failed to get value to path to ST PQ certificate"));
        }
    };

    let usb_cl_path = match regkey.value("UsbCaClCert") {
        Ok(Data::String(s)) => s.to_string_lossy(),
        _ => {
            return Err(anyhow!("Failed to get value to path to ST CL certificate"));
        }
    };

    let usb_pq_path = match regkey.value("UsbCaPqCert") {
        Ok(Data::String(s)) => s.to_string_lossy(),
        _ => {
            return Err(anyhow!("Failed to get value to path to ST PQ certificate"));
        }
    };

    let st_ca_pub = match KeysasHybridPubKeys::get_pubkeys_from_certs(&st_cl_path, &st_pq_path) {
        Ok(Some(pk)) => pk,
        Ok(None) => {
            return Err(anyhow!("No public key found in station CA certificates"));
        }
        Err(e) => {
            return Err(anyhow!("Failed to extract station CA certificates: {e}"));
        }
    };

    let usb_ca_pub = match KeysasHybridPubKeys::get_pubkeys_from_certs(&usb_cl_path, &usb_pq_path) {
        Ok(Some(pk)) => pk,
        Ok(None) => {
            return Err(anyhow!("No public key found in USB CA certificates"));
        }
        Err(e) => {
            return Err(anyhow!("Failed to extract USB CA certificates: {e}"));
        }
    };

    // Parse and expiry-check USB CA certificates.
    let usb_cl_bytes = std::fs::read(&*usb_cl_path)
        .map_err(|e| anyhow!("Cannot read USB CA ED25519 certificate {usb_cl_path:?}: {e}"))?;
    let usb_ca_cert_cl = Certificate::from_pem(&usb_cl_bytes)
        .map_err(|e| anyhow!("Cannot parse USB CA ED25519 certificate: {e}"))?;
    check_not_expired(&usb_ca_cert_cl, "USB CA ED25519")?;

    let usb_pq_bytes = std::fs::read(&*usb_pq_path)
        .map_err(|e| anyhow!("Cannot read USB CA ML-DSA87 certificate {usb_pq_path:?}: {e}"))?;
    let usb_ca_cert_pq = Certificate::from_pem(&usb_pq_bytes)
        .map_err(|e| anyhow!("Cannot parse USB CA ML-DSA87 certificate: {e}"))?;
    check_not_expired(&usb_ca_cert_pq, "USB CA ML-DSA87")?;

    // Load and expiry-check station CA certificates (also used for file-report validation).
    let st_cl_bytes = std::fs::read(&*st_cl_path)
        .map_err(|e| anyhow!("Cannot read station CA ED25519 certificate {st_cl_path:?}: {e}"))?;
    let st_ca_cert_cl = Certificate::from_pem(&st_cl_bytes)
        .map_err(|e| anyhow!("Cannot parse station CA ED25519 certificate: {e}"))?;
    check_not_expired(&st_ca_cert_cl, "station CA ED25519")?;

    let st_pq_bytes = std::fs::read(&*st_pq_path)
        .map_err(|e| anyhow!("Cannot read station CA ML-DSA87 certificate {st_pq_path:?}: {e}"))?;
    let st_ca_cert_pq = Certificate::from_pem(&st_pq_bytes)
        .map_err(|e| anyhow!("Cannot parse station CA ML-DSA87 certificate: {e}"))?;
    check_not_expired(&st_ca_cert_pq, "station CA ML-DSA87")?;

    Ok((st_ca_pub, usb_ca_pub, st_ca_cert_cl, st_ca_cert_pq))
}
