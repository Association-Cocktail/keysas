use anyhow::anyhow;
use std::fs;
use std::time::SystemTime;
use x509_cert::der::DecodePem;
use x509_cert::time::Time;
use x509_cert::Certificate;

use keysas_lib::keysas_key::{KeysasHybridPubKeys, PublicKeys};

use crate::controller::SecurityPolicy;
use crate::Config;

pub fn load_security_policy(config: &Config) -> Result<SecurityPolicy, anyhow::Error> {
    // Set user language
    // TODO - Add it in the installation configuration
    rust_i18n::set_locale("fr");

    // Load administration security policy
    let config_path = std::env::current_dir()?;
    // config_path.push(&config.config);
    // &config.config
    let config_toml = match fs::read_to_string(&config.config) {
        Ok(s) => s,
        Err(e) => {
            return Err(anyhow!(
                "Failed to read configuration file {:#?} from {:#?}: {e}",
                &config.config,
                config_path.to_string_lossy()
            ));
        }
    };

    let policy: SecurityPolicy = match toml::from_str(&config_toml) {
        Ok(p) => p,
        Err(e) => {
            return Err(anyhow!(
                "Failed to parse configuration file {:#?}: {e}",
                &config.config
            ));
        }
    };

    Ok(policy)
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

pub fn load_certificates(
    config: &Config,
) -> Result<
    (
        KeysasHybridPubKeys,
        KeysasHybridPubKeys,
        Certificate,
        Certificate,
    ),
    anyhow::Error,
> {
    let st_ca_pub =
        match KeysasHybridPubKeys::get_pubkeys_from_certs(&config.ca_cert_cl, &config.ca_cert_pq) {
            Ok(Some(pk)) => pk,
            Ok(None) => {
                return Err(anyhow!("No public key found in station CA certificates"));
            }
            Err(e) => {
                return Err(anyhow!("Failed to extract station CA certificates: {e}"));
            }
        };

    let usb_ca_pub =
        match KeysasHybridPubKeys::get_pubkeys_from_certs(&config.usb_ca_cl, &config.usb_ca_pq) {
            Ok(Some(pk)) => pk,
            Ok(None) => {
                return Err(anyhow!("No public key found in USB CA certificates"));
            }
            Err(e) => {
                return Err(anyhow!("Failed to extract USB CA certificates: {e}"));
            }
        };

    // Parse and expiry-check USB CA certificates.
    let usb_cl_bytes = fs::read(&config.usb_ca_cl).map_err(|e| {
        anyhow!("Cannot read USB CA ED25519 certificate {:?}: {e}", &config.usb_ca_cl)
    })?;
    let usb_ca_cert_cl = Certificate::from_pem(&usb_cl_bytes)
        .map_err(|e| anyhow!("Cannot parse USB CA ED25519 certificate: {e}"))?;
    check_not_expired(&usb_ca_cert_cl, "USB CA ED25519")?;

    let usb_pq_bytes = fs::read(&config.usb_ca_pq).map_err(|e| {
        anyhow!("Cannot read USB CA ML-DSA87 certificate {:?}: {e}", &config.usb_ca_pq)
    })?;
    let usb_ca_cert_pq = Certificate::from_pem(&usb_pq_bytes)
        .map_err(|e| anyhow!("Cannot parse USB CA ML-DSA87 certificate: {e}"))?;
    check_not_expired(&usb_ca_cert_pq, "USB CA ML-DSA87")?;

    // Load and expiry-check station CA certificates (also used for file-report validation).
    let st_cl_bytes = fs::read(&config.ca_cert_cl).map_err(|e| {
        anyhow!(
            "Cannot read station CA ED25519 certificate {:?}: {e}",
            &config.ca_cert_cl
        )
    })?;
    let st_ca_cert_cl = Certificate::from_pem(&st_cl_bytes)
        .map_err(|e| anyhow!("Cannot parse station CA ED25519 certificate: {e}"))?;
    check_not_expired(&st_ca_cert_cl, "station CA ED25519")?;

    let st_pq_bytes = fs::read(&config.ca_cert_pq).map_err(|e| {
        anyhow!(
            "Cannot read station CA ML-DSA87 certificate {:?}: {e}",
            &config.ca_cert_pq
        )
    })?;
    let st_ca_cert_pq = Certificate::from_pem(&st_pq_bytes)
        .map_err(|e| anyhow!("Cannot parse station CA ML-DSA87 certificate: {e}"))?;
    check_not_expired(&st_ca_cert_pq, "station CA ML-DSA87")?;

    Ok((st_ca_pub, usb_ca_pub, st_ca_cert_cl, st_ca_cert_pq))
}
