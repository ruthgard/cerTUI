
use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::process::{Command, Stdio};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertInfo {
    pub subject: String,
    pub issuer: String,
    pub not_before: Option<DateTime<Utc>>,
    pub not_after: Option<DateTime<Utc>>,
    pub sha256_fingerprint: Option<String>,
    pub san: Vec<String>,
    pub pem: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InspectReport {
    pub host: String,
    pub port: u16,
    pub sni: Option<String>,
    pub certs: Vec<CertInfo>,
}

/// Call `openssl s_client -showcerts` and return the raw output
fn openssl_s_client(host: &str, port: u16, sni: Option<&str>) -> Result<String> {
    let target = format!("{host}:{port}");
    let mut cmd = Command::new("openssl");
    cmd.arg("s_client")
        .arg("-connect").arg(&target)
        .arg("-showcerts")
        .stdin(Stdio::null())
        .stderr(Stdio::piped())
        .stdout(Stdio::piped());

    if let Some(server_name) = sni {
        cmd.arg("-servername").arg(server_name);
    }

    let out = cmd.output().with_context(|| "failed to execute openssl s_client")?;
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();

    // Some OpenSSL versions print certs on stdout, errors on stderr — we keep stdout.
    // Still, include stderr if stdout is empty but stderr has PEM (rare).
    if stdout.contains("BEGIN CERTIFICATE") {
        Ok(stdout)
    } else if stderr.contains("BEGIN CERTIFICATE") {
        Ok(stderr)
    } else {
        let combined = format!("{}\n{}", stdout, stderr);
        if combined.contains("BEGIN CERTIFICATE") {
            Ok(combined)
        } else {
            Err(anyhow::anyhow!("No certificates found. OpenSSL output:\n{}", combined))
        }
    }
}

/// Extract all PEM certificate blocks from a string
fn extract_pems(s: &str) -> Vec<String> {
    let re = Regex::new(r"-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----").unwrap();
    re.find_iter(s).map(|m| m.as_str().to_string()).collect()
}

fn parse_pem_cert(pem_str: &str) -> Result<CertInfo> {
    use x509_parser::{prelude::FromDer, traits::FromBer};
    // Decode PEM to DER
    let block = pem::parse(pem_str.as_bytes()).context("failed to parse PEM")?;
    let der = block.contents;
    let (_, x509) = x509_parser::certificate::X509Certificate::from_der(&der)
        .or_else(|_| {
            // some certs may parse with BER fallback
            x509_parser::certificate::X509Certificate::from_ber(&der).map(|(_, c)| ((), c))
        })
        .map_err(|e| anyhow::anyhow!("failed to parse X509: {e}"))?;

    // Subject/Issuer
    let subject = x509.subject().to_string();
    let issuer = x509.issuer().to_string();

    // Validity
    let not_before = x509.validity().not_before.to_datetime().map(|dt| DateTime::<Utc>::from(dt));
    let not_after  = x509.validity().not_after .to_datetime().map(|dt| DateTime::<Utc>::from(dt));

    // SANs
    let mut san = Vec::new();
    if let Some(ext) = x509.subject_alternative_name() {
        for name in ext.value.general_names.iter() {
            if let x509_parser::extensions::GeneralName::DNSName(d) = name {
                san.push(d.to_string());
            }
        }
    }

    // Fingerprint (SHA-256)
    use sha2::{Digest, Sha256};
    let fp = {
        let mut hasher = Sha256::new();
        hasher.update(&der);
        let res = hasher.finalize();
        Some(res.iter().map(|b| format!("{:02X}", b)).collect::<Vec<_>>().join(":"))
    };

    Ok(CertInfo {
        subject,
        issuer,
        not_before,
        not_after,
        sha256_fingerprint: fp,
        san,
        pem: pem_str.to_string(),
    })
}

pub fn inspect_remote(host: &str, port: u16, sni: Option<&str>) -> Result<InspectReport> {
    let output = openssl_s_client(host, port, sni)?;
    let pems = extract_pems(&output);
    let mut certs = Vec::new();
    for p in pems {
        match parse_pem_cert(&p) {
            Ok(ci) => certs.push(ci),
            Err(e) => eprintln!("warn: failed to parse one cert: {e}"),
        }
    }
    Ok(InspectReport {
        host: host.to_string(),
        port,
        sni: sni.map(|s| s.to_string()),
        certs,
    })
}

/// Utility: days until expiry for convenience
pub fn days_until_expiry(ci: &CertInfo) -> Option<i64> {
    ci.not_after.map(|na| {
        let now = Utc::now();
        let dur = na.signed_duration_since(now);
        dur.num_days()
    })
}
