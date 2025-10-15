use anyhow::{Context, Result};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use time::OffsetDateTime;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertInfo {
    pub subject: String,
    pub issuer: String,
    /// Seconds since Unix epoch (UTC)
    pub not_before_ts: Option<i64>,
    /// Seconds since Unix epoch (UTC)
    pub not_after_ts: Option<i64>,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalInspectReport {
    pub path: PathBuf,
    pub certs: Vec<CertInfo>,
}

/// Call `openssl s_client -showcerts` and return the raw output
fn openssl_s_client(host: &str, port: u16, sni: Option<&str>) -> Result<String> {
    let target = format!("{host}:{port}");
    let mut cmd = Command::new("openssl");
    cmd.arg("s_client")
        .arg("-connect")
        .arg(&target)
        .arg("-showcerts")
        .stdin(Stdio::null())
        .stderr(Stdio::piped())
        .stdout(Stdio::piped());

    if let Some(server_name) = sni {
        cmd.arg("-servername").arg(server_name);
    }

    let out = cmd
        .output()
        .with_context(|| "failed to execute openssl s_client")?;
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();

    if stdout.contains("BEGIN CERTIFICATE") {
        Ok(stdout)
    } else if stderr.contains("BEGIN CERTIFICATE") {
        Ok(stderr)
    } else {
        let combined = format!("{}\n{}", stdout, stderr);
        if combined.contains("BEGIN CERTIFICATE") {
            Ok(combined)
        } else {
            Err(anyhow::anyhow!(
                "No certificates found. OpenSSL output:\n{}",
                combined
            ))
        }
    }
}

/// Extract all PEM certificate blocks from a string
fn extract_pems(s: &str) -> Vec<String> {
    let re = Regex::new(r"-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----").unwrap();
    re.find_iter(s).map(|m| m.as_str().to_string()).collect()
}

fn parse_pem_cert(pem_str: &str) -> Result<CertInfo> {
    use x509_parser::prelude::FromDer;

    // Decode PEM to DER
    let block = pem::parse(pem_str.as_bytes()).context("failed to parse PEM")?;
    let der = block.contents();

    let (_, x509) = x509_parser::certificate::X509Certificate::from_der(&der)
        .map_err(|e| anyhow::anyhow!("failed to parse X509: {e}"))?;

    // Subject/Issuer
    let subject = x509.subject().to_string();
    let issuer = x509.issuer().to_string();

    // Validity -> epoch seconds
    let nb = x509.validity().not_before.to_datetime();
    let na = x509.validity().not_after.to_datetime();
    let not_before_ts = Some(nb.unix_timestamp());
    let not_after_ts = Some(na.unix_timestamp());

    // SANs
    let mut san = Vec::new();
    if let Ok(Some(ext)) = x509.subject_alternative_name() {
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
        Some(
            res.iter()
                .map(|b| format!("{:02X}", b))
                .collect::<Vec<_>>()
                .join(":"),
        )
    };

    Ok(CertInfo {
        subject,
        issuer,
        not_before_ts,
        not_after_ts,
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
    let na = ci.not_after_ts?;
    let now = OffsetDateTime::now_utc().unix_timestamp();
    Some((na - now) / 86_400)
}

fn read_pem_file(path: &Path) -> Result<Vec<CertInfo>> {
    let data =
        fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))?;
    let pems = extract_pems(&data);
    if pems.is_empty() {
        anyhow::bail!("no PEM blocks found in {}", path.display());
    }
    let mut certs = Vec::new();
    for pem in pems {
        match parse_pem_cert(&pem) {
            Ok(ci) => certs.push(ci),
            Err(err) => eprintln!(
                "warn: {}: failed to parse certificate: {err}",
                path.display()
            ),
        }
    }
    if certs.is_empty() {
        anyhow::bail!("failed to parse certificates from {}", path.display());
    }
    Ok(certs)
}

fn is_cert_like(path: &Path) -> bool {
    matches!(
        path.extension()
            .and_then(|e| e.to_str())
            .map(|s| s.to_ascii_lowercase()),
        Some(ext) if matches!(ext.as_str(), "pem" | "crt" | "cer" | "cert")
    )
}

pub fn inspect_local_path<P: AsRef<Path>>(path: P) -> Result<LocalInspectReport> {
    let path = path.as_ref();
    let meta = fs::metadata(path)
        .with_context(|| format!("{} does not exist or is not accessible", path.display()))?;

    let mut collected = Vec::new();
    if meta.is_file() {
        collected.extend(read_pem_file(path)?);
    } else if meta.is_dir() {
        for entry in fs::read_dir(path)
            .with_context(|| format!("failed to read directory {}", path.display()))?
        {
            let entry = entry?;
            let entry_path = entry.path();
            if entry_path.is_file() && is_cert_like(&entry_path) {
                match read_pem_file(&entry_path) {
                    Ok(mut certs) => collected.append(&mut certs),
                    Err(err) => eprintln!("warn: {}: {}", entry_path.display(), err),
                }
            }
        }
    } else {
        anyhow::bail!("{} is neither a file nor a directory", path.display());
    }

    if collected.is_empty() {
        anyhow::bail!("no certificates parsed from {}", path.display());
    }

    Ok(LocalInspectReport {
        path: path.to_path_buf(),
        certs: collected,
    })
}
