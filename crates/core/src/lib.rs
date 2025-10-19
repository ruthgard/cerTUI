use anyhow::{anyhow, Context, Result};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::env;
use std::fmt;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use tempfile::NamedTempFile;
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
    pub requires_mtls: bool,
    #[serde(default)]
    pub client_ca_names: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustValidation {
    pub trusted: bool,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalInspectReport {
    pub path: PathBuf,
    pub certs: Vec<CertInfo>,
    pub format: LocalCertFormat,
    pub is_dir: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtectedStoreKind {
    Pkcs12,
    JavaKeystore,
}

impl ProtectedStoreKind {
    pub fn label(self) -> &'static str {
        match self {
            ProtectedStoreKind::Pkcs12 => "PKCS#12",
            ProtectedStoreKind::JavaKeystore => "Java keystore",
        }
    }
}

#[derive(Debug)]
pub struct PasswordRequiredError {
    path: PathBuf,
    kind: ProtectedStoreKind,
    last_error: Option<String>,
}

impl PasswordRequiredError {
    pub fn new(path: PathBuf, kind: ProtectedStoreKind, last_error: Option<String>) -> Self {
        Self {
            path,
            kind,
            last_error,
        }
    }

    pub fn kind(&self) -> ProtectedStoreKind {
        self.kind
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn last_error(&self) -> Option<&str> {
        self.last_error.as_deref()
    }
}

impl fmt::Display for PasswordRequiredError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "password required to open {} ({})",
            self.path.display(),
            self.kind.label()
        )?;
        if let Some(err) = self.last_error.as_ref() {
            write!(f, ": {err}")?;
        }
        Ok(())
    }
}

impl std::error::Error for PasswordRequiredError {}

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

fn parse_client_ca_names(output: &str) -> Vec<String> {
    let mut names = Vec::new();
    let mut lines = output.lines();
    while let Some(line) = lines.next() {
        if line
            .trim()
            .eq_ignore_ascii_case("acceptable client certificate CA names")
        {
            for name_line in &mut lines {
                let trimmed = name_line.trim();
                if trimmed.is_empty()
                    || trimmed.eq_ignore_ascii_case("requested signature algorithms:")
                    || trimmed.eq_ignore_ascii_case("client certificate types:")
                    || trimmed.starts_with("---")
                {
                    break;
                }
                names.push(trimmed.to_string());
            }
            break;
        }
    }
    names
}

fn parse_requires_mtls(output: &str) -> (bool, Vec<String>) {
    let lower = output.to_ascii_lowercase();
    let has_req = lower.contains("acceptable client certificate ca names")
        || lower.contains("client certificate types");
    let mut requires = has_req;
    if !requires {
        requires = lower.contains("alert handshake failure") && lower.contains("certificate");
    }
    let names = if requires {
        parse_client_ca_names(output)
    } else {
        Vec::new()
    };
    (requires, names)
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
    let (requires_mtls, client_ca_names) = parse_requires_mtls(&output);
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
        requires_mtls,
        client_ca_names,
    })
}

pub fn verify_with_truststore(
    trust_certs: &[CertInfo],
    target_chain: &[CertInfo],
) -> Result<TrustValidation> {
    if trust_certs.is_empty() {
        return Err(anyhow!("trust store has no certificates"));
    }
    if target_chain.is_empty() {
        return Err(anyhow!("target entry has no certificates"));
    }

    let mut trust_file =
        NamedTempFile::new().context("failed to create temporary trust store file")?;
    for cert in trust_certs {
        writeln!(trust_file, "{}", cert.pem)?;
    }
    trust_file
        .flush()
        .context("failed to write temporary trust store file")?;

    let mut leaf_file =
        NamedTempFile::new().context("failed to create temporary leaf certificate file")?;
    writeln!(leaf_file, "{}", target_chain[0].pem)?;
    leaf_file
        .flush()
        .context("failed to write temporary leaf certificate file")?;

    let intermediate_file = if target_chain.len() > 1 {
        let mut file =
            NamedTempFile::new().context("failed to create temporary intermediates file")?;
        for cert in &target_chain[1..] {
            writeln!(file, "{}", cert.pem)?;
        }
        file.flush()
            .context("failed to write temporary intermediates file")?;
        Some(file)
    } else {
        None
    };

    let mut cmd = Command::new("openssl");
    cmd.arg("verify").arg("-CAfile").arg(trust_file.path());
    if let Some(intermediate) = intermediate_file.as_ref() {
        cmd.arg("-untrusted").arg(intermediate.path());
    }
    cmd.arg(leaf_file.path());

    let output = cmd
        .output()
        .with_context(|| "failed to execute openssl verify")?;

    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    let trusted = output.status.success();

    let mut message_parts = Vec::new();
    if !stdout.is_empty() {
        message_parts.push(stdout);
    }
    if !stderr.is_empty() {
        message_parts.push(stderr);
    }
    let message = if message_parts.is_empty() {
        if trusted {
            "Verification succeeded.".to_string()
        } else {
            "Verification failed.".to_string()
        }
    } else {
        message_parts.join(" ")
    };

    Ok(TrustValidation { trusted, message })
}

/// Utility: days until expiry for convenience
pub fn days_until_expiry(ci: &CertInfo) -> Option<i64> {
    let na = ci.not_after_ts?;
    let now = OffsetDateTime::now_utc().unix_timestamp();
    Some((na - now) / 86_400)
}

fn parse_pem_bundle(bundle: &str, context: &str) -> Result<Vec<CertInfo>> {
    let pems = extract_pems(bundle);
    if pems.is_empty() {
        anyhow::bail!("no PEM blocks found in {context}");
    }
    let mut certs = Vec::new();
    for pem in pems {
        match parse_pem_cert(&pem) {
            Ok(ci) => certs.push(ci),
            Err(err) => eprintln!("warn: {context}: failed to parse certificate: {err}"),
        }
    }
    if certs.is_empty() {
        anyhow::bail!("failed to parse certificates from {context}");
    }
    Ok(certs)
}

fn file_starts_with(path: &Path, needle: &[u8]) -> Result<bool> {
    let mut file = fs::File::open(path)
        .with_context(|| format!("failed to open {} for inspection", path.display()))?;
    let mut buf = vec![0u8; needle.len()];
    let read = file.read(&mut buf)?;
    Ok(read >= needle.len() && buf.starts_with(needle))
}

fn detect_pkcs7_format(path: &Path) -> Result<Pkcs7Format> {
    if file_starts_with(path, b"-----BEGIN")? {
        Ok(Pkcs7Format::Pem)
    } else {
        Ok(Pkcs7Format::Der)
    }
}

fn looks_like_jks(path: &Path) -> Result<bool> {
    let mut file = fs::File::open(path)
        .with_context(|| format!("failed to open {} for inspection", path.display()))?;
    let mut magic = [0u8; 4];
    let read = file.read(&mut magic)?;
    Ok(read == 4 && magic == [0xFE, 0xED, 0xFE, 0xED])
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LocalCertFormat {
    Pem,
    Pkcs12,
    Pkcs7,
    JavaKeystore,
}

struct LocalCertFormatInfo {
    format: LocalCertFormat,
    preferred_types: Vec<&'static str>,
    pkcs7_format: Option<Pkcs7Format>,
}

enum Pkcs7Format {
    Pem,
    Der,
}

enum PasswordKind {
    Pkcs12,
    JavaKeystore,
}

impl PasswordKind {
    fn store_kind(self) -> ProtectedStoreKind {
        match self {
            PasswordKind::Pkcs12 => ProtectedStoreKind::Pkcs12,
            PasswordKind::JavaKeystore => ProtectedStoreKind::JavaKeystore,
        }
    }
}

fn password_candidates(kind: PasswordKind, override_password: Option<&str>) -> Vec<String> {
    let mut seen: Vec<String> = Vec::new();
    let push = |value: String, seen: &mut Vec<String>| {
        if !seen.iter().any(|existing| existing == &value) {
            seen.push(value);
        }
    };

    if let Some(primary) = override_password {
        push(primary.to_string(), &mut seen);
    }

    let env_vars = match kind {
        PasswordKind::Pkcs12 => ["OMARCHY_PKCS12_PASSWORD", "OMARCHY_CERT_PASSWORD"],
        PasswordKind::JavaKeystore => ["OMARCHY_KEYSTORE_PASSWORD", "OMARCHY_CERT_PASSWORD"],
    };
    for var in env_vars {
        if let Ok(val) = env::var(var) {
            push(val, &mut seen);
        }
    }

    let defaults: &[&str] = match kind {
        PasswordKind::Pkcs12 => &["", "changeit"],
        PasswordKind::JavaKeystore => &["changeit", ""],
    };
    for default in defaults {
        push(default.to_string(), &mut seen);
    }
    seen
}

fn detect_cert_format(path: &Path) -> Result<LocalCertFormatInfo> {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .map(|s| s.to_ascii_lowercase());
    match ext.as_deref() {
        Some("pem") | Some("crt") | Some("cer") | Some("cert") => Ok(LocalCertFormatInfo {
            format: LocalCertFormat::Pem,
            preferred_types: Vec::new(),
            pkcs7_format: None,
        }),
        Some("p12") | Some("pfx") | Some("pkcs12") => Ok(LocalCertFormatInfo {
            format: LocalCertFormat::Pkcs12,
            preferred_types: Vec::new(),
            pkcs7_format: None,
        }),
        Some("p7b") | Some("p7c") | Some("pkcs7") => {
            let format = detect_pkcs7_format(path)?;
            Ok(LocalCertFormatInfo {
                format: LocalCertFormat::Pkcs7,
                preferred_types: Vec::new(),
                pkcs7_format: Some(format),
            })
        }
        Some("jks") => Ok(LocalCertFormatInfo {
            format: LocalCertFormat::JavaKeystore,
            preferred_types: vec!["JKS"],
            pkcs7_format: None,
        }),
        Some("jceks") => Ok(LocalCertFormatInfo {
            format: LocalCertFormat::JavaKeystore,
            preferred_types: vec!["JCEKS"],
            pkcs7_format: None,
        }),
        Some("keystore") | Some("truststore") => Ok(LocalCertFormatInfo {
            format: LocalCertFormat::JavaKeystore,
            preferred_types: vec!["JKS", "PKCS12"],
            pkcs7_format: None,
        }),
        _ => {
            if looks_like_jks(path).unwrap_or(false) {
                return Ok(LocalCertFormatInfo {
                    format: LocalCertFormat::JavaKeystore,
                    preferred_types: vec!["JKS", "PKCS12"],
                    pkcs7_format: None,
                });
            }
            Ok(LocalCertFormatInfo {
                format: LocalCertFormat::Pem,
                preferred_types: Vec::new(),
                pkcs7_format: None,
            })
        }
    }
}

fn read_cert_file(
    path: &Path,
    override_password: Option<&str>,
) -> Result<(Vec<CertInfo>, LocalCertFormat)> {
    let info = detect_cert_format(path)?;
    match info.format {
        LocalCertFormat::Pem => Ok((read_pem_file(path)?, LocalCertFormat::Pem)),
        LocalCertFormat::Pkcs12 => Ok((
            read_pkcs12_file(path, override_password)?,
            LocalCertFormat::Pkcs12,
        )),
        LocalCertFormat::Pkcs7 => Ok((
            read_pkcs7_file(path, info.pkcs7_format.unwrap_or(Pkcs7Format::Pem))?,
            LocalCertFormat::Pkcs7,
        )),
        LocalCertFormat::JavaKeystore => Ok((
            read_java_keystore(path, &info.preferred_types, override_password)?,
            LocalCertFormat::JavaKeystore,
        )),
    }
}

fn read_pkcs12_file(path: &Path, override_password: Option<&str>) -> Result<Vec<CertInfo>> {
    let mut last_error: Option<String> = None;
    for password in password_candidates(PasswordKind::Pkcs12, override_password) {
        match run_pkcs12(path, &password) {
            Ok(bundle) => {
                return parse_pem_bundle(&bundle, &format!("{} (PKCS#12)", path.display()))
            }
            Err(err) => {
                last_error = Some(err.to_string());
            }
        }
    }
    let last_error = last_error.or_else(|| Some("no candidate passwords accepted".to_string()));
    Err(PasswordRequiredError::new(
        path.to_path_buf(),
        PasswordKind::Pkcs12.store_kind(),
        last_error,
    )
    .into())
}

fn read_pkcs7_file(path: &Path, format: Pkcs7Format) -> Result<Vec<CertInfo>> {
    let bundle = run_pkcs7(path, format)?;
    parse_pem_bundle(&bundle, &format!("{} (PKCS#7)", path.display()))
}

fn read_java_keystore(
    path: &Path,
    preferred_types: &[&str],
    override_password: Option<&str>,
) -> Result<Vec<CertInfo>> {
    let passwords = password_candidates(PasswordKind::JavaKeystore, override_password);
    let store_types = java_store_type_candidates(preferred_types);
    let mut last_error: Option<String> = None;

    for password in passwords {
        for store_type in &store_types {
            match run_keytool(path, store_type.as_deref(), &password) {
                Ok(bundle) => {
                    return parse_pem_bundle(
                        &bundle,
                        &format!("{} (keytool export)", path.display()),
                    )
                }
                Err(err) => {
                    last_error = Some(err.to_string());
                }
            }
        }
    }

    let mut last_error = last_error;
    if env::var("OMARCHY_KEYSTORE_PASSWORD").is_err()
        && env::var("OMARCHY_CERT_PASSWORD").is_err()
        && last_error.is_none()
    {
        last_error = Some(
            "set OMARCHY_KEYSTORE_PASSWORD or OMARCHY_CERT_PASSWORD with the keystore password"
                .to_string(),
        );
    }
    let last_error = last_error.or_else(|| Some("no candidate passwords accepted".to_string()));
    Err(PasswordRequiredError::new(
        path.to_path_buf(),
        PasswordKind::JavaKeystore.store_kind(),
        last_error,
    )
    .into())
}

fn java_store_type_candidates(preferred: &[&str]) -> Vec<Option<String>> {
    let mut candidates: Vec<Option<String>> = Vec::new();
    let push = |value: Option<String>, candidates: &mut Vec<Option<String>>| {
        if !candidates
            .iter()
            .any(|existing| existing.as_deref() == value.as_deref())
        {
            candidates.push(value);
        }
    };

    push(None, &mut candidates);
    for ty in preferred {
        push(Some(ty.to_ascii_uppercase()), &mut candidates);
    }
    for fallback in ["JKS", "PKCS12", "JCEKS"] {
        push(Some(fallback.to_string()), &mut candidates);
    }
    candidates
}

fn run_pkcs12(path: &Path, password: &str) -> Result<String> {
    let attempt_args: &[&[&str]] = &[
        &[],
        &["-legacy"],
        &["-provider", "legacy"],
        &["-provider", "default", "-provider", "legacy"],
    ];
    let mut first_error: Option<String> = None;

    for (idx, extra) in attempt_args.iter().enumerate() {
        match run_pkcs12_once(path, password, extra) {
            Ok(output) => return Ok(output),
            Err(err) => {
                let message = err.to_string();
                if first_error.is_none() {
                    first_error = Some(message.clone());
                }
                if idx == attempt_args.len() - 1 {
                    anyhow::bail!("{}", first_error.unwrap());
                }
                if is_unknown_option_error(&message) {
                    continue;
                }
            }
        }
    }

    anyhow::bail!(
        first_error.unwrap_or_else(|| format!("openssl pkcs12 failed for {}", path.display()))
    );
}

fn run_pkcs12_once(path: &Path, password: &str, extra_args: &[&str]) -> Result<String> {
    let pass_arg = format!("pass:{password}");
    let mut cmd = Command::new("openssl");
    cmd.arg("pkcs12");
    for arg in extra_args {
        cmd.arg(arg);
    }
    let output = cmd
        .arg("-in")
        .arg(path)
        .arg("-nodes")
        .arg("-nokeys")
        .arg("-passin")
        .arg(pass_arg)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .with_context(|| {
            format!(
                "failed to execute openssl pkcs12 while reading {}",
                path.display()
            )
        })?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        if stderr.is_empty() {
            anyhow::bail!("openssl pkcs12 failed for {}", path.display());
        } else {
            anyhow::bail!(stderr);
        }
    }
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    if !stdout.trim().is_empty() {
        return Ok(stdout);
    }
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    if stderr.trim().is_empty() {
        anyhow::bail!("openssl pkcs12 produced no output for {}", path.display());
    }
    Ok(stderr)
}

fn is_unknown_option_error(message: &str) -> bool {
    let lower = message.to_ascii_lowercase();
    lower.contains("unknown option") || lower.contains("invalid option")
}

fn run_pkcs7(path: &Path, format: Pkcs7Format) -> Result<String> {
    let mut cmd = Command::new("openssl");
    cmd.arg("pkcs7").arg("-print_certs").arg("-in").arg(path);
    if matches!(format, Pkcs7Format::Der) {
        cmd.arg("-inform").arg("DER");
    }
    let output = cmd
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .with_context(|| {
            format!(
                "failed to execute openssl pkcs7 while reading {}",
                path.display()
            )
        })?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        if stderr.is_empty() {
            anyhow::bail!("openssl pkcs7 failed for {}", path.display());
        } else {
            anyhow::bail!(stderr);
        }
    }
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

fn run_keytool(path: &Path, store_type: Option<&str>, password: &str) -> Result<String> {
    let mut cmd = Command::new("keytool");
    cmd.arg("-list")
        .arg("-rfc")
        .arg("-noprompt")
        .arg("-keystore")
        .arg(path);
    if let Some(store_type) = store_type {
        cmd.arg("-storetype").arg(store_type);
    }
    cmd.arg("-storepass").arg(password);
    let output = cmd
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .with_context(|| format!("failed to execute keytool while reading {}", path.display()))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        if stderr.is_empty() {
            anyhow::bail!("keytool failed for {}", path.display());
        } else {
            anyhow::bail!(stderr);
        }
    }
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

fn read_pem_file(path: &Path) -> Result<Vec<CertInfo>> {
    let data =
        fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))?;
    parse_pem_bundle(&data, &path.display().to_string())
}

fn is_cert_like(path: &Path) -> bool {
    matches!(
        path.extension()
            .and_then(|e| e.to_str())
            .map(|s| s.to_ascii_lowercase()),
        Some(ext)
            if matches!(
                ext.as_str(),
                "pem"
                    | "crt"
                    | "cer"
                    | "cert"
                    | "p12"
                    | "pfx"
                    | "pkcs12"
                    | "p7b"
                    | "p7c"
                    | "pkcs7"
                    | "jks"
                    | "keystore"
                    | "truststore"
                    | "jceks"
            )
    )
}

pub fn inspect_local_path<P: AsRef<Path>>(
    path: P,
    password: Option<&str>,
) -> Result<LocalInspectReport> {
    let path = path.as_ref();
    let meta = fs::metadata(path)
        .with_context(|| format!("{} does not exist or is not accessible", path.display()))?;

    let mut collected = Vec::new();
    let mut detected_format = LocalCertFormat::Pem;
    let is_dir = meta.is_dir();
    if meta.is_file() {
        let (certs, format) = read_cert_file(path, password)?;
        collected.extend(certs);
        detected_format = format;
    } else if is_dir {
        for entry in fs::read_dir(path)
            .with_context(|| format!("failed to read directory {}", path.display()))?
        {
            let entry = entry?;
            let entry_path = entry.path();
            if entry_path.is_file() && is_cert_like(&entry_path) {
                match read_cert_file(&entry_path, None) {
                    Ok((mut certs, _)) => collected.append(&mut certs),
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
        format: detected_format,
        is_dir,
    })
}
