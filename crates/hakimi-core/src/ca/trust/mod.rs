use std::path::Path;

#[cfg(any(windows, target_os = "macos", target_os = "linux"))]
use anyhow::Context;
use anyhow::{bail, Result};

#[cfg(target_os = "macos")]
use super::CA_COMMON_NAME;
#[cfg(target_os = "android")]
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(target_os = "macos")]
use std::time::Duration;

/// Android cannot install or probe the user CA store from Rust: the user must
/// install the certificate through Settings, and the JNI shell reports the
/// result back with [`set_android_ca_trusted`]. Chrome and WebView read
/// `AndroidCAStore` directly and trust user CAs; most other apps do not.
#[cfg(target_os = "android")]
static ANDROID_CA_TRUSTED: AtomicBool = AtomicBool::new(false);

#[cfg(target_os = "android")]
pub fn set_android_ca_trusted(trusted: bool) {
    ANDROID_CA_TRUSTED.store(trusted, Ordering::SeqCst);
}

/// The JNI shell is part of the workspace and must also compile for the host,
/// where there is no Android user CA store to update.
#[cfg(not(target_os = "android"))]
pub fn set_android_ca_trusted(_trusted: bool) {}

/// Cap command output before it lands in the log.
#[cfg(any(target_os = "macos", test))]
pub(super) fn truncate_for_log(text: &str, max: usize) -> String {
    let one_line = text.trim().replace('\n', " ");
    if one_line.chars().count() <= max {
        return one_line;
    }
    let head: String = one_line.chars().take(max).collect();
    format!("{head}…")
}

#[cfg(target_os = "macos")]
#[derive(Debug, PartialEq, Eq)]
pub(super) enum SecurityOutcome {
    Ok,
    Cancelled,
    Failed,
}

/// `security` may exit 0 after the user dismisses the authorization dialog, so
/// the output decides first and the exit status only breaks the tie.
#[cfg(target_os = "macos")]
pub(super) fn classify_security_output(success: bool, stderr: &str) -> SecurityOutcome {
    if stderr.to_ascii_lowercase().contains("cancel") {
        SecurityOutcome::Cancelled
    } else if success {
        SecurityOutcome::Ok
    } else {
        SecurityOutcome::Failed
    }
}

// ---------------------------------------------------------------------------
// Trust store integration
// ---------------------------------------------------------------------------

pub(super) fn trust_supported() -> bool {
    cfg!(any(
        windows,
        target_os = "macos",
        target_os = "android",
        target_os = "linux"
    ))
}

pub(super) fn trust_note() -> Option<String> {
    #[cfg(windows)]
    {
        Some(
            "已安装到当前用户的根证书存储；Chromium/Edge 会使用它，Firefox 可能用自己的证书库。"
                .to_string(),
        )
    }
    #[cfg(target_os = "macos")]
    {
        Some("已安装到登录钥匙串；使用系统信任库的浏览器会生效。".to_string())
    }
    #[cfg(target_os = "android")]
    {
        Some(
            "已作为用户证书安装；Chrome/WebView 及 Chromium 系浏览器会信任它，多数原生应用不会。"
                .to_string(),
        )
    }
    #[cfg(target_os = "linux")]
    {
        Some(
            "已通过发行版的工具安装到系统信任库；Firefox 等使用 NSS 的程序需要单独导入。"
                .to_string(),
        )
    }
    #[cfg(not(any(
        windows,
        target_os = "macos",
        target_os = "android",
        target_os = "linux"
    )))]
    {
        Some("该平台不支持自动安装 CA。".to_string())
    }
}

/// The file `install` writes and the command that rebuilds the bundle, so a
/// caller can show the exact change before making it. Platforms that install
/// through an OS API have nothing to show.
#[cfg(not(target_os = "linux"))]
pub(super) fn install_target() -> Option<(String, String)> {
    None
}



// [fork] 信任库操作按操作系统分文件。每个平台都必须提供同名接口：
// `install_target` / `trust_status` / `install_cert` / `uninstall_by_sha1`，
// mod.rs 只保留公共逻辑与各发行版信任库的路径数据。
#[cfg(windows)]
mod windows;
#[cfg(windows)]
use windows::*;

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
use macos::*;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
use linux::*;

#[cfg(target_os = "android")]
mod android;
#[cfg(target_os = "android")]
use android::*;

#[cfg(not(any(windows, target_os = "macos", target_os = "linux", target_os = "android")))]
mod unsupported;
#[cfg(not(any(windows, target_os = "macos", target_os = "linux", target_os = "android")))]
use unsupported::*;

// ---------------------------------------------------------------------------
// Linux: distribution trust anchors
// ---------------------------------------------------------------------------

/// Where a distribution keeps local anchors and how it rebuilds the bundle.
/// Kept as data so path selection and PEM matching are testable on any host;
/// the functions below only add the file and process calls.
#[cfg(any(test, target_os = "linux"))]
mod distro {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    #[cfg(target_os = "linux")]
    use std::path::Path;

    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
    const END: &str = "-----END CERTIFICATE-----";

    pub struct Layout {
        /// Where the distribution expects local anchors.
        pub anchor: &'static str,
        /// The extracted bundle TLS clients read.
        pub bundle: &'static str,
        /// Command that rebuilds the bundle from the anchors.
        pub update: &'static [&'static str],
    }

    /// Debian, Ubuntu and derivatives.
    const DEBIAN: Layout = Layout {
        anchor: "/usr/local/share/ca-certificates/hakimi.crt",
        bundle: "/etc/ssl/certs/ca-certificates.crt",
        update: &["update-ca-certificates"],
    };

    /// Fedora, RHEL and openSUSE.
    const RPM: Layout = Layout {
        anchor: "/etc/pki/ca-trust/source/anchors/hakimi.pem",
        bundle: "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
        update: &["update-ca-trust", "extract"],
    };

    /// Arch and anything else on p11-kit: `trust` writes the same
    /// `ca-certificates.crt` that OpenSSL reads.
    const P11KIT: Layout = Layout {
        anchor: "/etc/ca-certificates/trust-source/anchors/hakimi.pem",
        bundle: "/etc/ssl/certs/ca-certificates.crt",
        update: &["trust", "extract-compat"],
    };

    pub fn detect(exists: impl Fn(&str) -> bool) -> Option<&'static Layout> {
        if exists("/usr/local/share/ca-certificates") {
            Some(&DEBIAN)
        } else if exists("/etc/pki/ca-trust/source/anchors") {
            Some(&RPM)
        } else if exists("/etc/ca-certificates/trust-source/anchors") {
            Some(&P11KIT)
        } else {
            None
        }
    }

    #[cfg(target_os = "linux")]
    pub fn exists(path: &str) -> bool {
        Path::new(path).exists()
    }

    /// DER of the first certificate in a PEM file.
    pub fn pem_to_der(pem: &[u8]) -> Option<Vec<u8>> {
        let text = String::from_utf8_lossy(pem);
        let start = text.find(BEGIN)?;
        let body = &text[start + BEGIN.len()..];
        let end = body.find(END)?;
        let encoded: String = body[..end].split_whitespace().collect();
        STANDARD.decode(encoded).ok()
    }

    pub fn der_to_pem(der: &[u8]) -> Vec<u8> {
        let encoded = STANDARD.encode(der);
        let mut pem = String::from(BEGIN);
        pem.push('\n');
        for chunk in encoded.as_bytes().chunks(64) {
            pem.push_str(&String::from_utf8_lossy(chunk));
            pem.push('\n');
        }
        pem.push_str(END);
        pem.push('\n');
        pem.into_bytes()
    }

    /// Whether the extracted bundle already carries this certificate. Line
    /// wrapping differs between distributions, so each block is decoded rather
    /// than matched as text.
    pub fn bundle_contains(bundle: &[u8], der: &[u8]) -> bool {
        let text = String::from_utf8_lossy(bundle);
        let mut rest = text.as_ref();
        while let Some(start) = rest.find(BEGIN) {
            let body = &rest[start + BEGIN.len()..];
            let Some(end) = body.find(END) else {
                return false;
            };
            let encoded: String = body[..end].split_whitespace().collect();
            if STANDARD.decode(encoded).is_ok_and(|decoded| decoded == der) {
                return true;
            }
            rest = &body[end + END.len()..];
        }
        false
    }
}
mod trust_tests {
    use super::distro;

    fn sample_der() -> Vec<u8> {
        (0u8..=255).collect()
    }

    #[test]
    fn pem_roundtrip_keeps_the_der() {
        let der = sample_der();
        assert_eq!(distro::pem_to_der(&distro::der_to_pem(&der)), Some(der));
    }

    #[test]
    fn bundle_match_ignores_line_wrapping() {
        let der = sample_der();
        let mut bundle = b"# system bundle\n".to_vec();
        bundle.extend(distro::der_to_pem(&der));
        assert!(distro::bundle_contains(&bundle, &der));
        assert!(!distro::bundle_contains(
            &bundle,
            b"a different certificate"
        ));
        // A truncated block must not panic or match.
        assert!(!distro::bundle_contains(
            b"-----BEGIN CERTIFICATE-----\n",
            &der
        ));
    }

    #[test]
    fn layout_names_a_hakimi_anchor_and_the_family_update_command() {
        let debian = distro::detect(|path| path == "/usr/local/share/ca-certificates").unwrap();
        assert!(debian.anchor.ends_with("hakimi.crt"));
        assert!(debian.bundle.starts_with("/etc/ssl/"));
        assert_eq!(debian.update, ["update-ca-certificates"]);

        let rpm = distro::detect(|path| path == "/etc/pki/ca-trust/source/anchors").unwrap();
        assert!(rpm.anchor.ends_with("hakimi.pem"));
        assert!(rpm.bundle.contains("ca-trust"));
        assert_eq!(rpm.update, ["update-ca-trust", "extract"]);

        let p11kit =
            distro::detect(|path| path == "/etc/ca-certificates/trust-source/anchors").unwrap();
        assert!(p11kit.anchor.contains("trust-source"));
        assert_eq!(p11kit.update, ["trust", "extract-compat"]);

        assert!(distro::detect(|_| false).is_none());
    }
}
