//! macOS：security add-trusted-cert（登录钥匙串）。
//!
//! 由 `ca::trust` 原文件按平台切分而来，逻辑未改动。

use super::*;

use std::process::Command;

fn keychain_path() -> String {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    format!("{home}/Library/Keychains/login.keychain-db")
}

/// Finds our CA in the login keychain. Returns whether the fingerprint is
/// present and how many certificates carry the CA common name, which tells
/// "not imported at all" from "imported but never trusted".
fn keychain_lookup(sha1_hex: &str) -> Result<(bool, usize)> {
    let keychain = keychain_path();
    let output = Command::new("security")
        .args([
            "find-certificate",
            "-a",
            "-Z",
            "-c",
            CA_COMMON_NAME,
            &keychain,
        ])
        .output()
        .context("执行 security find-certificate")?;
    let text = String::from_utf8_lossy(&output.stdout).to_uppercase();
    let present = text.contains(&sha1_hex.to_uppercase());
    let listed = text.matches("SHA-1 HASH:").count();
    tracing::debug!(
        keychain = %keychain,
        exit = output.status.code().unwrap_or(-1),
        certificates_with_our_cn = listed,
        present,
        "ca keychain lookup"
    );
    if !output.status.success() {
        tracing::warn!(
            keychain = %keychain,
            stderr = %truncate_for_log(&String::from_utf8_lossy(&output.stderr), 300),
            "security find-certificate failed; treating the CA as not installed"
        );
    }
    Ok((present, listed))
}

pub(crate) fn trust_status(
    sha1_hex: &str,
    cert_path: &Path,
) -> Result<(bool, bool, Option<String>)> {
    let (present, _) = keychain_lookup(sha1_hex)?;
    if !present {
        return Ok((true, false, None));
    }
    // The certificate being in the keychain is not trust: a cancelled trust
    // dialog leaves it imported but untrusted. Verify what the system actually
    // believes before reporting "installed and trusted".
    let verify = Command::new("security")
        .args([
            "verify-cert",
            "-c",
            &cert_path.display().to_string(),
            "-p",
            "ssl",
        ])
        .output()
        .context("执行 security verify-cert")?;
    if verify.status.success() {
        tracing::debug!("ca verify-cert passed; reporting trusted");
        Ok((true, true, None))
    } else {
        tracing::info!(
            exit = verify.status.code().unwrap_or(-1),
            stderr = %truncate_for_log(&String::from_utf8_lossy(&verify.stderr), 300),
            "ca is imported but not trusted"
        );
        // Keep it short: the UI only shows one status line here.
        Ok((true, false, Some("已导入，但尚未受信任".into())))
    }
}

pub(crate) fn install_cert(_der: &[u8], pem_path: &Path) -> Result<()> {
    let keychain = keychain_path();
    let pem = pem_path.display().to_string();
    let output = Command::new("security")
        .args(["add-trusted-cert", "-r", "trustRoot", "-k", &keychain, &pem])
        .output()
        .context("执行 security add-trusted-cert")?;
    let stderr = String::from_utf8_lossy(&output.stderr);
    let outcome = classify_security_output(output.status.success(), &stderr);
    tracing::info!(
        exit = output.status.code().unwrap_or(-1),
        outcome = ?outcome,
        stderr = %truncate_for_log(&stderr, 400),
        "security add-trusted-cert finished"
    );
    // `security` can exit 0 after the user dismisses the authorization dialog,
    // and an already-trusted copy would still verify — so a cancellation has to
    // be detected from the output, not from the exit status alone.
    match outcome {
        SecurityOutcome::Ok => {}
        SecurityOutcome::Cancelled => bail!("用户取消了授权对话框"),
        SecurityOutcome::Failed => {
            bail!("security add-trusted-cert 执行失败：{}", stderr.trim())
        }
    }
    // The trust dialog can be cancelled: the certificate imports but the trust
    // setting never lands. Only report success when the system really trusts it.
    // Trust settings can take a moment to propagate, so retry briefly instead
    // of rolling back an install that actually worked.
    const VERIFY_ATTEMPTS: u32 = 5;
    let mut stderr = String::new();
    for attempt in 1..=VERIFY_ATTEMPTS {
        let verify = Command::new("security")
            .args(["verify-cert", "-c", &pem, "-p", "ssl"])
            .output()
            .context("执行 security verify-cert")?;
        stderr = String::from_utf8_lossy(&verify.stderr).to_string();
        if verify.status.success() {
            tracing::info!(attempt, "security verify-cert after install: trusted");
            return Ok(());
        }
        tracing::debug!(
            attempt,
            stderr = %truncate_for_log(&stderr, 200),
            "security verify-cert after install: not trusted yet"
        );
        if attempt < VERIFY_ATTEMPTS {
            std::thread::sleep(Duration::from_millis(150));
        }
    }
    tracing::info!(
        stderr = %truncate_for_log(&stderr, 300),
        "security verify-cert after install: still untrusted"
    );
    bail!("证书已导入，但授权对话框没有确认；请重新执行一次安装")
}

pub(crate) fn uninstall_by_sha1(sha1_hex: &str, remove_trust: bool) -> Result<()> {
    let keychain = keychain_path();
    let thumbprint = sha1_hex.to_uppercase();
    // Nothing to delete is a no-op: `security delete-certificate` would exit
    // non-zero and turn an idempotent `ca uninstall` (and the uninstall step of
    // `ca repair`) into a failure.
    if !keychain_lookup(sha1_hex)?.0 {
        tracing::info!(
            thumbprint = %thumbprint,
            "no matching certificate in the keychain; nothing to remove"
        );
        return Ok(());
    }
    // `-t` also drops the user trust settings, but macOS asks for authorization
    // again — fine for an explicit "remove", wrong for a silent rollback after
    // the user already cancelled one dialog.
    let mut args = vec!["delete-certificate"];
    if remove_trust {
        args.push("-t");
    }
    args.extend(["-Z", thumbprint.as_str(), keychain.as_str()]);
    let output = Command::new("security")
        .args(&args)
        .output()
        .context("执行 security delete-certificate")?;
    tracing::info!(
        thumbprint = %thumbprint,
        exit = output.status.code().unwrap_or(-1),
        stderr = %truncate_for_log(&String::from_utf8_lossy(&output.stderr), 300),
        "security delete-certificate finished"
    );
    if !output.status.success() {
        bail!(
            "security delete-certificate 执行失败：{}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}
