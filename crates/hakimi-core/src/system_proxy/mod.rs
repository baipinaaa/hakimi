use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::config::ProxyMode;
use crate::pac::same_url;
use crate::util::{atomic_write_json, now, read_json};

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SystemProxyStatus {
    pub supported: bool,
    pub mode: String,
    pub applied: bool,
    pub expected: Option<String>,
    pub current: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SavedState {
    #[serde(default)]
    platform: String,
    #[serde(default)]
    proxy_enable: Option<u32>,
    #[serde(default)]
    auto_config_url: Option<String>,
    #[serde(default)]
    proxy_server: Option<String>,
    #[serde(default)]
    proxy_override: Option<String>,
    #[serde(default)]
    mac_services: Vec<String>,
    /// The proxy mode that was applied when the snapshot was taken. `None`
    /// means a snapshot written by an older version, which only ever took
    /// over PAC on macOS.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    mode: Option<ProxyMode>,
    /// Original PAC settings per macOS network service. Saved before the PAC
    /// takeover so restore can put back the user's own URL/enabled flag
    /// instead of blindly disabling the protocol.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    mac_pac: Vec<MacPacState>,
    /// Original web/secure proxy settings per service, for HTTP mode.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    mac_http: Vec<MacHttpState>,
    /// WinINet's per-connection flags captured before the first takeover.
    /// The legacy registry values are not authoritative on Windows: WinINet
    /// reconciles them with `Connections\DefaultConnectionSettings` on every
    /// settings reload, so a restore that only rewrites the legacy values can
    /// be undone by the next notification.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    win_proxy_flags: Option<u32>,
    /// Raw per-connection blobs captured before the takeover: the LAN entry
    /// plus any dial-up/VPN entries. Restoring from them puts the user's own
    /// per-connection modes back instead of re-deriving them from the legacy
    /// mirror, which cannot express per-connection state.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    win_connections: Vec<WinConnectionBlob>,
    #[serde(default)]
    applied_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct WinConnectionBlob {
    /// `None` is the LAN entry (`DefaultConnectionSettings`).
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    bytes: Vec<u8>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct MacPacState {
    service: String,
    enabled: bool,
    url: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct MacHttpState {
    service: String,
    web_enabled: bool,
    web_server: Option<String>,
    web_port: Option<u16>,
    secure_enabled: bool,
    secure_server: Option<String>,
    secure_port: Option<u16>,
}


// [fork] 平台实现按操作系统分文件：Windows（WinINet + 连接 blob）、macOS
// （networksetup/scutil）、其余平台（明确报不支持）。mod.rs 只保留与平台无关
// 的公共逻辑，平台文件通过下面的 glob 导入提供同名 `platform_*` 函数。
#[cfg(windows)]
mod windows;
#[cfg(windows)]
use windows::*;

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
use macos::*;

#[cfg(not(any(windows, target_os = "macos")))]
mod linux;
#[cfg(not(any(windows, target_os = "macos")))]
use linux::*;

/// Whether this platform has a system-wide proxy setting this process can
/// change. Linux has no single one: callers point tools at the proxy through
/// environment variables instead.
pub fn takeover_supported() -> bool {
    cfg!(any(windows, target_os = "macos"))
}

/// Applies/restores the OS proxy setting. The original state is persisted before the first
/// change, so a crash still allows the next start to restore it.
pub struct SystemProxyManager {
    state_path: std::path::PathBuf,
}

impl SystemProxyManager {
    pub fn new(state_path: impl Into<std::path::PathBuf>) -> Self {
        Self {
            state_path: state_path.into(),
        }
    }

    pub fn apply_pac(&self, pac_url: &str) -> Result<SystemProxyStatus> {
        self.save_original(ProxyMode::Pac, Some(pac_url))?;
        let failed = platform_apply_pac(&self.state_path, pac_url)?;
        let mut status = self.verify(ProxyMode::Pac, pac_url.to_string())?;
        attach_apply_warnings(&mut status, &failed);
        Ok(status)
    }

    pub fn apply_http(&self, proxy: SocketAddr) -> Result<SystemProxyStatus> {
        self.save_original(ProxyMode::Http, None)?;
        let failed = platform_apply_http(&self.state_path, proxy)?;
        let mut status = self.verify(ProxyMode::Http, proxy.to_string())?;
        attach_apply_warnings(&mut status, &failed);
        Ok(status)
    }

    /// The PAC URL still present in the readable registry mirror, if any.
    ///
    /// Browsers that read the registry directly (Chromium) use this value even
    /// when WinINet's blob no longer holds a PAC, so a takeover has to be
    /// cleared from the mirror as well.
    pub fn legacy_pac_url(&self) -> Option<String> {
        platform_legacy_pac_url()
    }

    pub fn restore(&self) -> Result<bool> {
        if !self.state_path.exists() {
            return Ok(false);
        }
        // A snapshot that cannot be read must never be treated as "the user
        // had no proxy": the user's own settings exist only in this file, so
        // restoring an empty state would delete them from the OS and then
        // delete the file itself, making the loss permanent. A read failure
        // can also be transient (a locked file), so keep the snapshot and let
        // the caller retry or fall back to switching our takeover off — that
        // leaves the system working without destroying anything.
        let state: SavedState = read_json(&self.state_path).with_context(|| {
            format!(
                "reading the system proxy snapshot {}; refusing to restore an empty state",
                self.state_path.display()
            )
        })?;
        platform_restore(&state)?;
        std::fs::remove_file(&self.state_path).ok();
        Ok(true)
    }

    /// Drop the snapshot without touching the system settings.
    ///
    /// Used when the setting no longer belongs to us — another client took the
    /// system proxy over. Restoring the snapshot then would put *our* captured
    /// state back on top of theirs, so the only safe move is to forget it.
    pub fn forget(&self) {
        match std::fs::remove_file(&self.state_path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                tracing::warn!(error = %error, path = %self.state_path.display(), "could not delete the system proxy snapshot")
            }
        }
    }

    /// Read the OS back and report whether it still matches `expected`.
    ///
    /// `None` means the OS could not be read at all, which is not evidence of
    /// a takeover loss — callers must not treat it as one.
    pub fn still_ours(&self, mode: ProxyMode, expected: &str) -> Option<bool> {
        self.status(Some(mode), Some(expected.to_string()))
            .ok()
            .map(|status| status.applied)
    }

    pub fn status(
        &self,
        mode: Option<ProxyMode>,
        expected: Option<String>,
    ) -> Result<SystemProxyStatus> {
        let CurrentProxy { supported, current } = platform_current(mode)?;
        let applied = match (&current, &expected) {
            (Some(current), Some(expected)) => proxy_setting_matches(current, expected),
            _ => false,
        };
        Ok(SystemProxyStatus {
            supported,
            mode: mode.map(mode_name).unwrap_or("off").to_string(),
            applied,
            expected,
            current,
            error: None,
        })
    }

    /// Read the value back once after writing. macOS propagates proxy changes
    /// through configd, so a write can take a few hundred milliseconds to show
    /// up in `scutil`; retry briefly instead of reporting a false failure.
    fn verify(&self, mode: ProxyMode, expected: String) -> Result<SystemProxyStatus> {
        let attempts = if cfg!(target_os = "macos") { 5 } else { 1 };
        let mut last = None;
        for attempt in 0..attempts {
            let status = self.status(Some(mode), Some(expected.clone()));
            if let Ok(status) = &status {
                if status.applied {
                    return Ok(status.clone());
                }
            }
            last = Some(status);
            if attempt + 1 < attempts {
                std::thread::sleep(Duration::from_millis(150));
            }
        }
        match last.expect("verify always runs at least once") {
            Ok(mut status) => {
                if status.error.is_none() {
                    status.error = Some("system proxy setting was not applied".into());
                }
                Ok(status)
            }
            Err(error) => Err(error),
        }
    }

    /// Switch every network service's automatic proxy off. Used when a stale
    /// takeover points at a paused/broken instance: browsing keeps working
    /// directly while the environment is being fixed.
    pub fn pac_disable(&self) {
        platform_pac_disable();
    }

    pub fn saved_state_exists(&self) -> bool {
        self.state_path.exists()
    }

    fn save_original(&self, mode: ProxyMode, own_pac: Option<&str>) -> Result<()> {
        if self.state_path.exists() {
            return Ok(());
        }
        let mut state = platform_snapshot(mode)?;
        // A killed previous run can leave *our* PAC enabled. Recording that as
        // the user's original state would make restore put the takeover back —
        // the "pause does not switch the proxy off" bug.
        if let Some(own) = own_pac {
            // Windows keeps the same value in the registry; clearing it keeps a
            // killed run's PAC out of the "original" state there too.
            if state
                .auto_config_url
                .as_deref()
                .is_some_and(|stored| same_url(stored, own))
            {
                state.auto_config_url = None;
            }
            // The per-connection blob can also carry a killed run's PAC. Drop
            // it from the snapshot for the same reason as the legacy value.
            #[cfg(windows)]
            for connection in &mut state.win_connections {
                let Some(mut blob) = ConnectionBlob::parse(&connection.bytes) else {
                    continue;
                };
                if blob
                    .pac_url()
                    .as_deref()
                    .is_some_and(|stored| same_url(stored, own))
                {
                    blob.set_flags(blob.flags() & !WIN_PROXY_TYPE_AUTO_PROXY_URL);
                    blob.set_pac_url(None);
                    connection.bytes = blob.to_bytes();
                }
            }
            for pac in &mut state.mac_pac {
                if pac.url.as_deref().is_some_and(|stored| same_url(stored, own)) {
                    pac.enabled = false;
                    pac.url = None;
                }
            }
        }
        state.mode = Some(mode);
        if let Some(parent) = self.state_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        state.applied_at = Some(now());
        atomic_write_json(&self.state_path, &state)?;
        Ok(())
    }
}

/// Keep partial write failures in the status so the UI can show a warning even
/// when the currently active service did receive the setting.
fn attach_apply_warnings(status: &mut SystemProxyStatus, failed: &[String]) {
    if failed.is_empty() {
        return;
    }
    let detail = if failed.len() == 1 {
        failed[0].clone()
    } else {
        format!("{} 个网络服务写入失败（首个：{}）", failed.len(), failed[0])
    };
    status.error = Some(match status.error.take() {
        Some(existing) => format!("{existing}; {detail}"),
        None => detail,
    });
}

fn mode_name(mode: ProxyMode) -> &'static str {
    match mode {
        ProxyMode::Pac => "pac",
        ProxyMode::Http => "http",
        ProxyMode::Off => "off",
    }
}

/// Compare the OS-reported setting with the one this instance wrote.
///
/// PAC values are URLs and keep the existing substring contract. HTTP values
/// are socket addresses: macOS prints `Server: ::1` and `Port: 8443`, which
/// becomes `::1:8443`, while `SocketAddr::to_string()` keeps the IPv6 brackets
/// (`[::1]:8443`). Accept either spelling.
fn proxy_setting_matches(current: &str, expected: &str) -> bool {
    // A versioned PAC URL only ever matches itself, never an older or newer
    // write of the same script base, so the cache-buster is stripped first.
    let current = current.split('?').next().unwrap_or(current);
    let expected = expected.split('?').next().unwrap_or(expected);
    if current.contains(expected) {
        return true;
    }
    expected
        .parse::<SocketAddr>()
        .ok()
        .is_some_and(|address| current == format!("{}:{}", address.ip(), address.port()))
}

#[derive(Debug)]
struct CurrentProxy {
    supported: bool,
    current: Option<String>,
}

fn mac_value(text: &str, key: &str) -> Option<String> {
    text.lines().find_map(|line| {
        let (name, value) = line.trim_start().split_once(':')?;
        name.trim()
            .eq_ignore_ascii_case(key)
            .then(|| value.trim().to_string())
    })
}

fn mac_enabled(text: &str) -> bool {
    mac_value(text, "Enabled").as_deref() == Some("Yes")
}

/// The proxy address the system reports, in the same shape as the address
/// the proxy announces.
///
/// macOS prints a web proxy as two lines ("Server:" and "Port:").  Dropping
/// the port makes the comparison with the announced address fail, so the
/// proxy would look unapplied even while it routes the traffic.
fn parse_current_proxy(text: &str, mode: Option<ProxyMode>) -> Option<String> {
    let server = || {
        let server = mac_value(text, "Server")?;
        Some(match mac_value(text, "Port") {
            Some(port) => format!("{server}:{port}"),
            None => server,
        })
    };
    match mode {
        Some(ProxyMode::Http) => server(),
        _ => mac_value(text, "URL").or_else(server),
    }
}

/// `networksetup` reports a stale URL/server even when the protocol is off.
/// Only an enabled protocol counts as "the setting is in effect".
fn parse_networksetup_proxy(text: &str, mode: ProxyMode) -> Option<String> {
    if mac_enabled(text) {
        parse_current_proxy(text, Some(mode))
    } else {
        None
    }
}

#[cfg(any(target_os = "macos", test))]
fn parse_mac_pac(text: &str) -> (bool, Option<String>) {
    (
        mac_enabled(text),
        mac_value(text, "URL").filter(|url| !url.is_empty()),
    )
}

#[cfg(any(target_os = "macos", test))]
fn parse_mac_http_proxy(text: &str) -> (bool, Option<String>, Option<u16>) {
    (
        mac_enabled(text),
        mac_value(text, "Server").filter(|server| !server.is_empty()),
        mac_value(text, "Port").and_then(|port| port.parse().ok()),
    )
}

/// The proxy settings that decide whether our write survived on macOS.
#[cfg(any(target_os = "macos", test))]
#[derive(Debug, Default, PartialEq, Eq)]
struct ScutilProxyState {
    pac_enabled: bool,
    pac_url: Option<String>,
    http: Option<String>,
    https: Option<String>,
}

#[cfg(any(target_os = "macos", test))]
fn parse_scutil_proxy(text: &str) -> ScutilProxyState {
    let value = |key: &str| {
        text.lines().find_map(|line| {
            let (name, value) = line.trim_start().split_once(':')?;
            name.trim()
                .eq_ignore_ascii_case(key)
                .then(|| value.trim().to_string())
        })
    };
    let enabled = |key: &str| value(key).as_deref() == Some("1");
    let endpoint = |enable: &str, host: &str, port: &str| {
        if !enabled(enable) {
            return None;
        }
        let host = value(host).filter(|host| !host.is_empty())?;
        Some(match value(port).filter(|port| !port.is_empty()) {
            Some(port) => format!("{host}:{port}"),
            None => host,
        })
    };
    ScutilProxyState {
        pac_enabled: enabled("ProxyAutoConfigEnable"),
        pac_url: value("ProxyAutoConfigURLString").filter(|url| !url.is_empty()),
        http: endpoint("HTTPEnable", "HTTPProxy", "HTTPPort"),
        https: endpoint("HTTPSEnable", "HTTPSProxy", "HTTPSPort"),
    }
}

/// Guard against WinINet preferring a fixed proxy: our PAC mode writes
/// `AutoConfigURL` and disables the fixed proxy. Reading it back is enough to
/// know our write is intact.
#[cfg(any(windows, test))]
fn windows_current(
    mode: Option<ProxyMode>,
    auto: Option<String>,
    server: Option<String>,
    enabled: u32,
) -> Option<String> {
    match mode {
        Some(ProxyMode::Pac) => auto,
        Some(ProxyMode::Http) if enabled == 1 => server,
        Some(ProxyMode::Http) | Some(ProxyMode::Off) => None,
        None => auto.or(server),
    }
}

#[cfg(any(target_os = "macos", test))]
fn scutil_proxy_text() -> Option<String> {
    let output = std::process::Command::new("scutil")
        .arg("--proxy")
        .output()
        .ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).into_owned())
}

#[cfg(any(target_os = "macos", test))]
fn scutil_pac_current(text: &str) -> Option<String> {
    let state = parse_scutil_proxy(text);
    if state.pac_enabled {
        state.pac_url
    } else {
        None
    }
}

#[cfg(any(target_os = "macos", test))]
fn scutil_http_current(text: &str) -> Option<String> {
    let state = parse_scutil_proxy(text);
    if state.http.is_some() && state.http == state.https {
        state.http
    } else {
        None
    }
}


#[cfg(all(test, windows))]
mod tests {
    use super::*;

    #[test]
    fn snapshot_has_platform() {
        let state = platform_snapshot(ProxyMode::Pac).unwrap();
        assert_eq!(state.platform, "windows");
    }

    #[test]
    fn restore_flags_match_the_values_being_restored() {
        use windows_sys::Win32::Networking::WinInet::{
            PROXY_TYPE_AUTO_DETECT, PROXY_TYPE_AUTO_PROXY_URL, PROXY_TYPE_DIRECT, PROXY_TYPE_PROXY,
        };

        // A captured "direct" mode gains the PAC bit when a PAC is restored.
        assert_eq!(
            restore_flags(Some(PROXY_TYPE_DIRECT), true, false),
            PROXY_TYPE_DIRECT | PROXY_TYPE_AUTO_PROXY_URL
        );
        // A captured PAC is dropped when the snapshot has no PAC URL.
        assert_eq!(
            restore_flags(
                Some(PROXY_TYPE_DIRECT | PROXY_TYPE_AUTO_PROXY_URL),
                false,
                false
            ),
            PROXY_TYPE_DIRECT
        );
        // Manual proxy and PAC can coexist.
        assert_eq!(
            restore_flags(
                Some(PROXY_TYPE_DIRECT | PROXY_TYPE_AUTO_PROXY_URL),
                true,
                true
            ),
            PROXY_TYPE_DIRECT | PROXY_TYPE_AUTO_PROXY_URL | PROXY_TYPE_PROXY
        );
        // Without a captured blob, the flags are derived from the values.
        assert_eq!(
            restore_flags(None, false, true),
            PROXY_TYPE_DIRECT | PROXY_TYPE_PROXY
        );
        // Unrelated bits such as auto-detect survive the reconciliation.
        assert_eq!(
            restore_flags(
                Some(PROXY_TYPE_DIRECT | PROXY_TYPE_AUTO_DETECT),
                false,
                false
            ),
            PROXY_TYPE_DIRECT | PROXY_TYPE_AUTO_DETECT
        );
    }
}

#[cfg(test)]
mod verification_tests {
    use super::*;

    const PAC: &str = "http://127.0.0.1:8443/proxy.pac";
    const PAC_ON: &str = "<dictionary> {\n  ProxyAutoConfigEnable : 1\n  ProxyAutoConfigURLString : http://127.0.0.1:8443/proxy.pac\n}\n";

    #[test]
    fn a_written_pac_is_detected() {
        assert_eq!(scutil_pac_current(PAC_ON).as_deref(), Some(PAC));
    }

    #[test]
    fn a_disabled_or_different_pac_is_not_detected() {
        let disabled = PAC_ON.replace("ProxyAutoConfigEnable : 1", "ProxyAutoConfigEnable : 0");
        assert_eq!(scutil_pac_current(&disabled), None);
        assert_ne!(
            scutil_pac_current(PAC_ON).as_deref(),
            Some("http://127.0.0.1:8443/other.pac")
        );
    }

    /// The contract is only "our write is intact". A competing static proxy is
    /// deliberately ignored: there is no polling and no takeover detection.
    #[test]
    fn static_proxies_do_not_change_what_we_verify() {
        let text = format!(
            "{PAC_ON}  HTTPEnable : 1\n  HTTPProxy : 127.0.0.1\n  HTTPPort : 10809\n  SOCKSEnable : 1\n  SOCKSProxy : 127.0.0.1\n  SOCKSPort : 10809\n"
        );
        assert_eq!(scutil_pac_current(&text).as_deref(), Some(PAC));
    }

    #[test]
    fn http_requires_both_web_and_secure_proxies() {
        let both = "<dictionary> {\n  HTTPEnable : 1\n  HTTPProxy : 127.0.0.1\n  HTTPPort : 8443\n  HTTPSEnable : 1\n  HTTPSProxy : 127.0.0.1\n  HTTPSPort : 8443\n}\n";
        assert_eq!(scutil_http_current(both).as_deref(), Some("127.0.0.1:8443"));

        let web_only = both.replace("HTTPSEnable : 1", "HTTPSEnable : 0");
        assert_eq!(scutil_http_current(&web_only), None);
    }

    #[test]
    fn networksetup_parsing_keeps_the_enabled_flag() {
        let on = "Enabled: Yes\nServer: 127.0.0.1\nPort: 8443\n";
        assert_eq!(
            parse_networksetup_proxy(on, ProxyMode::Http).as_deref(),
            Some("127.0.0.1:8443")
        );
        let off = "Enabled: No\nServer: 127.0.0.1\nPort: 8443\n";
        assert_eq!(parse_networksetup_proxy(off, ProxyMode::Http), None);
    }

    #[test]
    fn mac_snapshot_parsers_keep_original_values() {
        let pac = "URL: http://127.0.0.1:8443/proxy.pac\nEnabled: Yes\n";
        assert_eq!(
            parse_mac_pac(pac),
            (true, Some("http://127.0.0.1:8443/proxy.pac".into()))
        );
        let http = "Enabled: Yes\nServer: 127.0.0.1\nPort: 10809\n";
        assert_eq!(
            parse_mac_http_proxy(http),
            (true, Some("127.0.0.1".into()), Some(10809))
        );
    }

    #[test]
    fn mac_snapshot_keeps_original_values() {
        let state = SavedState {
            platform: "macos".into(),
            mode: Some(ProxyMode::Pac),
            mac_pac: vec![MacPacState {
                service: "Wi-Fi".into(),
                enabled: true,
                url: Some("http://127.0.0.1:9999/original.pac".into()),
            }],
            ..Default::default()
        };
        let json = serde_json::to_string(&state).unwrap();
        let back: SavedState = serde_json::from_str(&json).unwrap();
        assert_eq!(back.mode, Some(ProxyMode::Pac));
        assert_eq!(back.mac_pac.len(), 1);
        assert_eq!(
            back.mac_pac[0].url.as_deref(),
            Some("http://127.0.0.1:9999/original.pac")
        );
    }

    /// A corrupt snapshot must not be restored as an empty state: that would
    /// delete the user's own proxy settings from the OS and then delete the
    /// snapshot, losing them for good. The failure has to surface and the
    /// file has to survive so it can be retried or repaired.
    #[test]
    fn a_corrupt_snapshot_is_never_restored_as_empty() {
        let dir = std::env::temp_dir().join(format!("hakimi-restore-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("system-proxy.json");
        std::fs::write(&path, b"{ not json").unwrap();

        let manager = SystemProxyManager::new(&path);
        let result = manager.restore();
        assert!(result.is_err(), "a corrupt snapshot must surface an error");
        assert!(
            path.exists(),
            "a failed restore must keep the snapshot for recovery"
        );

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn a_legacy_snapshot_still_deserializes() {
        let back: SavedState =
            serde_json::from_str(r#"{"platform":"macos","macServices":["Wi-Fi"]}"#).unwrap();
        assert_eq!(back.mode, None);
        assert!(back.mac_pac.is_empty());
    }

    #[test]
    fn windows_current_reads_the_value_we_wrote() {
        let pac = "http://127.0.0.1:8443/proxy.pac".to_string();
        // PAC mode verifies AutoConfigURL only; a later fixed-proxy toggle is
        // outside the write contract.
        assert_eq!(
            windows_current(
                Some(ProxyMode::Pac),
                Some(pac.clone()),
                Some("127.0.0.1:10809".into()),
                1
            ),
            Some(pac)
        );
        // HTTP mode requires the fixed proxy to be enabled.
        assert_eq!(
            windows_current(
                Some(ProxyMode::Http),
                None,
                Some("127.0.0.1:8443".into()),
                1
            ),
            Some("127.0.0.1:8443".into())
        );
        assert_eq!(
            windows_current(
                Some(ProxyMode::Http),
                None,
                Some("127.0.0.1:8443".into()),
                0
            ),
            None
        );
    }
}

/// Run a child process with a hard deadline. The program is a parameter so the
/// timeout behavior can be tested without a hanging `networksetup`.
///
/// 放在 `mod.rs` 而不是 `macos.rs`：它是纯 `std::process` 实现，和平台无关，
/// 而 Windows 侧的测试也要用它验证超时逻辑。
pub(super) fn run_command_with_timeout(
    program: &str,
    args: &[&str],
    timeout_secs: u64,
) -> Result<String> {
    use std::io::Read;
    let mut child = std::process::Command::new(program)
        .args(args)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .with_context(|| format!("spawning {program} {args:?}"))?;
    let deadline = std::time::Instant::now() + Duration::from_secs(timeout_secs);
    // Poll for exit FIRST and read the pipes only after: `read_to_string`
    // blocks until the pipe closes, which only happens when the child exits,
    // so reading first would make the deadline unreachable for a hung child.
    let status = loop {
        match child.try_wait()? {
            Some(status) => break status,
            None if std::time::Instant::now() > deadline => {
                let _ = child.kill();
                let _ = child.wait();
                bail!("{program} {args:?} timed out after {timeout_secs}s");
            }
            None => std::thread::sleep(Duration::from_millis(20)),
        }
    };
    let mut stdout = String::new();
    if let Some(mut pipe) = child.stdout.take() {
        let _ = pipe.read_to_string(&mut stdout);
    }
    if !status.success() {
        let mut stderr = String::new();
        if let Some(mut pipe) = child.stderr.take() {
            let _ = pipe.read_to_string(&mut stderr);
        }
        bail!(
            "{program} failed: {}",
            String::from_utf8_lossy(stderr.as_bytes()).trim()
        );
    }
    Ok(stdout)
}

#[cfg(test)]
#[cfg(unix)]
mod process_timeout_tests {
    use super::*;

    /// A hung child must be killed at the deadline, not waited out. The old
    /// implementation blocked in `read_to_string` until the child exited, so
    /// the timeout never fired.
    #[test]
    fn process_timeout_is_enforced() {
        let started = std::time::Instant::now();
        let result = run_command_with_timeout("/bin/sh", &["-c", "sleep 8"], 1);
        let elapsed = started.elapsed();
        assert!(
            elapsed < std::time::Duration::from_secs(5),
            "timeout not enforced: waited {elapsed:?} for a hung child"
        );
        assert!(result.is_err(), "a killed child must surface as an error");
    }
}

#[cfg(test)]
mod current_proxy_tests {
    use super::*;

    /// macOS reports a web proxy as two lines. The address has to keep the
    /// port, otherwise the proxy looks unapplied even while it is routing.
    #[test]
    fn the_web_proxy_address_keeps_its_port() {
        let text = "Enabled: Yes\nServer: 127.0.0.1\nPort: 8443\nAuthenticated Proxy Enabled: 0\n";
        let current = parse_current_proxy(text, Some(ProxyMode::Http)).unwrap();
        assert_eq!(current, "127.0.0.1:8443");
        // The comparison the status does must now succeed.
        assert!(proxy_setting_matches(&current, "127.0.0.1:8443"));
    }

    #[test]
    fn an_ipv6_http_proxy_status_matches_the_host_port_form() {
        // macOS reports the host and port separately, so an IPv6 listener
        // (`[::1]:8443` as a SocketAddr) appears as `::1:8443`. Comparing it
        // with `contains("[::1]:8443")` marked a working proxy as unapplied.
        let text = "Enabled: Yes\nServer: ::1\nPort: 8443\n";
        let current = parse_current_proxy(text, Some(ProxyMode::Http)).unwrap();
        assert_eq!(current, "::1:8443");
        assert!(proxy_setting_matches(&current, "[::1]:8443"));
        assert!(!proxy_setting_matches(&current, "[::1]:8444"));
    }

    #[test]
    fn the_pac_url_is_read_as_a_whole() {
        let text = "URL: http://127.0.0.1:8443/proxy.pac\nEnabled: Yes\n";
        let current = parse_current_proxy(text, Some(ProxyMode::Pac)).unwrap();
        assert_eq!(current, "http://127.0.0.1:8443/proxy.pac");
        assert!(current.contains("http://127.0.0.1:8443/proxy.pac"));
    }

    /// Without a mode the URL wins, and the web proxy is the fallback.
    #[test]
    fn the_fallback_reads_the_web_proxy() {
        let text = "Enabled: Yes\nServer: 127.0.0.1\nPort: 8443\n";
        assert_eq!(
            parse_current_proxy(text, None),
            Some("127.0.0.1:8443".to_string())
        );
        let text = "URL: http://127.0.0.1:8443/proxy.pac\nEnabled: Yes\n";
        assert_eq!(
            parse_current_proxy(text, None),
            Some("http://127.0.0.1:8443/proxy.pac".to_string())
        );
    }
}
