//! Windows：WinINet 注册表镜像 + Connections 连接 blob 的读写与恢复。
//!
//! 由 `system_proxy` 原文件按平台切分而来，逻辑未改动。

use super::*;

/// WinINet's `PROXY_TYPE_*` bits, mirrored from `wininet.h` so the blob
/// handling below does not depend on the Windows headers:
/// direct 0x01, proxy 0x02, auto-proxy URL 0x04, auto-detect 0x08.
pub(super) const WIN_PROXY_TYPE_PROXY: u32 = 0x02;
pub(super) const WIN_PROXY_TYPE_AUTO_PROXY_URL: u32 = 0x04;

/// One value of `Internet Settings\Connections`: WinINet's per-connection
/// proxy state. The layout is the serialized per-connection option list:
///
/// ```text
/// 0..4   fixed header (0x46 on every build observed; not a total length)
/// 4..8   version
/// 8..12  PROXY_TYPE_* flags
/// then   length-prefixed ANSI strings: proxy server, bypass list, PAC URL
/// then   a trailer WinINet owns (32 zero bytes on LAN entries)
/// ```
///
/// WinINet treats this blob as the source of truth and rewrites the legacy
/// registry values (`AutoConfigURL`, `ProxyEnable`, ...) from it on every
/// settings reload. Reading or verifying only the legacy mirror can therefore
/// disagree with what the system actually uses; worse, when the blob says
/// "direct" the reload deletes the mirror that was just written.
#[derive(Debug, Clone)]
pub(super) struct ConnectionBlob {
    prefix: [u8; 12],
    proxy_server: Vec<u8>,
    proxy_bypass: Vec<u8>,
    pac_url: Vec<u8>,
    trailing: Vec<u8>,
}

impl ConnectionBlob {
    pub(super) fn parse(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 12 {
            return None;
        }
        let mut prefix = [0u8; 12];
        prefix.copy_from_slice(&bytes[..12]);
        let mut offset = 12;
        let proxy_server = read_length_prefixed(bytes, &mut offset)?;
        let proxy_bypass = read_length_prefixed(bytes, &mut offset)?;
        let pac_url = read_length_prefixed(bytes, &mut offset)?;
        Some(Self {
            prefix,
            proxy_server,
            proxy_bypass,
            pac_url,
            trailing: bytes[offset..].to_vec(),
        })
    }

    pub(super) fn flags(&self) -> u32 {
        u32::from_le_bytes(self.prefix[8..12].try_into().expect("four flag bytes"))
    }

    pub(super) fn set_flags(&mut self, flags: u32) {
        self.prefix[8..12].copy_from_slice(&flags.to_le_bytes());
    }

    fn proxy_server(&self) -> Option<String> {
        blob_text(&self.proxy_server)
    }

    fn proxy_bypass(&self) -> Option<String> {
        blob_text(&self.proxy_bypass)
    }

    pub(super) fn pac_url(&self) -> Option<String> {
        blob_text(&self.pac_url)
    }

    pub(super) fn set_pac_url(&mut self, value: Option<&str>) {
        self.pac_url = value
            .map(|value| value.as_bytes().to_vec())
            .unwrap_or_default();
    }

    pub(super) fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(
            12 + self.proxy_server.len()
                + self.proxy_bypass.len()
                + self.pac_url.len()
                + self.trailing.len()
                + 12,
        );
        out.extend_from_slice(&self.prefix);
        for section in [&self.proxy_server, &self.proxy_bypass, &self.pac_url] {
            out.extend_from_slice(&(section.len() as u32).to_le_bytes());
            out.extend_from_slice(section);
        }
        out.extend_from_slice(&self.trailing);
        out
    }
}

pub(super) fn read_length_prefixed(bytes: &[u8], offset: &mut usize) -> Option<Vec<u8>> {
    let length_end = offset.checked_add(4)?;
    if length_end > bytes.len() {
        return None;
    }
    let length = u32::from_le_bytes(bytes[*offset..length_end].try_into().ok()?) as usize;
    let end = length_end.checked_add(length)?;
    if end > bytes.len() {
        return None;
    }
    *offset = end;
    Some(bytes[length_end..end].to_vec())
}

pub(super) fn blob_text(bytes: &[u8]) -> Option<String> {
    (!bytes.is_empty()).then(|| String::from_utf8_lossy(bytes).into_owned())
}

pub(super) fn platform_snapshot(_mode: ProxyMode) -> Result<SavedState> {
    use winreg::enums::HKEY_CURRENT_USER;
    use winreg::RegKey;

    let key = RegKey::predef(HKEY_CURRENT_USER)
        .open_subkey_with_flags(INTERNET_SETTINGS, winreg::enums::KEY_READ)
        .context("opening Internet Settings registry key")?;
    Ok(SavedState {
        platform: "windows".into(),
        proxy_enable: key.get_value("ProxyEnable").ok(),
        auto_config_url: key.get_value("AutoConfigURL").ok(),
        proxy_server: key.get_value("ProxyServer").ok(),
        proxy_override: key.get_value("ProxyOverride").ok(),
        win_proxy_flags: read_connection_flags(),
        win_connections: snapshot_connection_blobs(),
        applied_at: None,
        ..Default::default()
    })
}

pub(super) const INTERNET_SETTINGS: &str = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings";

pub(super) const INTERNET_CONNECTIONS: &str =
    r"Software\Microsoft\Windows\CurrentVersion\Internet Settings\Connections";

pub(super) const DEFAULT_CONNECTION_VALUE: &str = "DefaultConnectionSettings";

/// WinINet's authoritative proxy mode lives in the per-connection settings
/// blob, not in the legacy `AutoConfigURL`/`ProxyEnable` values. Reading the
/// blob lets a restore put back the exact mode the user had (including
/// auto-detect), instead of guessing from the legacy values.
///
/// Reads the flags straight from the fixed offset so a blob whose string
/// sections do not parse still yields its mode.
pub(super) fn read_connection_flags() -> Option<u32> {
    use winreg::enums::{HKEY_CURRENT_USER, KEY_READ};
    use winreg::RegKey;

    let key = RegKey::predef(HKEY_CURRENT_USER)
        .open_subkey_with_flags(INTERNET_CONNECTIONS, KEY_READ)
        .ok()?;
    let blob = key.get_raw_value(DEFAULT_CONNECTION_VALUE).ok()?;
    let flags = blob.bytes.get(8..12)?;
    Some(u32::from_le_bytes(flags.try_into().ok()?))
}

/// The LAN entry's mirror of the previous settings; not a connection.
pub(super) const SAVED_LEGACY_VALUE: &str = "SavedLegacySettings";

/// Names of the dial-up/VPN entries WinINet keeps settings for. A machine
/// where one of these is the effective connection needs its blob written too,
/// otherwise the reload keeps reading a blob that says "direct".
///
/// Only values whose bytes match the per-connection layout are returned: a
/// value this crate cannot parse is not something it should write through the
/// WinINet API or mutate.
pub(super) fn named_connection_values() -> Vec<String> {
    use winreg::enums::{RegType, HKEY_CURRENT_USER, KEY_READ};
    use winreg::RegKey;

    let Ok(key) =
        RegKey::predef(HKEY_CURRENT_USER).open_subkey_with_flags(INTERNET_CONNECTIONS, KEY_READ)
    else {
        return Vec::new();
    };
    key.enum_values()
        .filter_map(|entry| entry.ok())
        .filter(|(name, value)| {
            value.vtype == RegType::REG_BINARY
                && name != DEFAULT_CONNECTION_VALUE
                && name != SAVED_LEGACY_VALUE
                && ConnectionBlob::parse(&value.bytes).is_some()
        })
        .map(|(name, _)| name)
        .collect()
}

pub(super) fn read_connection_blob(name: Option<&str>) -> Option<ConnectionBlob> {
    use winreg::enums::{HKEY_CURRENT_USER, KEY_READ};
    use winreg::RegKey;

    let key = RegKey::predef(HKEY_CURRENT_USER)
        .open_subkey_with_flags(INTERNET_CONNECTIONS, KEY_READ)
        .ok()?;
    let raw = key
        .get_raw_value(name.unwrap_or(DEFAULT_CONNECTION_VALUE))
        .ok()?;
    ConnectionBlob::parse(&raw.bytes)
}

/// Capture the stored bytes verbatim: a parse-and-reserialize round trip could
/// drop a section this crate does not understand. Restore goes through the
/// WinINet API again, so entries that do not parse are skipped there.
pub(super) fn snapshot_connection_blobs() -> Vec<WinConnectionBlob> {
    use winreg::enums::{RegType, HKEY_CURRENT_USER, KEY_READ};
    use winreg::RegKey;

    let Ok(key) = RegKey::predef(HKEY_CURRENT_USER)
        .open_subkey_with_flags(INTERNET_CONNECTIONS, KEY_READ)
    else {
        return Vec::new();
    };
    let mut entries = Vec::new();
    if let Ok(raw) = key.get_raw_value(DEFAULT_CONNECTION_VALUE) {
        entries.push(WinConnectionBlob {
            name: None,
            bytes: raw.bytes,
        });
    }
    for (name, value) in key.enum_values().filter_map(|entry| entry.ok()) {
        if value.vtype != RegType::REG_BINARY
            || name == DEFAULT_CONNECTION_VALUE
            || name == SAVED_LEGACY_VALUE
        {
            continue;
        }
        entries.push(WinConnectionBlob {
            name: Some(name),
            bytes: value.bytes,
        });
    }
    entries
}

/// Put the captured per-connection modes back through the same WinINet API
/// the apply path uses. No raw registry blob writes: the snapshot is only
/// parsed for the values the API accepts.
///
/// Returns whether the LAN entry was put back. That entry is the one a normal
/// machine uses; a named connection that refuses the write is only logged, so
/// one stale VPN entry cannot block the restore.
pub(super) fn restore_connection_settings(entries: &[WinConnectionBlob]) -> bool {
    let mut saw_lan = false;
    let mut lan_restored = true;
    for entry in entries {
        let value_name = entry.name.as_deref().unwrap_or(DEFAULT_CONNECTION_VALUE);
        let is_lan = entry.name.is_none();
        if is_lan {
            saw_lan = true;
        }
        let Some(blob) = ConnectionBlob::parse(&entry.bytes) else {
            tracing::warn!(
                blob = value_name,
                "skipping an unparseable WinINet connection blob in the snapshot"
            );
            if is_lan {
                lan_restored = false;
            }
            continue;
        };
        let pac = blob.pac_url();
        let server = blob.proxy_server();
        let bypass = blob.proxy_bypass();
        // Never restore a mode bit whose value is missing: an enabled fixed
        // proxy with no server, or a PAC with no URL, would break browsing.
        let flags = restore_flags(Some(blob.flags()), pac.is_some(), server.is_some());
        match apply_per_connection(
            entry.name.as_deref(),
            flags,
            pac.as_deref(),
            server.as_deref(),
            bypass.as_deref(),
        ) {
            Ok(()) if is_lan => {
                // A successful call is not proof the blob changed; verify it.
                lan_restored =
                    connection_blob_matches(None, flags, pac.as_deref(), server.as_deref());
                if !lan_restored {
                    tracing::warn!("WinINet did not keep the restored LAN settings");
                }
            }
            Ok(()) => {
                // A named connection that silently keeps another mode is not
                // worth blocking the snapshot removal over, but log it.
                if !connection_blob_matches(
                    entry.name.as_deref(),
                    flags,
                    pac.as_deref(),
                    server.as_deref(),
                ) {
                    tracing::warn!(
                        blob = value_name,
                        "WinINet did not keep the restored connection settings"
                    );
                }
            }
            Err(error) => {
                tracing::warn!(
                    blob = value_name,
                    error = %error,
                    "failed to restore a WinINet connection"
                );
                if is_lan {
                    lan_restored = false;
                }
            }
        }
    }
    // A snapshot without the LAN entry cannot be trusted to put the machine
    // back; keep it for a retry instead of deleting it.
    saw_lan && lan_restored
}

/// Write WinINet's per-connection proxy configuration.
///
/// This is the state WinINet enforces: on a settings-changed notification it
/// refreshes the legacy registry values from the blob. Writing only the legacy
/// values is therefore not enough — when the blob still says "direct", the
/// notification deletes the freshly written `AutoConfigURL` again. Updating
/// the blob first keeps the two views consistent, so both survive.
///
/// `connection = None` targets the LAN entry; `Some(name)` targets that
/// dial-up/VPN connection.
pub(super) fn apply_per_connection(
    connection: Option<&str>,
    flags: u32,
    pac_url: Option<&str>,
    proxy_server: Option<&str>,
    proxy_bypass: Option<&str>,
) -> Result<()> {
    use windows_sys::Win32::Networking::WinInet::{
        InternetSetOptionW, INTERNET_OPTION_PER_CONNECTION_OPTION,
        INTERNET_PER_CONN_AUTOCONFIG_URL, INTERNET_PER_CONN_FLAGS, INTERNET_PER_CONN_OPTIONW,
        INTERNET_PER_CONN_OPTIONW_0, INTERNET_PER_CONN_OPTION_LISTW,
        INTERNET_PER_CONN_PROXY_BYPASS, INTERNET_PER_CONN_PROXY_SERVER,
    };

    // The API reads these buffers synchronously; keep them alive until it
    // returns.
    let mut connection_name: Option<Vec<u16>> =
        connection.map(|name| name.encode_utf16().chain([0]).collect());
    let mut pac: Option<Vec<u16>> = pac_url.map(|url| url.encode_utf16().chain([0]).collect());
    let mut server: Option<Vec<u16>> = proxy_server.map(|s| s.encode_utf16().chain([0]).collect());
    let mut bypass: Option<Vec<u16>> = proxy_bypass.map(|s| s.encode_utf16().chain([0]).collect());

    let string_option = |option: u32, value: *mut u16| INTERNET_PER_CONN_OPTIONW {
        dwOption: option,
        Value: INTERNET_PER_CONN_OPTIONW_0 { pszValue: value },
    };

    let mut options: Vec<INTERNET_PER_CONN_OPTIONW> = Vec::with_capacity(4);
    options.push(INTERNET_PER_CONN_OPTIONW {
        dwOption: INTERNET_PER_CONN_FLAGS,
        Value: INTERNET_PER_CONN_OPTIONW_0 { dwValue: flags },
    });
    if let Some(server) = server.as_mut() {
        options.push(string_option(
            INTERNET_PER_CONN_PROXY_SERVER,
            server.as_mut_ptr(),
        ));
    }
    if let Some(bypass) = bypass.as_mut() {
        options.push(string_option(
            INTERNET_PER_CONN_PROXY_BYPASS,
            bypass.as_mut_ptr(),
        ));
    }
    if let Some(pac) = pac.as_mut() {
        options.push(string_option(
            INTERNET_PER_CONN_AUTOCONFIG_URL,
            pac.as_mut_ptr(),
        ));
    }

    let mut list = INTERNET_PER_CONN_OPTION_LISTW {
        dwSize: std::mem::size_of::<INTERNET_PER_CONN_OPTION_LISTW>() as u32,
        // NULL selects the LAN connection, which the legacy values describe.
        pszConnection: connection_name
            .as_mut()
            .map_or(std::ptr::null_mut(), |name| name.as_mut_ptr()),
        dwOptionCount: options.len() as u32,
        dwOptionError: 0,
        pOptions: options.as_mut_ptr(),
    };
    let pointer: *const std::ffi::c_void = std::ptr::from_mut(&mut list).cast();
    let ok = unsafe {
        InternetSetOptionW(
            std::ptr::null(),
            INTERNET_OPTION_PER_CONNECTION_OPTION,
            pointer,
            list.dwSize,
        )
    };
    if ok == 0 {
        return Err(std::io::Error::last_os_error())
            .context("setting per-connection proxy options");
    }
    Ok(())
}

/// Write the setting to the LAN entry and every dial-up/VPN entry.
///
/// A named connection may refuse (for example when it is not connected), which
/// is only logged: the blob check afterwards decides whether the refusal
/// matters. A LAN failure is collected instead of returned so the caller can
/// still write the legacy values that registry readers use; the final
/// verification reports the real outcome.
pub(super) fn apply_to_all_connections(
    flags: u32,
    pac_url: Option<&str>,
    proxy_server: Option<&str>,
    proxy_bypass: Option<&str>,
    failed: &mut Vec<String>,
) {
    if let Err(error) = apply_per_connection(None, flags, pac_url, proxy_server, proxy_bypass) {
        failed.push(format!("{DEFAULT_CONNECTION_VALUE}: {error:#}"));
    }

    for name in named_connection_values() {
        if let Err(error) =
            apply_per_connection(Some(&name), flags, pac_url, proxy_server, proxy_bypass)
        {
            tracing::debug!(
                connection = %name,
                error = %error,
                "WinINet refused a named connection; the blob check covers it"
            );
        }
    }
}

/// Whether one connection's blob holds the values we just applied. Read back
/// from the registry rather than from WinINet's cache: the cache can accept a
/// write that never reaches the blob, and then the next reload undoes the
/// mirror. Read-only; nothing here writes registry bytes.
pub(super) fn connection_blob_matches(
    name: Option<&str>,
    flags: u32,
    pac_url: Option<&str>,
    proxy_server: Option<&str>,
) -> bool {
    let Some(blob) = read_connection_blob(name) else {
        return false;
    };
    let mode_bits = WIN_PROXY_TYPE_PROXY | WIN_PROXY_TYPE_AUTO_PROXY_URL;
    if blob.flags() & mode_bits != flags & mode_bits {
        return false;
    }
    if let Some(url) = pac_url {
        if blob
            .pac_url()
            .as_deref()
            .is_none_or(|stored| !same_url(stored, url))
        {
            return false;
        }
    }
    if let Some(server) = proxy_server {
        if blob.proxy_server().as_deref() != Some(server) {
            return false;
        }
    }
    true
}

/// Read the LAN blob back, allowing a moment for WinINet to flush the API
/// write. A false "not persisted" must not warn on a healthy machine.
pub(super) fn lan_blob_persisted(flags: u32, pac_url: Option<&str>, proxy_server: Option<&str>) -> bool {
    for attempt in 0..4 {
        if connection_blob_matches(None, flags, pac_url, proxy_server) {
            return true;
        }
        if attempt < 3 {
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    false
}

/// Every connection we wrote must carry the setting: the effective one is not
/// necessarily the LAN entry, and checking only that entry would let a silent
/// failure on a VPN/dial-up entry go unnoticed.
pub(super) fn all_connection_blobs_match(
    flags: u32,
    pac_url: Option<&str>,
    proxy_server: Option<&str>,
) -> bool {
    if !connection_blob_matches(None, flags, pac_url, proxy_server) {
        return false;
    }
    named_connection_values()
        .iter()
        .all(|name| connection_blob_matches(Some(name), flags, pac_url, proxy_server))
}

pub(super) fn platform_apply_pac(_state_path: &Path, pac_url: &str) -> Result<Vec<String>> {
    use windows_sys::Win32::Networking::WinInet::{PROXY_TYPE_AUTO_PROXY_URL, PROXY_TYPE_DIRECT};
    use winreg::enums::{HKEY_CURRENT_USER, KEY_READ, KEY_WRITE};
    use winreg::RegKey;

    let flags = PROXY_TYPE_DIRECT | PROXY_TYPE_AUTO_PROXY_URL;
    let mut failed = Vec::new();

    tracing::debug!(
        before = ?log_blob(),
        "WinINet connection blob before applying the PAC"
    );

    apply_to_all_connections(flags, Some(pac_url), None, None, &mut failed);

    // If the call is accepted but the blob does not change, there is no
    // documented way to force it: log it and continue with the legacy mirror
    // instead of writing registry bytes by hand.
    if !lan_blob_persisted(flags, Some(pac_url), None) {
        tracing::warn!(
            "WinINet did not persist the per-connection PAC; continuing with the registry mirror"
        );
    } else if !all_connection_blobs_match(flags, Some(pac_url), None) {
        tracing::warn!("WinINet kept the PAC on only some connections");
    }

    let key = RegKey::predef(HKEY_CURRENT_USER)
        .open_subkey_with_flags(INTERNET_SETTINGS, KEY_READ | KEY_WRITE)
        .context("opening Internet Settings registry key")?;
    // Mirror the legacy values for readers that do not go through WinINet,
    // including this crate's health probe. When the blob carries the same PAC
    // the notification cannot undo them; otherwise the check below restores
    // the mirror after the reload.
    key.set_value("AutoConfigURL", &pac_url)
        .context("setting AutoConfigURL")?;
    // PAC takes precedence; disable the fixed proxy so a stale old value cannot win.
    key.set_value("ProxyEnable", &0u32)
        .context("disabling fixed proxy")?;
    notify_proxy_changed();

    // The reload rewrites the legacy values from the blob it considers
    // effective. If that blob is not the one above, the reload deletes the
    // mirror; put it back after the notification without notifying again, or
    // the same overwrite would run one more time.
    if key.get_value::<String, _>("AutoConfigURL").ok().as_deref() != Some(pac_url) {
        key.set_value("AutoConfigURL", &pac_url)
            .context("restoring AutoConfigURL after the settings reload")?;
        let _ = key.set_value("ProxyEnable", &0u32);
        tracing::warn!(
            "Windows reset the registry proxy mirror after the settings reload; wrote it again"
        );
    } else if key.get_value::<u32, _>("ProxyEnable").ok() == Some(1) {
        // PAC wins over the fixed proxy; turning this off only keeps the
        // mirror honest for readers that inspect both.
        let _ = key.set_value("ProxyEnable", &0u32);
    }

    tracing::debug!(
        after = ?log_blob(),
        "WinINet connection blob after applying the PAC"
    );
    // Final truth checks: the mirror is what registry readers (Chromium) use,
    // and the blob is what WinINet clients use. A silent revert in either must
    // not look like a clean success.
    if key.get_value::<String, _>("AutoConfigURL").ok().as_deref() != Some(pac_url) {
        failed.push("the registry proxy mirror no longer contains this PAC after the apply".into());
    }
    if !lan_blob_persisted(flags, Some(pac_url), None) {
        failed.push(
            "WinINet did not keep the PAC in its connection settings; Windows may reset it again"
                .into(),
        );
    } else if !all_connection_blobs_match(flags, Some(pac_url), None) {
        tracing::warn!("WinINet kept the PAC on only some connections after the apply");
    }
    Ok(failed)
}

pub(super) fn log_blob() -> Option<(u32, Option<String>, Option<String>)> {
    read_connection_blob(None).map(|blob| (blob.flags(), blob.pac_url(), blob.proxy_server()))
}

pub(super) fn platform_apply_http(_state_path: &Path, proxy: SocketAddr) -> Result<Vec<String>> {
    use windows_sys::Win32::Networking::WinInet::{PROXY_TYPE_DIRECT, PROXY_TYPE_PROXY};
    use winreg::enums::{HKEY_CURRENT_USER, KEY_READ, KEY_WRITE};
    use winreg::RegKey;

    let server = format!("http={proxy};https={proxy}", proxy = proxy);
    let flags = PROXY_TYPE_DIRECT | PROXY_TYPE_PROXY;
    let mut failed = Vec::new();
    apply_to_all_connections(flags, None, Some(&server), Some("<local>"), &mut failed);

    if !lan_blob_persisted(flags, None, Some(&server)) {
        tracing::warn!(
            "WinINet did not persist the per-connection HTTP proxy; continuing with the registry \
             mirror"
        );
    } else if !all_connection_blobs_match(flags, None, Some(&server)) {
        tracing::warn!("WinINet kept the HTTP proxy on only some connections");
    }

    let key = RegKey::predef(HKEY_CURRENT_USER)
        .open_subkey_with_flags(INTERNET_SETTINGS, KEY_READ | KEY_WRITE)
        .context("opening Internet Settings registry key")?;
    let _ = key.delete_value("AutoConfigURL");
    key.set_value("ProxyServer", &server)
        .context("setting ProxyServer")?;
    key.set_value("ProxyOverride", &"<local>")
        .context("setting ProxyOverride")?;
    key.set_value("ProxyEnable", &1u32)
        .context("enabling fixed proxy")?;
    notify_proxy_changed();

    let mirror_matches = key.get_value::<u32, _>("ProxyEnable").ok() == Some(1)
        && key.get_value::<String, _>("ProxyServer").ok().as_deref() == Some(server.as_str());
    if !mirror_matches {
        key.set_value("ProxyServer", &server)
            .context("restoring ProxyServer after the settings reload")?;
        key.set_value("ProxyEnable", &1u32)
            .context("restoring ProxyEnable after the settings reload")?;
        tracing::warn!(
            "Windows reset the registry proxy mirror after the settings reload; wrote it again"
        );
    }
    // A PAC from another connection's blob can come back with the reload; the
    // fixed proxy must stay the only mode in effect.
    if key.get_value::<String, _>("AutoConfigURL").is_ok() {
        let _ = key.delete_value("AutoConfigURL");
    }
    // Final truth checks: the mirror is what registry readers (Chromium) use,
    // so a silent revert must not look like a clean success. A PAC URL would
    // take precedence over the fixed proxy, so it must not be back either.
    let pac_present = key
        .get_value::<String, _>("AutoConfigURL")
        .ok()
        .is_some_and(|url| !url.is_empty());
    let mirror_ok = !pac_present
        && key.get_value::<u32, _>("ProxyEnable").ok() == Some(1)
        && key.get_value::<String, _>("ProxyServer").ok().as_deref() == Some(server.as_str());
    if !mirror_ok {
        failed.push("the registry proxy mirror no longer contains this proxy after the apply".into());
    }
    if !lan_blob_persisted(flags, None, Some(&server)) {
        failed.push(
            "WinINet did not keep the HTTP proxy in its connection settings; Windows may reset it \
             again"
                .into(),
        );
    } else if !all_connection_blobs_match(flags, None, Some(&server)) {
        tracing::warn!("WinINet kept the HTTP proxy on only some connections after the apply");
    }
    Ok(failed)
}

pub(super) fn platform_pac_disable() {
    use windows_sys::Win32::Networking::WinInet::{
        PROXY_TYPE_AUTO_PROXY_URL, PROXY_TYPE_DIRECT, PROXY_TYPE_PROXY,
    };
    use winreg::enums::{HKEY_CURRENT_USER, KEY_READ, KEY_WRITE};
    use winreg::RegKey;

    let Ok(key) = RegKey::predef(HKEY_CURRENT_USER)
        .open_subkey_with_flags(INTERNET_SETTINGS, KEY_READ | KEY_WRITE)
    else {
        return;
    };
    // Only this instance's PAC is ours to clear: a user-configured fixed proxy
    // stays enabled.
    let enabled: u32 = key.get_value("ProxyEnable").unwrap_or(0);
    let server: Option<String> = key.get_value("ProxyServer").ok();
    let bypass: Option<String> = key.get_value("ProxyOverride").ok();
    let present_server = server.as_deref().filter(|server| !server.is_empty());
    let manual = enabled == 1 && present_server.is_some();
    // Clear only the PAC bit; keep auto-detect and any manual proxy the user
    // configured for themselves.
    let mut flags = read_connection_flags().unwrap_or(PROXY_TYPE_DIRECT);
    flags &= !PROXY_TYPE_AUTO_PROXY_URL;
    if manual {
        flags |= PROXY_TYPE_PROXY;
    } else {
        flags &= !PROXY_TYPE_PROXY;
    }
    if flags == 0 {
        flags = PROXY_TYPE_DIRECT;
    }
    let lan_server = if manual { present_server } else { None };
    let lan_bypass = if manual { bypass.as_deref() } else { None };

    if let Err(error) = apply_per_connection(None, flags, None, lan_server, lan_bypass) {
        tracing::warn!(error = %error, "failed to clear the per-connection PAC setting");
    }

    // Clear the PAC bit on every connection entry too. Only that bit: each
    // entry keeps its own proxy and auto-detect settings instead of inheriting
    // the LAN entry's flags.
    for name in named_connection_values() {
        let Some(blob) = read_connection_blob(Some(&name)) else {
            continue;
        };
        if blob.flags() & WIN_PROXY_TYPE_AUTO_PROXY_URL == 0 {
            continue;
        }
        let mut entry_flags = blob.flags() & !WIN_PROXY_TYPE_AUTO_PROXY_URL;
        if entry_flags == 0 {
            entry_flags = PROXY_TYPE_DIRECT;
        }
        if let Err(error) = apply_per_connection(Some(&name), entry_flags, None, None, None) {
            tracing::debug!(
                connection = %name,
                error = %error,
                "WinINet refused to clear the PAC on a named connection"
            );
        }
    }

    let _ = key.delete_value("AutoConfigURL");
    // WinINet keeps the previous PAC in memory until it is told the settings
    // changed; without this the browser would keep dialing the dead PAC port
    // after a takeover was rolled back.
    notify_proxy_changed();

    // A reload can write the old in-memory PAC back. Report it instead of
    // forcing registry bytes: the next apply/disable retries through the API.
    if !connection_blob_matches(None, flags, None, lan_server) {
        tracing::warn!("Windows kept the PAC in the LAN connection settings after clearing it");
    }
    for name in named_connection_values() {
        if read_connection_blob(Some(&name))
            .is_some_and(|blob| blob.flags() & WIN_PROXY_TYPE_AUTO_PROXY_URL != 0)
        {
            tracing::warn!(
                connection = %name,
                "Windows kept the PAC on a named connection after clearing it"
            );
        }
    }
}

/// Reconcile the captured per-connection flags with the values that are
/// actually being restored: never keep a mode bit whose value is missing, and
/// never pass a value without its mode bit (that inconsistency is what makes
/// WinINet drop the PAC on the next reload). Unrelated bits, such as
/// auto-detect, are preserved.
pub(super) fn restore_flags(saved: Option<u32>, has_pac: bool, has_manual: bool) -> u32 {
    use windows_sys::Win32::Networking::WinInet::{
        PROXY_TYPE_AUTO_PROXY_URL, PROXY_TYPE_DIRECT, PROXY_TYPE_PROXY,
    };

    let mut flags = saved.unwrap_or(PROXY_TYPE_DIRECT);
    if has_pac {
        flags |= PROXY_TYPE_AUTO_PROXY_URL;
    } else {
        flags &= !PROXY_TYPE_AUTO_PROXY_URL;
    }
    if has_manual {
        flags |= PROXY_TYPE_PROXY;
    } else {
        flags &= !PROXY_TYPE_PROXY;
    }
    if flags == 0 {
        flags = PROXY_TYPE_DIRECT;
    }
    flags
}

pub(super) fn platform_restore(state: &SavedState) -> Result<()> {
    use winreg::enums::{HKEY_CURRENT_USER, KEY_READ, KEY_WRITE};
    use winreg::RegKey;

    let auto = state
        .auto_config_url
        .as_deref()
        .filter(|url| !url.is_empty());
    let manual_server = state
        .proxy_enable
        .filter(|enabled| *enabled == 1)
        .and(state.proxy_server.as_deref())
        .filter(|server| !server.is_empty());
    let bypass = manual_server.and(state.proxy_override.as_deref());

    // Restore the per-connection state first: it is what WinINet enforces on
    // the next settings reload. Restoring only the legacy values below would
    // be reverted by that reload. The captured blobs carry every connection's
    // own mode and are written back through the API; older snapshots only
    // carry the LAN flags, which are re-derived from the restored values.
    let lan_restored = if !state.win_connections.is_empty() {
        let restored = restore_connection_settings(&state.win_connections);
        if !restored {
            tracing::warn!("WinINet did not restore the per-connection proxy settings");
        }
        restored
    } else {
        let flags = restore_flags(
            state.win_proxy_flags,
            auto.is_some(),
            manual_server.is_some(),
        );
        match apply_per_connection(None, flags, auto, manual_server, bypass) {
            Ok(()) => {
                let restored = connection_blob_matches(None, flags, auto, manual_server);
                if !restored {
                    tracing::warn!("WinINet did not keep the restored LAN settings");
                }
                restored
            }
            Err(error) => {
                tracing::warn!(error = %error, "failed to restore per-connection proxy settings");
                false
            }
        }
    };

    let key = RegKey::predef(HKEY_CURRENT_USER)
        .open_subkey_with_flags(INTERNET_SETTINGS, KEY_READ | KEY_WRITE)
        .context("opening Internet Settings registry key")?;
    match state.proxy_enable {
        Some(value) => key.set_value("ProxyEnable", &value)?,
        None => {
            let _ = key.delete_value("ProxyEnable");
        }
    }
    match &state.auto_config_url {
        Some(value) => key.set_value("AutoConfigURL", value)?,
        None => {
            let _ = key.delete_value("AutoConfigURL");
        }
    }
    match &state.proxy_server {
        Some(value) => key.set_value("ProxyServer", value)?,
        None => {
            let _ = key.delete_value("ProxyServer");
        }
    }
    match &state.proxy_override {
        Some(value) => key.set_value("ProxyOverride", value)?,
        None => {
            let _ = key.delete_value("ProxyOverride");
        }
    }

    if !lan_restored {
        // Reloading now would let WinINet copy the stale blob back over the
        // values just restored. Leave the snapshot in place so the next start
        // or `restore-proxy` retries once the blob write can succeed.
        tracing::warn!("skipping the proxy reload because the WinINet blob was not restored");
        bail!("the WinINet per-connection settings could not be restored");
    }
    notify_proxy_changed();
    Ok(())
}

pub(super) fn platform_current(mode: Option<ProxyMode>) -> Result<CurrentProxy> {
    use winreg::enums::{HKEY_CURRENT_USER, KEY_READ};
    use winreg::RegKey;

    let key = RegKey::predef(HKEY_CURRENT_USER)
        .open_subkey_with_flags(INTERNET_SETTINGS, KEY_READ)
        .context("opening Internet Settings registry key")?;
    let legacy_auto: Option<String> = key.get_value("AutoConfigURL").ok();
    let legacy_server: Option<String> = key.get_value("ProxyServer").ok();
    let legacy_enabled: u32 = key.get_value("ProxyEnable").unwrap_or(0);

    // WinINet enforces the per-connection blob and mirrors it into the legacy
    // values. A readable blob is therefore authoritative even when it says a
    // different mode than the mirror: falling back to the mirror in that case
    // would report a takeover as applied while WinINet clients ignore it. The
    // mirror is only a fallback when the blob cannot be read at all.
    let blob = read_connection_blob(None);
    let auto = match blob.as_ref() {
        Some(blob) if blob.flags() & WIN_PROXY_TYPE_AUTO_PROXY_URL != 0 => blob.pac_url(),
        Some(_) => None,
        None => legacy_auto,
    };
    let (server, enabled) = match blob.as_ref() {
        Some(blob) if blob.flags() & WIN_PROXY_TYPE_PROXY != 0 => (blob.proxy_server(), 1),
        Some(_) => (None, 0),
        None => (legacy_server, legacy_enabled),
    };
    Ok(CurrentProxy {
        supported: true,
        current: windows_current(mode, auto, server, enabled),
    })
}

pub(super) fn platform_legacy_pac_url() -> Option<String> {
    use winreg::enums::{HKEY_CURRENT_USER, KEY_READ};
    use winreg::RegKey;

    let key = RegKey::predef(HKEY_CURRENT_USER)
        .open_subkey_with_flags(INTERNET_SETTINGS, KEY_READ)
        .ok()?;
    key.get_value("AutoConfigURL").ok()
}

pub(super) fn notify_proxy_changed() {
    use windows_sys::Win32::Networking::WinInet::{
        InternetSetOptionW, INTERNET_OPTION_REFRESH, INTERNET_OPTION_SETTINGS_CHANGED,
    };
    let settings_changed = unsafe {
        InternetSetOptionW(
            std::ptr::null(),
            INTERNET_OPTION_SETTINGS_CHANGED,
            std::ptr::null(),
            0,
        )
    };
    let refreshed = unsafe {
        InternetSetOptionW(
            std::ptr::null(),
            INTERNET_OPTION_REFRESH,
            std::ptr::null(),
            0,
        )
    };
    if settings_changed == 0 || refreshed == 0 {
        tracing::warn!(
            settings_changed,
            refreshed,
            error = %std::io::Error::last_os_error(),
            "WinINet did not acknowledge the proxy change notification"
        );
    }
}
