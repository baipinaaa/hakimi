//! Linux 与其他平台：没有统一的系统代理可接管，明确返回不支持。
//!
//! 由 `system_proxy` 原文件按平台切分而来，逻辑未改动。

use super::*;

pub(super) fn platform_snapshot(_mode: ProxyMode) -> Result<SavedState> {
    Ok(SavedState {
        platform: std::env::consts::OS.to_string(),
        ..Default::default()
    })
}

pub(super) fn platform_apply_pac(_state_path: &Path, _pac_url: &str) -> Result<Vec<String>> {
    anyhow::bail!(
        "this platform has no system proxy to take over; point your own tools at the proxy \
         (`hakimi env` for a shell, `hakimi pac` for a PAC file)"
    )
}

pub(super) fn platform_apply_http(_state_path: &Path, _proxy: SocketAddr) -> Result<Vec<String>> {
    anyhow::bail!(
        "this platform has no system proxy to take over; point your own tools at the proxy \
         (`hakimi env` for a shell, `hakimi pac` for a PAC file)"
    )
}

pub(super) fn platform_restore(_state: &SavedState) -> Result<()> {
    Ok(())
}

pub(super) fn platform_pac_disable() {}

pub(super) fn platform_legacy_pac_url() -> Option<String> {
    None
}

pub(super) fn platform_current(_mode: Option<ProxyMode>) -> Result<CurrentProxy> {
    Ok(CurrentProxy {
        supported: false,
        current: None,
    })
}
