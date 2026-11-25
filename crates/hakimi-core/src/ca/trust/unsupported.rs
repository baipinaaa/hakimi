//! 其他平台：明确报告不支持自动安装。
//!
//! 由 `ca::trust` 原文件按平台切分而来，逻辑未改动。

use super::*;

#[cfg(not(any(
    windows,
    target_os = "macos",
    target_os = "android",
    target_os = "linux"
)))]
pub(super) fn trust_status(
    _sha1_hex: &str,
    _cert_path: &Path,
) -> Result<(bool, bool, Option<String>)> {
    Ok((
        false,
        false,
        Some("该平台不支持自动检查 CA 信任状态".into()),
    ))
}

#[cfg(not(any(
    windows,
    target_os = "macos",
    target_os = "android",
    target_os = "linux"
)))]
pub(super) fn install_cert(_der: &[u8], _pem_path: &Path) -> Result<()> {
    bail!("该平台不支持自动安装 CA；请用 `hakimi ca export` 导出后手动信任")
}
#[cfg(not(any(
    windows,
    target_os = "macos",
    target_os = "android",
    target_os = "linux"
)))]
pub(super) fn uninstall_by_sha1(_sha1_hex: &str, _remove_trust: bool) -> Result<()> {
    bail!("该平台不支持自动移除 CA")
}
