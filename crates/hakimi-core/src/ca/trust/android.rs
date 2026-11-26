//! Android：系统证书由用户在设置里手动安装，这里只记录状态。
//!
//! 由 `ca::trust` 原文件按平台切分而来，逻辑未改动。

use super::*;

pub(crate) fn trust_status(
    _sha1_hex: &str,
    _cert_path: &Path,
) -> Result<(bool, bool, Option<String>)> {
    Ok((true, ANDROID_CA_TRUSTED.load(Ordering::SeqCst), None))
}
pub(crate) fn install_cert(_der: &[u8], _pem_path: &Path) -> Result<()> {
    bail!("请在 Android 设置中手动安装导出的 CA（用户证书）")
}
pub(crate) fn uninstall_by_sha1(_sha1_hex: &str, _remove_trust: bool) -> Result<()> {
    bail!("请在 Android 设置中手动移除该 CA")
}
