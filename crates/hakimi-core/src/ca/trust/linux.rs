//! Linux：发行版信任锚（Debian/RHEL/p11-kit）。
//!
//! 由 `ca::trust` 原文件按平台切分而来，逻辑未改动。

use super::*;

pub(super) fn install_target() -> Option<(String, String)> {
    distro::detect(distro::exists)
        .map(|layout| (layout.anchor.to_string(), layout.update.join(" ")))
}

pub(super) fn trust_status(
    _sha1_hex: &str,
    cert_path: &Path,
) -> Result<(bool, bool, Option<String>)> {
    let Some(layout) = distro::detect(distro::exists) else {
        return Ok((
            false,
            false,
            Some("未找到受支持的 CA 信任库；请用 `hakimi ca export` 导出后手动信任".into()),
        ));
    };
    let pem = match std::fs::read(cert_path) {
        Ok(pem) => pem,
        Err(error) => {
            return Ok((
                true,
                false,
                Some(format!("读取 {} 失败：{error}", cert_path.display())),
            ));
        }
    };
    let Some(der) = distro::pem_to_der(&pem) else {
        return Ok((true, false, Some("本地 CA 文件不是有效的 PEM".into())));
    };
    let bundle = std::fs::read(layout.bundle).unwrap_or_default();
    Ok((true, distro::bundle_contains(&bundle, &der), None))
}

pub(super) fn install_cert(der: &[u8], pem_path: &Path) -> Result<()> {
    let Some(layout) = distro::detect(distro::exists) else {
        bail!(
            "未找到受支持的 CA 信任库；该发行版可能用声明式方式管理信任（例如 NixOS）。\
             请用 `hakimi ca export` 导出证书，再按系统的配置方式加入"
        )
    };
    let pem = std::fs::read(pem_path).unwrap_or_else(|_| distro::der_to_pem(der));
    write_anchor(layout.anchor, &pem)?;
    run_update(layout)?;
    // The update tool can exit 0 and still skip the file (wrong suffix, a stale
    // lock), so success is only reported once the bundle lists the certificate.
    let bundle = std::fs::read(layout.bundle).unwrap_or_default();
    if !distro::bundle_contains(&bundle, der) {
        bail!(
            "已写入 {}，但 {} 中还没有这张证书；请手动执行 `{}` 并检查输出",
            layout.anchor,
            layout.bundle,
            layout.update.join(" ")
        );
    }
    Ok(())
}

pub(super) fn uninstall_by_sha1(_sha1_hex: &str, _remove_trust: bool) -> Result<()> {
    let Some(layout) = distro::detect(distro::exists) else {
        return Ok(());
    };
    match std::fs::remove_file(layout.anchor) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
            return Err(anyhow::Error::new(super::super::NeedsRoot {
                path: layout.anchor.to_string(),
            }))
        }
        Err(error) => return Err(error).with_context(|| format!("删除 {} 失败", layout.anchor)),
    }
    run_update(layout)
}

fn write_anchor(path: &str, pem: &[u8]) -> Result<()> {
    if let Some(parent) = Path::new(path).parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("创建 {} 失败", parent.display()))?;
    }
    match std::fs::write(path, pem) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
            Err(anyhow::Error::new(super::super::NeedsRoot {
                path: path.to_string(),
            }))
        }
        Err(error) => Err(error).with_context(|| format!("写入 {path} 失败")),
    }
}

fn run_update(layout: &distro::Layout) -> Result<()> {
    let Some((program, args)) = layout.update.split_first() else {
        bail!("信任库配置缺少重建命令");
    };
    let output = std::process::Command::new(program)
        .args(args)
        .output()
        .with_context(|| format!("执行 {program} 失败"))?;
    if !output.status.success() {
        bail!(
            "{program} 执行失败：{}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}

#[cfg(test)]
