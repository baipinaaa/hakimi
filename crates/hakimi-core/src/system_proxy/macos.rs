//! macOS：networksetup（逐网络服务）+ scutil --proxy（读回校验）。
//!
//! 由 `system_proxy` 原文件按平台切分而来，逻辑未改动。

use super::*;

pub(super) fn platform_snapshot(mode: ProxyMode) -> Result<SavedState> {
    let services = list_network_services()?;
    let mut mac_pac = Vec::new();
    let mut mac_http = Vec::new();
    match mode {
        ProxyMode::Pac => {
            for service in &services {
                let text = run_networksetup_with_timeout(
                    &["-getautoproxyurl", service],
                    NETWORKSETUP_TIMEOUT_SECS,
                )?;
                let (enabled, url) = parse_mac_pac(&text);
                mac_pac.push(MacPacState {
                    service: service.clone(),
                    enabled,
                    url,
                });
            }
        }
        ProxyMode::Http => {
            for service in &services {
                let web = run_networksetup_with_timeout(
                    &["-getwebproxy", service],
                    NETWORKSETUP_TIMEOUT_SECS,
                )?;
                let secure = run_networksetup_with_timeout(
                    &["-getsecurewebproxy", service],
                    NETWORKSETUP_TIMEOUT_SECS,
                )?;
                let (web_enabled, web_server, web_port) = parse_mac_http_proxy(&web);
                let (secure_enabled, secure_server, secure_port) = parse_mac_http_proxy(&secure);
                mac_http.push(MacHttpState {
                    service: service.clone(),
                    web_enabled,
                    web_server,
                    web_port,
                    secure_enabled,
                    secure_server,
                    secure_port,
                });
            }
        }
        ProxyMode::Off => {}
    }
    Ok(SavedState {
        platform: "macos".into(),
        mac_services: services,
        mac_pac,
        mac_http,
        ..Default::default()
    })
}

pub(super) fn list_network_services() -> Result<Vec<String>> {
    let text =
        run_networksetup_with_timeout(&["-listallnetworkservices"], NETWORKSETUP_TIMEOUT_SECS)?;
    let text = text.as_str();
    Ok(text
        .lines()
        .skip(1)
        .filter(|line| !line.trim().is_empty() && !line.starts_with('*'))
        .map(|line| line.trim().to_string())
        .collect())
}

pub(super) fn run_networksetup(args: &[&str]) -> Result<()> {
    run_networksetup_with_timeout(args, NETWORKSETUP_TIMEOUT_SECS).map(|_| ())
}

/// `networksetup` serialises on the system configuration daemon and is known
/// to hang for seconds when that daemon is busy. Every call is bounded so a
/// stuck invocation cannot stall the health check or a self-heal.
pub(super) fn run_networksetup_with_timeout(args: &[&str], timeout_secs: u64) -> Result<String> {
    run_command_with_timeout("networksetup", args, timeout_secs)
}

pub(super) const NETWORKSETUP_TIMEOUT_SECS: u64 = 3;

pub(super) fn platform_apply_pac(_state_path: &Path, pac_url: &str) -> Result<Vec<String>> {
    let mut failed = Vec::new();
    for service in list_network_services()? {
        if let Err(error) = run_networksetup(&["-setautoproxyurl", &service, pac_url]) {
            failed.push(format!("{service}: {error:#}"));
            continue;
        }
        if let Err(error) = run_networksetup(&["-setautoproxystate", &service, "on"]) {
            failed.push(format!("{service}: {error:#}"));
        }
    }
    Ok(failed)
}

pub(super) fn platform_apply_http(_state_path: &Path, proxy: SocketAddr) -> Result<Vec<String>> {
    let mut failed = Vec::new();
    for service in list_network_services()? {
        let host = proxy.ip().to_string();
        let port = proxy.port().to_string();
        let mut apply = |args: &[&str]| {
            if let Err(error) = run_networksetup(args) {
                failed.push(format!("{service}: {error:#}"));
            }
        };
        apply(&["-setwebproxy", &service, &host, &port]);
        apply(&["-setsecurewebproxy", &service, &host, &port]);
        apply(&["-setwebproxystate", &service, "on"]);
        apply(&["-setsecurewebproxystate", &service, "on"]);
    }
    Ok(failed)
}

pub(super) fn platform_pac_disable() {
    if let Ok(services) = list_network_services() {
        for service in services {
            let _ = run_networksetup(&["-setautoproxystate", &service, "off"]);
        }
    }
}

/// macOS has no separate readable mirror to consult: `scutil --proxy` already
/// reports the effective state.
pub(super) fn platform_legacy_pac_url() -> Option<String> {
    None
}

pub(super) fn platform_restore(state: &SavedState) -> Result<()> {
    let mut failed = Vec::new();
    match state.mode.unwrap_or(ProxyMode::Pac) {
        ProxyMode::Pac => {
            // A snapshot from an older version has no original PAC values.
            // Switch the PAC off and leave the user's static proxies alone:
            // older builds also disabled web/secure here, which could destroy
            // a proxy the user had configured before hakimi.
            if state.mac_pac.is_empty() {
                for service in &state.mac_services {
                    if let Err(error) = run_networksetup(&["-setautoproxystate", service, "off"]) {
                        failed.push(format!("{service}: {error:#}"));
                    }
                }
            } else {
                for pac in &state.mac_pac {
                    // No original URL: leave the field alone and just switch
                    // the protocol off. Writing "" would be a needless write,
                    // and `-setautoproxyurl` enables the protocol as a side
                    // effect.
                    if let Some(url) = pac.url.as_deref().filter(|url| !url.is_empty()) {
                        if let Err(error) =
                            run_networksetup(&["-setautoproxyurl", &pac.service, url])
                        {
                            failed.push(format!("{}: {error:#}", pac.service));
                        }
                    }
                    let enable = pac.enabled && pac.url.is_some();
                    if let Err(error) = run_networksetup(&[
                        "-setautoproxystate",
                        &pac.service,
                        if enable { "on" } else { "off" },
                    ]) {
                        failed.push(format!("{}: {error:#}", pac.service));
                    }
                }
            }
        }
        ProxyMode::Http => {
            if state.mac_http.is_empty() {
                for service in &state.mac_services {
                    // These must be reported like every other restore command:
                    // a swallowed failure would leave the OS proxy pointing at
                    // a port nothing listens on while claiming success.
                    if let Err(error) =
                        run_networksetup(&["-setwebproxystate", service, "off"])
                    {
                        failed.push(format!("{service}: {error:#}"));
                    }
                    if let Err(error) =
                        run_networksetup(&["-setsecurewebproxystate", service, "off"])
                    {
                        failed.push(format!("{service}: {error:#}"));
                    }
                }
            } else {
                for http in &state.mac_http {
                    restore_http_service(http, &mut failed);
                }
            }
        }
        ProxyMode::Off => {}
    }
    if failed.is_empty() {
        Ok(())
    } else {
        bail!(
            "failed to restore {} proxy setting(s): {}",
            failed.len(),
            failed.join("; ")
        )
    }
}

pub(super) fn restore_http_service(state: &MacHttpState, failed: &mut Vec<String>) {
    let mut restore = |kind: &str, enabled: bool, server: &Option<String>, port: Option<u16>| {
        if let (Some(server), Some(port)) = (server, port) {
            let args = [
                format!("-set{kind}proxy"),
                state.service.clone(),
                server.clone(),
                port.to_string(),
            ];
            let refs: Vec<&str> = args.iter().map(String::as_str).collect();
            if let Err(error) = run_networksetup(&refs) {
                failed.push(format!("{}: {error:#}", state.service));
            }
        }
        let enable = enabled && server.is_some() && port.is_some();
        let args = [
            format!("-set{kind}proxystate"),
            state.service.clone(),
            if enable { "on".into() } else { "off".into() },
        ];
        let refs: Vec<&str> = args.iter().map(String::as_str).collect();
        if let Err(error) = run_networksetup(&refs) {
            failed.push(format!("{}: {error:#}", state.service));
        }
    };
    restore("web", state.web_enabled, &state.web_server, state.web_port);
    restore(
        "secureweb",
        state.secure_enabled,
        &state.secure_server,
        state.secure_port,
    );
}

pub(super) fn platform_current(mode: Option<ProxyMode>) -> Result<CurrentProxy> {
    // `scutil --proxy` reports the effective system view in one fast call.
    // Only used right after applying, never from the periodic UI snapshot.
    if let Some(text) = scutil_proxy_text() {
        let current = match mode {
            Some(ProxyMode::Pac) => scutil_pac_current(&text),
            Some(ProxyMode::Http) => scutil_http_current(&text),
            Some(ProxyMode::Off) => None,
            None => scutil_pac_current(&text).or_else(|| scutil_http_current(&text)),
        };
        return Ok(CurrentProxy {
            supported: true,
            current,
        });
    }

    // Fallback for the rare case where scutil itself is unavailable.
    let services = list_network_services()?;
    let Some(service) = services.first() else {
        return Ok(CurrentProxy {
            supported: true,
            current: None,
        });
    };
    let current = match mode {
        Some(ProxyMode::Pac) => {
            let text = run_networksetup_with_timeout(
                &["-getautoproxyurl", service],
                NETWORKSETUP_TIMEOUT_SECS,
            )?;
            parse_networksetup_proxy(&text, ProxyMode::Pac)
        }
        Some(ProxyMode::Http) => {
            let web = run_networksetup_with_timeout(
                &["-getwebproxy", service],
                NETWORKSETUP_TIMEOUT_SECS,
            )?;
            let secure = run_networksetup_with_timeout(
                &["-getsecurewebproxy", service],
                NETWORKSETUP_TIMEOUT_SECS,
            )?;
            let web = parse_networksetup_proxy(&web, ProxyMode::Http);
            let secure = parse_networksetup_proxy(&secure, ProxyMode::Http);
            if web.is_some() && web == secure {
                web
            } else {
                None
            }
        }
        Some(ProxyMode::Off) => None,
        None => None,
    };
    Ok(CurrentProxy {
        supported: true,
        current,
    })
}
