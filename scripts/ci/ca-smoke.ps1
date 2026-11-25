# Windows 冒烟：替代原来依赖 CLI 的 scripts/ci/ca-smoke.sh。
#
# 原来 Linux CI 靠 `target/debug/hakimi` 这个 CLI 二进制做「安装 CA → 起代理 →
# curl 验 TLS → 卸载 CA」。本 fork 删掉了 hakimi-cli，改为直接跑 core 的集成
# 测试：proxy_endpoints 会自己用 127.0.0.1:0 起一个真实代理实例并校验 PAC /
# 健康端点，CA 逻辑则由 ca 模块的单元测试覆盖。
#
# 用法：
#   pwsh -File scripts/ci/ca-smoke.ps1
#
# 真实写入证书存储（LocalMachine\ROOT）需要管理员权限，CI 上会污染 runner，
# 因此不在自动化里执行：那条路径由桌面端的「安装证书」按钮覆盖，人工验收时
# 走一遍引导即可。

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
Push-Location $repoRoot
try {
    Write-Host '==> cargo test -p hakimi-core --lib ca::' -ForegroundColor Cyan
    cargo test -p hakimi-core --lib --locked ca::
    if ($LASTEXITCODE -ne 0) { throw "ca 单元测试失败（exit $LASTEXITCODE）" }

    Write-Host '==> cargo test -p hakimi-core --test proxy_endpoints' -ForegroundColor Cyan
    cargo test -p hakimi-core --test proxy_endpoints --locked
    if ($LASTEXITCODE -ne 0) { throw "proxy_endpoints 集成测试失败（exit $LASTEXITCODE）" }

    Write-Host '冒烟通过' -ForegroundColor Green
}
finally {
    Pop-Location
}
