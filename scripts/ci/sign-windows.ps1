# Signs a Windows executable with signtool, then verifies the result.
#
# The certificate is accepted either as a base64-encoded PFX (what the release
# workflow passes from a repository secret) or as a path to a PFX file (what a
# developer uses locally). Nothing is cached: the decoded PFX is written to the
# runner temp directory and removed in a finally block, so a failed signing run
# cannot leave the private key behind on the build machine.
#
# Usage:
#   pwsh -File scripts/ci/sign-windows.ps1 -Path target/desktop/hakimi-ui.exe `
#     -PfxBase64 $env:SIGN_PFX_BASE64 -Password $env:SIGN_PFX_PASSWORD
#
#   pwsh -File scripts/ci/sign-windows.ps1 -Path dist\hakimi.exe `
#     -PfxPath C:\certs\hakimi.pfx -Password 'pfx-password'

[CmdletBinding(DefaultParameterSetName = 'Base64')]
param(
    [Parameter(Mandatory = $true)]
    [string] $Path,

    [Parameter(Mandatory = $true, ParameterSetName = 'Base64')]
    [string] $PfxBase64,

    [Parameter(Mandatory = $true, ParameterSetName = 'File')]
    [string] $PfxPath,

    [Parameter(Mandatory = $true)]
    [string] $Password,

    # RFC 3161 timestamp server. Timestamping keeps the signature valid after the
    # certificate itself expires, which is why it is not optional here.
    [string] $TimestampUrl = 'http://timestamp.digicert.com',

    # Some publishers (for example an internal CA) cannot be checked against the
    # system trust store; verification then only asserts that a signature exists.
    [switch] $SkipTrustCheck
)

$ErrorActionPreference = 'Stop'

function Find-SignTool {
    $roots = @(
        (Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\bin'),
        (Join-Path $env:ProgramFiles 'Windows Kits\10\bin')
    ) | Where-Object { Test-Path $_ }

    foreach ($root in $roots) {
        $candidate = Get-ChildItem -Path $root -Recurse -Filter 'signtool.exe' -ErrorAction SilentlyContinue |
            Where-Object { $_.FullName -match '\\x64\\' } |
            Sort-Object FullName -Descending |
            Select-Object -First 1
        if ($candidate) { return $candidate.FullName }
    }
    throw '找不到 signtool.exe：请安装 Windows SDK（Windows Kits\10\bin\x64）。'
}

function Resolve-Targets {
    param([string] $Spec)
    if (Test-Path -Path $Spec -PathType Container) {
        $files = Get-ChildItem -Path $Spec -Filter '*.exe' -Recurse -File
        if (-not $files) { throw "目录里没有可签名的 exe：$Spec" }
        return $files.FullName
    }
    if (-not (Test-Path -Path $Spec -PathType Leaf)) { throw "找不到待签名文件：$Spec" }
    return @((Resolve-Path -Path $Spec).Path)
}

$signTool = Find-SignTool
$targets = Resolve-Targets -Spec $Path
$tempPfx = $null

try {
    if ($PSCmdlet.ParameterSetName -eq 'Base64') {
        $tempPfx = Join-Path ([System.IO.Path]::GetTempPath()) ("hakimi-sign-{0}.pfx" -f ([guid]::NewGuid().ToString('N')))
        [System.IO.File]::WriteAllBytes($tempPfx, [System.Convert]::FromBase64String($PfxBase64))
        $pfx = $tempPfx
    }
    else {
        $pfx = (Resolve-Path -Path $PfxPath).Path
    }

    foreach ($file in $targets) {
        Write-Host "签名 $file"
        & $signTool sign /f $pfx /p $Password /fd sha256 /tr $TimestampUrl /td sha256 $file
        if ($LASTEXITCODE -ne 0) { throw "signtool 签名失败（退出码 $LASTEXITCODE）：$file" }

        $signature = Get-AuthenticodeSignature -FilePath $file
        Write-Host ("  状态 {0}  主体 {1}" -f $signature.Status, $signature.SignerCertificate.Subject)

        if ($signature.Status -eq 'Valid') { continue }
        if ($SkipTrustCheck -and $signature.SignerCertificate) { continue }
        throw "签名校验失败（$($signature.Status)）：$file"
    }
}
finally {
    if ($tempPfx -and (Test-Path $tempPfx)) {
        Remove-Item -Path $tempPfx -Force -ErrorAction SilentlyContinue
    }
}
