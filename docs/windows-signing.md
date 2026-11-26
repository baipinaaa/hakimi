# Windows 产物代码签名

发布的 zip 里只有一个 `hakimi.exe`。没有签名时，用户首次运行会被 SmartScreen 拦一次（"Windows 已保护你的电脑"），企业环境里还可能被策略直接阻止。签名后主体名会显示为证书持有者，SmartScreen 的声誉也会随下载量累积。

签名是**可选**的：仓库没有配置证书时，发布流程照常进行，只是会打一条 `::warning::` 提醒本次产物未签名。

## 一、在 GitHub 上启用

需要两个 secret（仓库 → Settings → Secrets and variables → Actions）：

| 名称 | 内容 |
| --- | --- |
| `WINDOWS_SIGN_PFX_BASE64` | PFX 文件的 base64（一行，无换行） |
| `WINDOWS_SIGN_PFX_PASSWORD` | PFX 的导出密码 |

可选的仓库变量：

| 名称 | 默认值 | 说明 |
| --- | --- | --- |
| `WINDOWS_SIGN_TIMESTAMP_URL` | `http://timestamp.digicert.com` | RFC 3161 时间戳服务；签名带时间戳才能在证书过期后继续有效 |

生成 base64：

```powershell
$bytes = [IO.File]::ReadAllBytes('C:\certs\hakimi.pfx')
[Convert]::ToBase64String($bytes) | Set-Clipboard
```

配好之后，`.github/workflows/release.yml` 的 Windows job 会在构建完成后自动调用 `scripts/ci/sign-windows.ps1`，对 `target/desktop/hakimi-ui.exe` 签名并校验，再把签名后的 exe 打进 zip。

`WINDOWS_SIGN_PFX_BASE64` 为空时该步骤整体跳过。证书只在这一步解密到 runner 的临时目录，脚本 `finally` 里删除，不会留在产物或缓存里。

## 二、本地签名

```powershell
pwsh -File scripts/ci/sign-windows.ps1 -Path target\desktop\hakimi-ui.exe `
  -PfxPath C:\certs\hakimi.pfx -Password 'pfx-password'
```

也可以直接传 base64：

```powershell
$env:SIGN_PFX_BASE64 = Get-Content -Raw C:\certs\hakimi.pfx.b64
pwsh -File scripts/ci/sign-windows.ps1 -Path dist\hakimi.exe `
  -PfxBase64 $env:SIGN_PFX_BASE64 -Password 'pfx-password'
```

脚本会用 `signtool sign /fd sha256 /tr <时间戳> /td sha256` 签名，然后用 `Get-AuthenticodeSignature` 校验；不是 `Valid` 就非零退出。内网 CA 签发的证书可以加 `-SkipTrustCheck`，此时只校验"签名存在"而不校验信任链。

## 三、没有商业证书时

自签名证书能消除"未签名"这个状态，但**不会**消除 SmartScreen 警告：SmartScreen 看的是证书的声誉，自签证书没有。它的实际用途是内部测试和固定指纹校验。

```powershell
$cert = New-SelfSignedCertificate -Type CodeSigningCert `
  -Subject 'CN=Hakimi Dev' -CertStoreLocation Cert:\CurrentUser\My `
  -KeyUsage DigitalSignature -NotAfter (Get-Date).AddYears(3)
$password = ConvertTo-SecureString -String 'change-me' -Force -AsPlainText
Export-PfxCertificate -Cert $cert -FilePath C:\certs\hakimi-self.pfx -Password $password
```

对端机器要信任它，需要把证书导入"受信任的根证书颁发机构"，否则签名状态是 `UnknownError`：

```powershell
Import-Certificate -FilePath C:\certs\hakimi-self.cer -CertStoreLocation Cert:\LocalMachine\Root
```

## 四、注意事项

- PFX 与密码都不要进仓库、不要写进 workflow 文件；只放 secrets。
- 证书过期后旧版本仍能通过校验（因为时间戳），但**新的**构建会失败，需要换证书。
- 换证书后主体名会变，SmartScreen 声誉需要重新累积。
- 仓库里没有任何地方硬编码证书路径：签名入口只认命令行参数与环境变量。
