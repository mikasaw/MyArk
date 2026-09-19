$ErrorActionPreference = 'Stop'
# Exports the WDK test-signing certificate from a freshly signed MyArkCore.sys
# into build\wdk_test.cer (the guest setup then installs it into Root +
# TrustedPublisher). Paths are derived from this script's location (build\).
$repo = Split-Path -Parent $PSScriptRoot
$sys = Join-Path $repo 'driver\x64\Release\MyArkCore.sys'
$sig = Get-AuthenticodeSignature -FilePath $sys
"Status: $($sig.Status)"
"Subject: $($sig.SignerCertificate.Subject)"
Export-Certificate -Cert $sig.SignerCertificate -FilePath (Join-Path $PSScriptRoot 'wdk_test.cer') | Out-Null
"Exported build\wdk_test.cer"
