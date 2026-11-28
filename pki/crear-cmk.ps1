<#
  Crea la CMK de Always Encrypted en el almacen de certificados del
  usuario (CurrentUser\My). La clave privada nunca sale del equipo y no
  es exportable: es el "almacen de claves del cliente" que pide Always
  Encrypted. El motor solo guarda la ruta y el proveedor.

  Uso:  powershell -NoProfile -ExecutionPolicy Bypass -File pki\crear-cmk.ps1
#>
$ErrorActionPreference = 'Stop'
$asunto = 'CN=CMK_BancoAndino'

$cert = Get-ChildItem Cert:\CurrentUser\My |
    Where-Object { $_.Subject -eq $asunto -and $_.HasPrivateKey } |
    Sort-Object NotAfter -Descending |
    Select-Object -First 1

if ($null -eq $cert) {
    $cert = New-SelfSignedCertificate `
        -Subject $asunto `
        -CertStoreLocation Cert:\CurrentUser\My `
        -Type Custom `
        -KeyAlgorithm RSA `
        -KeyLength 2048 `
        -HashAlgorithm SHA256 `
        -KeyUsage KeyEncipherment, DataEncipherment `
        -KeyUsageProperty All `
        -KeyExportPolicy NonExportable `
        -NotAfter (Get-Date).AddYears(5)
    Write-Host "CMK creada en CurrentUser\My"
} else {
    Write-Host "CMK ya existente en CurrentUser\My"
}

Write-Host ("Asunto     : " + $cert.Subject)
Write-Host ("Huella     : " + $cert.Thumbprint)
Write-Host ("Vence      : " + $cert.NotAfter.ToString('yyyy-MM-dd'))
Write-Host "Clave privada: no exportable (queda en el almacen del usuario)"
Write-Host ""
Write-Host "Ruta para la CMK: CurrentUser/My/$($cert.Thumbprint)"
