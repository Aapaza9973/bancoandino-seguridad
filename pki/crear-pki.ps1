<#
  PKI local para la firma XMLDSig de BancoAndino.
  Genera una CA raiz y un certificado de firma emitido por esa CA,
  en lugar del certificado autofirmado efimero de la demostracion.

  Resultado en esta carpeta:
    BancoAndino-RootCA.cer   clave publica de la CA (ancla de confianza)
    firma-bancoandino.pfx    certificado de firma + clave privada

  La aplicacion valida la cadena contra la raiz con X509Chain
  (CustomRootTrust). En produccion la CA es la de la organizacion y la
  clave privada vive en un HSM o en el almacen del servidor; aqui se
  reproduce el mismo camino criptografico.

  Uso: powershell -NoProfile -ExecutionPolicy Bypass -File pki\crear-pki.ps1
#>
$ErrorActionPreference = 'Stop'
$destino = $PSScriptRoot
$claveFirma = 'Firma_BancoAndino_2026!'

$raiz = Get-ChildItem Cert:\CurrentUser\My |
    Where-Object { $_.Subject -like 'CN=BancoAndino Root CA*' -and $_.HasPrivateKey } |
    Sort-Object NotAfter -Descending |
    Select-Object -First 1

if ($null -eq $raiz) {
    $raiz = New-SelfSignedCertificate `
        -Subject 'CN=BancoAndino Root CA, O=Banco Andino S.A., C=BO' `
        -CertStoreLocation Cert:\CurrentUser\My `
        -Type Custom `
        -KeyAlgorithm RSA `
        -KeyLength 4096 `
        -HashAlgorithm SHA256 `
        -KeyUsage CertSign, CRLSign, DigitalSignature `
        -KeyUsageProperty All `
        -TextExtension @('2.5.29.19={critical}{text}ca=1&pathlength=1') `
        -NotAfter (Get-Date).AddYears(10)
    Write-Host "CA raiz creada."
} else {
    Write-Host "CA raiz ya existente."
}

Export-Certificate -Cert $raiz -FilePath (Join-Path $destino 'BancoAndino-RootCA.cer') -Force | Out-Null

$firma = Get-ChildItem Cert:\CurrentUser\My |
    Where-Object { $_.Subject -like 'CN=Firma Transacciones BancoAndino*' -and $_.HasPrivateKey } |
    Sort-Object NotAfter -Descending |
    Select-Object -First 1

if ($null -eq $firma) {
    $firma = New-SelfSignedCertificate `
        -Subject 'CN=Firma Transacciones BancoAndino, O=Banco Andino S.A., C=BO' `
        -Signer $raiz `
        -CertStoreLocation Cert:\CurrentUser\My `
        -Type Custom `
        -KeyAlgorithm RSA `
        -KeyLength 2048 `
        -HashAlgorithm SHA256 `
        -KeyUsage DigitalSignature `
        -KeyUsageProperty Sign `
        -TextExtension @('2.5.29.37={text}1.3.6.1.4.1.311.10.3.12') `
        -NotAfter (Get-Date).AddYears(3)
    Write-Host "Certificado de firma emitido por la CA."
} else {
    Write-Host "Certificado de firma ya existente."
}

Export-PfxCertificate -Cert $firma `
    -FilePath (Join-Path $destino 'firma-bancoandino.pfx') `
    -Password (ConvertTo-SecureString $claveFirma -AsPlainText -Force) -Force | Out-Null

# La cadena se valida en la aplicacion con X509Chain y CustomRootTrust
# (TrustMode no existe en .NET Framework 4.8, que es lo que usa PowerShell 5.1).
Write-Host ""
Write-Host ("Emisor            : " + $firma.Issuer)
Write-Host ("Firma (huella)    : " + $firma.Thumbprint)
Write-Host ("Vence             : " + $firma.NotAfter.ToString('yyyy-MM-dd'))
Write-Host ("CA raiz (huella)  : " + $raiz.Thumbprint)
Write-Host ("Contrasena del PFX: " + $claveFirma)
Write-Host ""
Write-Host "La cadena se comprueba en /api/firma/xmldsig (campo cadena_valida)."
