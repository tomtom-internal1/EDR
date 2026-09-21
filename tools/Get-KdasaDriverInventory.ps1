[CmdletBinding()]
param(
    [string]$OutputPath = ".\out\driver-inventory.json"
)

$ErrorActionPreference = "Stop"

$outDir = Split-Path -Parent (Resolve-Path -LiteralPath $OutputPath -ErrorAction SilentlyContinue)
if (-not $outDir) {
    $outDir = Split-Path -Parent $OutputPath
}
if ($outDir -and -not (Test-Path $outDir)) {
    New-Item -ItemType Directory -Path $outDir -Force | Out-Null
}

$drivers = Get-CimInstance Win32_SystemDriver |
    Where-Object { $_.State -eq "Running" -and $_.Started } |
    ForEach-Object {
        $rawPath = $_.PathName
        $resolvedPath = $rawPath

        if ($rawPath -match '^s*"([^"]+)"') {
            $resolvedPath = $Matches[1]
        }
        elseif ($rawPath -match '^s*([^s]+)') {
            $resolvedPath = $Matches[1]
        }

        $fileVersion = $null
        $productVersion = $null
        $company = $null
        $signatureStatus = $null
        $signer = $null

        if (Test-Path -LiteralPath $resolvedPath) {
            try {
                $item = Get-Item -LiteralPath $resolvedPath
                $fileVersion = $item.VersionInfo.FileVersion
                $productVersion = $item.VersionInfo.ProductVersion
                $company = $item.VersionInfo.CompanyName
            } catch {}

            try {
                $sig = Get-AuthenticodeSignature -LiteralPath $resolvedPath
                $signatureStatus = [string]$sig.Status
                $signer = $sig.SignerCertificate.Subject
            } catch {}
        }

        [pscustomobject]@{
            Name            = $_.Name
            DisplayName     = $_.DisplayName
            State           = $_.State
            StartMode       = $_.StartMode
            PathName        = $rawPath
            ResolvedPath    = $resolvedPath
            FileVersion     = $fileVersion
            ProductVersion  = $productVersion
            Company         = $company
            SignatureStatus = $signatureStatus
            Signer          = $signer
        }
    }

$drivers | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $OutputPath -Encoding UTF8
Write-Host "Wrote $($drivers.Count) running drivers to $OutputPath"
