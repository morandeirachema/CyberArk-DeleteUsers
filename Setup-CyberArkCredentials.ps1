<#
.SYNOPSIS
    Sets up and encrypts CyberArk credentials for automated use.

.DESCRIPTION
    This script prompts for CyberArk credentials and stores them securely using Windows DPAPI
    (Data Protection API) or AES encryption. The encrypted credentials can only be decrypted
    by the same user on the same machine (DPAPI) or with the encryption key (AES).

.PARAMETER TenantUrl
    CyberArk Privilege Cloud tenant URL (e.g., https://your-tenant.cyberark.cloud).

.PARAMETER CredentialPath
    Path where encrypted credentials will be stored. Default: .\credentials

.PARAMETER UseAES
    Use AES encryption instead of DPAPI. Required for cross-platform or scheduled tasks under different users.

.EXAMPLE
    .\Setup-CyberArkCredentials.ps1 -TenantUrl "https://tenant.cyberark.cloud"

.EXAMPLE
    .\Setup-CyberArkCredentials.ps1 -TenantUrl "https://tenant.cyberark.cloud" -UseAES

.NOTES
    Author: CyberArk Admin
    Requires: PowerShell 5.1 or higher
    Security: DPAPI credentials only work for the same user on the same machine.
              AES credentials work across users/machines but require the key file.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$TenantUrl,

    [Parameter(Mandatory = $false)]
    [string]$CredentialPath = ".\credentials",

    [Parameter(Mandatory = $false)]
    [switch]$UseAES
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function New-AESKey {
    <#
    .SYNOPSIS
        Generates a new AES encryption key.
    #>
    $key = New-Object Byte[] 32
    [Security.Cryptography.RNGCryptoServiceProvider]::Create().GetBytes($key)
    return $key
}

function Export-SecureCredential {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ClientId,

        [Parameter(Mandatory = $true)]
        [SecureString]$ClientSecret,

        [Parameter(Mandatory = $true)]
        [string]$TenantUrl,

        [Parameter(Mandatory = $true)]
        [string]$OutputPath,

        [Parameter(Mandatory = $false)]
        [byte[]]$AESKey
    )

    # Create credentials directory if it doesn't exist
    $credDir = Split-Path -Path $OutputPath -Parent
    if (-not (Test-Path $credDir)) {
        New-Item -ItemType Directory -Path $credDir -Force | Out-Null
        Write-Host "Created credentials directory: $credDir" -ForegroundColor Green
    }

    # Create credential object
    $credential = @{
        TenantUrl    = $TenantUrl
        ClientId     = $ClientId
        ClientSecret = if ($AESKey) {
            # AES encryption
            ConvertFrom-SecureString -SecureString $ClientSecret -Key $AESKey
        } else {
            # DPAPI encryption (Windows only, user-specific)
            ConvertFrom-SecureString -SecureString $ClientSecret
        }
        EncryptionType = if ($AESKey) { "AES" } else { "DPAPI" }
        CreatedDate    = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        CreatedBy      = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    }

    # Save to file
    $credential | ConvertTo-Json | Set-Content -Path $OutputPath -Force

    # Set restrictive permissions on the file (Windows)
    if ($IsWindows -or $null -eq $IsWindows) {
        try {
            $acl = Get-Acl $OutputPath
            $acl.SetAccessRuleProtection($true, $false)
            $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                [System.Security.Principal.WindowsIdentity]::GetCurrent().Name,
                "FullControl",
                "Allow"
            )
            $acl.SetAccessRule($rule)
            Set-Acl -Path $OutputPath -AclObject $acl
            Write-Host "Set restrictive permissions on credential file" -ForegroundColor Green
        }
        catch {
            Write-Warning "Could not set file permissions: $($_.Exception.Message)"
        }
    }
    else {
        # Linux/macOS - use chmod
        try {
            chmod 600 $OutputPath
            Write-Host "Set restrictive permissions (600) on credential file" -ForegroundColor Green
        }
        catch {
            Write-Warning "Could not set file permissions: $($_.Exception.Message)"
        }
    }
}

# Main execution
try {
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "CyberArk Credential Setup" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""

    # Validate tenant URL
    $TenantUrl = $TenantUrl.TrimEnd('/')
    Write-Host "Tenant URL: $TenantUrl" -ForegroundColor Yellow
    Write-Host ""

    # Prompt for Client ID
    Write-Host "Enter your CyberArk OAuth2 credentials:" -ForegroundColor Cyan
    $clientId = Read-Host "Client ID"

    if ([string]::IsNullOrWhiteSpace($clientId)) {
        throw "Client ID cannot be empty"
    }

    # Prompt for Client Secret (secure)
    $clientSecretSecure = Read-Host "Client Secret" -AsSecureString

    # Verify Client Secret is not empty
    $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($clientSecretSecure)
    $plainSecret = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
    [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)

    if ([string]::IsNullOrWhiteSpace($plainSecret)) {
        throw "Client Secret cannot be empty"
    }

    Write-Host ""

    # Determine encryption method
    $aesKey = $null
    $keyFilePath = $null

    if ($UseAES) {
        Write-Host "Using AES encryption..." -ForegroundColor Yellow
        $aesKey = New-AESKey
        $keyFilePath = Join-Path $CredentialPath "aes.key"

        # Save AES key
        $aesKey | Set-Content -Path $keyFilePath -Encoding Byte -Force

        Write-Host "AES key saved to: $keyFilePath" -ForegroundColor Green
        Write-Host "WARNING: Keep this key file secure! Anyone with this file can decrypt your credentials." -ForegroundColor Red
        Write-Host ""
    }
    else {
        Write-Host "Using DPAPI encryption (user/machine specific)..." -ForegroundColor Yellow
        Write-Host "Note: These credentials will only work for user '$([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)' on this machine." -ForegroundColor Yellow
        Write-Host ""
    }

    # Test authentication before saving
    Write-Host "Testing authentication with CyberArk..." -ForegroundColor Cyan

    $authUrl = "$TenantUrl/oauth2/platformtoken"
    $body = @{
        grant_type    = "client_credentials"
        client_id     = $clientId
        client_secret = $plainSecret
    } | ConvertTo-Json

    $headers = @{
        "Content-Type" = "application/json"
    }

    try {
        $response = Invoke-RestMethod -Uri $authUrl -Method Post -Body $body -Headers $headers -ErrorAction Stop
        Write-Host "✓ Authentication successful!" -ForegroundColor Green
    }
    catch {
        Write-Host "✗ Authentication failed: $($_.Exception.Message)" -ForegroundColor Red
        throw "Please verify your credentials and tenant URL"
    }

    Write-Host ""

    # Save credentials
    $credFilePath = Join-Path $CredentialPath "cyberark.cred"
    Export-SecureCredential -ClientId $clientId `
                           -ClientSecret $clientSecretSecure `
                           -TenantUrl $TenantUrl `
                           -OutputPath $credFilePath `
                           -AESKey $aesKey

    Write-Host ""
    Write-Host "========================================" -ForegroundColor Green
    Write-Host "Credentials saved successfully!" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "Credential file: $credFilePath" -ForegroundColor Yellow

    if ($UseAES) {
        Write-Host "Key file:        $keyFilePath" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "IMPORTANT SECURITY NOTES:" -ForegroundColor Red
        Write-Host "1. Keep the key file secure and separate from the credential file" -ForegroundColor Yellow
        Write-Host "2. Both files are required for automated scripts" -ForegroundColor Yellow
        Write-Host "3. Never commit these files to version control" -ForegroundColor Yellow
    }
    else {
        Write-Host ""
        Write-Host "IMPORTANT SECURITY NOTES:" -ForegroundColor Red
        Write-Host "1. Credentials are encrypted using DPAPI" -ForegroundColor Yellow
        Write-Host "2. They can only be decrypted by user: $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)" -ForegroundColor Yellow
        Write-Host "3. On this machine only" -ForegroundColor Yellow
        Write-Host "4. For scheduled tasks, use -UseAES or run setup as the task user" -ForegroundColor Yellow
    }

    Write-Host ""
    Write-Host "You can now run Delete-CyberArkUsers.ps1 without specifying credentials" -ForegroundColor Green
    Write-Host ""

}
catch {
    Write-Host ""
    Write-Host "Setup failed: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
