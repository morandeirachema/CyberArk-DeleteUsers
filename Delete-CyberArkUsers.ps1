<#
.SYNOPSIS
    Deletes users from CyberArk Privilege Cloud based on a CSV file.

.DESCRIPTION
    This script reads a CSV file containing user information (origin, username, days_since_last_login)
    and deletes users from CyberArk Privilege Cloud using the REST API.

.PARAMETER CsvPath
    Path to the CSV file containing users to delete.

.PARAMETER TenantUrl
    CyberArk Privilege Cloud tenant URL (e.g., https://your-tenant.cyberark.cloud).

.PARAMETER ClientId
    OAuth2 client ID for authentication. Can also be set via CYBERARK_CLIENT_ID environment variable.

.PARAMETER ClientSecret
    OAuth2 client secret for authentication. Can also be set via CYBERARK_CLIENT_SECRET environment variable.

.PARAMETER MinDays
    Optional. Only delete users with days_since_last_login greater than or equal to this value.

.PARAMETER DryRun
    If specified, simulates deletion without making actual changes.

.EXAMPLE
    .\Delete-CyberArkUsers.ps1 -CsvPath "users.csv" -TenantUrl "https://tenant.cyberark.cloud" -ClientId "abc123" -ClientSecret "secret"

.EXAMPLE
    .\Delete-CyberArkUsers.ps1 -CsvPath "users.csv" -TenantUrl "https://tenant.cyberark.cloud" -MinDays 90 -DryRun

.NOTES
    Author: CyberArk Admin
    Requires: PowerShell 5.1 or higher
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$CsvPath,

    [Parameter(Mandatory = $true)]
    [string]$TenantUrl,

    [Parameter(Mandatory = $false)]
    [string]$ClientId,

    [Parameter(Mandatory = $false)]
    [string]$ClientSecret,

    [Parameter(Mandatory = $false)]
    [int]$MinDays,

    [Parameter(Mandatory = $false)]
    [switch]$DryRun
)

# Set strict mode and error action preference
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# Initialize logging
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$logFile = "cyberark_delete_$timestamp.log"

function Write-Log {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,

        [Parameter(Mandatory = $false)]
        [ValidateSet("INFO", "WARNING", "ERROR")]
        [string]$Level = "INFO"
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "$timestamp - $Level - $Message"

    # Write to console with color
    switch ($Level) {
        "INFO"    { Write-Host $logMessage -ForegroundColor Green }
        "WARNING" { Write-Host $logMessage -ForegroundColor Yellow }
        "ERROR"   { Write-Host $logMessage -ForegroundColor Red }
    }

    # Write to log file
    Add-Content -Path $logFile -Value $logMessage
}

function Get-CyberArkAccessToken {
    param(
        [Parameter(Mandatory = $true)]
        [string]$TenantUrl,

        [Parameter(Mandatory = $true)]
        [string]$ClientId,

        [Parameter(Mandatory = $true)]
        [string]$ClientSecret
    )

    try {
        Write-Log "Authenticating with CyberArk..."

        $authUrl = "$TenantUrl/oauth2/platformtoken"
        $body = @{
            grant_type    = "client_credentials"
            client_id     = $ClientId
            client_secret = $ClientSecret
        } | ConvertTo-Json

        $headers = @{
            "Content-Type" = "application/json"
        }

        $response = Invoke-RestMethod -Uri $authUrl -Method Post -Body $body -Headers $headers

        Write-Log "Authentication successful"
        return $response.access_token
    }
    catch {
        Write-Log "Authentication failed: $($_.Exception.Message)" -Level ERROR
        throw
    }
}

function Get-CyberArkUserId {
    param(
        [Parameter(Mandatory = $true)]
        [string]$TenantUrl,

        [Parameter(Mandatory = $true)]
        [string]$AccessToken,

        [Parameter(Mandatory = $true)]
        [string]$Username
    )

    try {
        $searchUrl = "$TenantUrl/api/Users?search=$Username"
        $headers = @{
            "Authorization" = "Bearer $AccessToken"
            "Content-Type"  = "application/json"
        }

        $response = Invoke-RestMethod -Uri $searchUrl -Method Get -Headers $headers

        # Find exact match (case-insensitive)
        $user = $response.Users | Where-Object { $_.username -eq $Username }

        if ($user) {
            return $user.id
        }
        else {
            Write-Log "User '$Username' not found" -Level WARNING
            return $null
        }
    }
    catch {
        Write-Log "Error searching for user '$Username': $($_.Exception.Message)" -Level ERROR
        return $null
    }
}

function Remove-CyberArkUser {
    param(
        [Parameter(Mandatory = $true)]
        [string]$TenantUrl,

        [Parameter(Mandatory = $true)]
        [string]$AccessToken,

        [Parameter(Mandatory = $true)]
        [int]$UserId,

        [Parameter(Mandatory = $true)]
        [string]$Username
    )

    try {
        $deleteUrl = "$TenantUrl/api/Users/$UserId"
        $headers = @{
            "Authorization" = "Bearer $AccessToken"
            "Content-Type"  = "application/json"
        }

        Invoke-RestMethod -Uri $deleteUrl -Method Delete -Headers $headers | Out-Null

        Write-Log "Successfully deleted user: $Username (ID: $UserId)"
        return $true
    }
    catch {
        Write-Log "Error deleting user '$Username' (ID: $UserId): $($_.Exception.Message)" -Level ERROR
        return $false
    }
}

function Import-UsersFromCsv {
    param(
        [Parameter(Mandatory = $true)]
        [string]$CsvPath
    )

    try {
        if (-not (Test-Path $CsvPath)) {
            throw "CSV file not found: $CsvPath"
        }

        $users = Import-Csv -Path $CsvPath

        # Validate required columns
        $requiredColumns = @('origin', 'username', 'days_since_last_login')
        $csvColumns = $users[0].PSObject.Properties.Name

        foreach ($column in $requiredColumns) {
            if ($column -notin $csvColumns) {
                throw "CSV must contain column: $column"
            }
        }

        Write-Log "Loaded $($users.Count) users from CSV"
        return $users
    }
    catch {
        Write-Log "Error reading CSV file: $($_.Exception.Message)" -Level ERROR
        throw
    }
}

# Main script execution
try {
    Write-Log "========================================"
    Write-Log "CyberArk User Deletion Script Started"
    Write-Log "========================================"

    # Get credentials from parameters or environment variables
    if (-not $ClientId) {
        $ClientId = $env:CYBERARK_CLIENT_ID
    }

    if (-not $ClientSecret) {
        $ClientSecret = $env:CYBERARK_CLIENT_SECRET
    }

    if (-not $ClientId -or -not $ClientSecret) {
        throw "Client ID and Client Secret are required. Provide via parameters or environment variables."
    }

    # Remove trailing slash from tenant URL
    $TenantUrl = $TenantUrl.TrimEnd('/')

    if ($DryRun) {
        Write-Log "DRY RUN MODE - No users will be deleted" -Level WARNING
    }

    # Load users from CSV
    $users = Import-UsersFromCsv -CsvPath $CsvPath

    # Authenticate
    $accessToken = Get-CyberArkAccessToken -TenantUrl $TenantUrl -ClientId $ClientId -ClientSecret $ClientSecret

    # Initialize statistics
    $stats = @{
        Success = 0
        Failed  = 0
        Skipped = 0
    }

    # Process each user
    foreach ($user in $users) {
        $username = $user.username.Trim()
        $origin = $user.origin.Trim()
        $days = $user.days_since_last_login.Trim()

        Write-Log "Processing user: $username (Origin: $origin, Days: $days)"

        # Apply minimum days filter if specified
        if ($PSBoundParameters.ContainsKey('MinDays')) {
            try {
                $daysInt = [int]$days
                if ($daysInt -lt $MinDays) {
                    Write-Log "Skipping $username : $days days < $MinDays minimum" -Level WARNING
                    $stats.Skipped++
                    continue
                }
            }
            catch {
                Write-Log "Invalid days value for $username : $days" -Level WARNING
                $stats.Failed++
                continue
            }
        }

        if ($DryRun) {
            Write-Log "[DRY RUN] Would delete user: $username" -Level WARNING
            $stats.Success++
            continue
        }

        # Get user ID
        $userId = Get-CyberArkUserId -TenantUrl $TenantUrl -AccessToken $accessToken -Username $username

        if ($null -eq $userId) {
            $stats.Failed++
            continue
        }

        # Delete user
        $deleted = Remove-CyberArkUser -TenantUrl $TenantUrl -AccessToken $accessToken -UserId $userId -Username $username

        if ($deleted) {
            $stats.Success++
        }
        else {
            $stats.Failed++
        }
    }

    # Print summary
    Write-Log "========================================"
    Write-Log "DELETION SUMMARY"
    Write-Log "========================================"
    Write-Log "Successfully deleted: $($stats.Success)"
    Write-Log "Failed to delete:     $($stats.Failed)"
    Write-Log "Skipped:              $($stats.Skipped)"
    Write-Log "========================================"
    Write-Log "Log file: $logFile"

}
catch {
    Write-Log "Script execution failed: $($_.Exception.Message)" -Level ERROR
    exit 1
}
