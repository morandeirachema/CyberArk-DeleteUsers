# CyberArk Privilege Cloud User Deletion Script

**English** | [Español](README.es.md)

A PowerShell script to delete users from CyberArk Privilege Cloud based on a CSV file containing user information including origin, username, and days since last login.

## Features

- Bulk user deletion from CSV file
- OAuth2 authentication with CyberArk Privilege Cloud
- Filter users by minimum days since last login
- Dry-run mode for testing without actual deletion
- Comprehensive logging to file and console
- Color-coded console output
- Error handling and detailed statistics

## Prerequisites

- PowerShell 5.1 or higher (Windows PowerShell or PowerShell Core)
- CyberArk Privilege Cloud tenant
- OAuth2 credentials (Client ID and Client Secret)
- Appropriate permissions to delete users in CyberArk

## Setup

### 1. Enable PowerShell Script Execution

Ensure PowerShell execution policy allows script execution:

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

### 2. Set Up OAuth2 Credentials in CyberArk

1. Log in to your CyberArk Privilege Cloud tenant
2. Navigate to Administration > Access Control > Applications
3. Create a new application or use an existing one
4. Note the Client ID and Client Secret
5. Ensure the application has permissions to delete users

### 3. Configure Encrypted Credentials (Recommended for Automation)

For secure automated execution, use the credential setup script to encrypt and store your credentials:

**Using DPAPI (Windows, user-specific):**
```powershell
.\Setup-CyberArkCredentials.ps1 -TenantUrl "https://your-tenant.cyberark.cloud"
```

**Using AES (Cross-platform, portable):**
```powershell
.\Setup-CyberArkCredentials.ps1 -TenantUrl "https://your-tenant.cyberark.cloud" -UseAES
```

The script will:
- Prompt you for Client ID and Client Secret
- Test authentication with CyberArk
- Encrypt and save credentials to `.\credentials\cyberark.cred`
- Generate encryption key (if using AES) to `.\credentials\aes.key`

**Important Notes:**
- **DPAPI**: Credentials only work for the same user on the same machine (ideal for scheduled tasks running as specific user)
- **AES**: Credentials work across users/machines but require the key file (ideal for shared automation or containers)

## CSV File Format

The CSV file must contain the following columns:

- `origin`: Source of the user (e.g., LDAP, Local, SAML)
- `username`: Username to delete
- `days_since_last_login`: Number of days since last login

### Example CSV (`users_template.csv`):

```csv
origin,username,days_since_last_login
LDAP,john.doe,120
Local,jane.smith,90
LDAP,admin.user,45
```

## Usage

### Using Stored Credentials (Recommended)

After running the setup script, you can use the deletion script without specifying credentials:

```powershell
.\Delete-CyberArkUsers.ps1 -CsvPath "users.csv"
```

### Manual Credentials

If you haven't set up encrypted credentials, you can provide them manually:

```powershell
.\Delete-CyberArkUsers.ps1 -CsvPath "users.csv" `
  -TenantUrl "https://your-tenant.cyberark.cloud" `
  -ClientId "YOUR_CLIENT_ID" `
  -ClientSecret "YOUR_CLIENT_SECRET"
```

### Using Environment Variables

Set credentials as environment variables to avoid passing them on command line:

**Windows PowerShell:**
```powershell
$env:CYBERARK_CLIENT_ID = "your_client_id"
$env:CYBERARK_CLIENT_SECRET = "your_client_secret"

.\Delete-CyberArkUsers.ps1 -CsvPath "users.csv" `
  -TenantUrl "https://your-tenant.cyberark.cloud"
```

**Linux/macOS PowerShell:**
```powershell
$env:CYBERARK_CLIENT_ID = "your_client_id"
$env:CYBERARK_CLIENT_SECRET = "your_client_secret"

./Delete-CyberArkUsers.ps1 -CsvPath "users.csv" `
  -TenantUrl "https://your-tenant.cyberark.cloud"
```

### Filter by Minimum Days

Only delete users who haven't logged in for at least 90 days:

```powershell
.\Delete-CyberArkUsers.ps1 -CsvPath "users.csv" -MinDays 90
```

### Dry Run Mode

Test the script without actually deleting users (using stored credentials):

```powershell
.\Delete-CyberArkUsers.ps1 -CsvPath "users.csv" -DryRun
```

### Custom Credential Path

Use credentials from a different location:

```powershell
.\Delete-CyberArkUsers.ps1 -CsvPath "users.csv" -CredentialPath "C:\secure\credentials"
```

### Get Help

View detailed help and parameter information:

```powershell
Get-Help .\Delete-CyberArkUsers.ps1 -Full
```

## Parameters

- **CsvPath** (required): Path to CSV file containing users to delete
- **TenantUrl** (optional): CyberArk tenant URL (e.g., https://tenant.cyberark.cloud) - Required if not using stored credentials
- **ClientId** (optional): OAuth2 client ID (or use CYBERARK_CLIENT_ID env var or stored credentials)
- **ClientSecret** (optional): OAuth2 client secret (or use CYBERARK_CLIENT_SECRET env var or stored credentials)
- **CredentialPath** (optional): Path to directory containing encrypted credentials (default: .\credentials)
- **MinDays** (optional): Only delete users with days_since_last_login >= this value
- **DryRun** (switch): Simulate deletion without making actual changes

## Automation and Scheduled Tasks

### Windows Task Scheduler

To run the script automatically on a schedule:

1. **Set up credentials as the task user:**
   ```powershell
   # Run as the user that will execute the scheduled task
   .\Setup-CyberArkCredentials.ps1 -TenantUrl "https://your-tenant.cyberark.cloud"
   ```

2. **Create a scheduled task:**
   ```powershell
   $action = New-ScheduledTaskAction -Execute "PowerShell.exe" `
     -Argument "-ExecutionPolicy Bypass -File C:\path\to\Delete-CyberArkUsers.ps1 -CsvPath C:\path\to\users.csv -MinDays 90"

   $trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Monday -At 2am

   Register-ScheduledTask -TaskName "CyberArk-DeleteInactiveUsers" `
     -Action $action -Trigger $trigger -User "DOMAIN\ServiceAccount"
   ```

### Linux/macOS Cron Job

For cross-platform automation using AES encryption:

1. **Set up credentials with AES:**
   ```bash
   pwsh -Command ".\Setup-CyberArkCredentials.ps1 -TenantUrl 'https://your-tenant.cyberark.cloud' -UseAES"
   ```

2. **Create a cron job:**
   ```bash
   # Edit crontab
   crontab -e

   # Add entry (runs every Monday at 2 AM)
   0 2 * * 1 cd /path/to/scripts && pwsh -File Delete-CyberArkUsers.ps1 -CsvPath users.csv -MinDays 90
   ```

### Docker/Container Environments

When using containers, use AES encryption and mount credentials as secrets:

```dockerfile
# Store credentials securely
COPY credentials/cyberark.cred /app/credentials/
COPY credentials/aes.key /app/credentials/

# Run script
CMD ["pwsh", "-File", "Delete-CyberArkUsers.ps1", "-CsvPath", "users.csv"]
```

## Logging

The script creates a log file named `cyberark_delete_YYYYMMDD_HHMMSS.log` with detailed information about:

- Authentication status
- Each user processed
- Success/failure of deletions
- Final statistics

Logs are also displayed in the console in real-time.

## Output

At the end of execution, the script displays a summary:

```
========================================
DELETION SUMMARY
========================================
Successfully deleted: 10
Failed to delete:     2
Skipped:              5
========================================
Log file: cyberark_delete_20251026_143022.log
```

## Error Handling

The script handles various error scenarios:

- Invalid CSV format or missing columns
- Authentication failures
- User not found in CyberArk
- API errors during deletion
- Network connectivity issues

All errors are logged with detailed messages.

## Security Recommendations

1. Store credentials securely using environment variables or a secrets manager
2. Never commit credentials to version control
3. Use service accounts with minimal required permissions
4. Test with `-DryRun` before actual deletion
5. Back up user data before running bulk deletions
6. Review the CSV file carefully before execution
7. Consider using PowerShell SecureString for credentials in production environments

## API Reference

The script uses the following CyberArk REST API endpoints:

- `POST /oauth2/platformtoken` - OAuth2 authentication
- `GET /api/Users?search={username}` - User search
- `DELETE /api/Users/{id}` - User deletion

## Troubleshooting

### Authentication Failed

- Verify your tenant URL is correct
- Check that Client ID and Client Secret are valid
- Ensure the OAuth2 application has necessary permissions

### User Not Found

- Verify the username in the CSV matches exactly (case-insensitive)
- Check that the user exists in CyberArk
- Ensure you have permission to view the user

### Deletion Failed

- Verify you have permission to delete users
- Check if the user has dependencies (safes, accounts, etc.)
- Review the log file for detailed error messages

## License

This script is provided as-is for use with CyberArk Privilege Cloud.

## Support

For issues or questions:
1. Check the log files for detailed error messages
2. Review CyberArk Privilege Cloud API documentation
3. Contact your CyberArk administrator
