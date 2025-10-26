# CyberArk Privilege Cloud User Deletion Script

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

1. Set up OAuth2 credentials in CyberArk:
   - Log in to your CyberArk Privilege Cloud tenant
   - Navigate to Administration > Access Control > Applications
   - Create a new application or use an existing one
   - Note the Client ID and Client Secret
   - Ensure the application has permissions to delete users

2. Ensure PowerShell execution policy allows script execution:

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

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

### Basic Usage

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
.\Delete-CyberArkUsers.ps1 -CsvPath "users.csv" `
  -TenantUrl "https://your-tenant.cyberark.cloud" `
  -MinDays 90
```

### Dry Run Mode

Test the script without actually deleting users:

```powershell
.\Delete-CyberArkUsers.ps1 -CsvPath "users.csv" `
  -TenantUrl "https://your-tenant.cyberark.cloud" `
  -DryRun
```

### Get Help

View detailed help and parameter information:

```powershell
Get-Help .\Delete-CyberArkUsers.ps1 -Full
```

## Parameters

- **CsvPath** (required): Path to CSV file containing users to delete
- **TenantUrl** (required): CyberArk tenant URL (e.g., https://tenant.cyberark.cloud)
- **ClientId** (optional): OAuth2 client ID (or use CYBERARK_CLIENT_ID env var)
- **ClientSecret** (optional): OAuth2 client secret (or use CYBERARK_CLIENT_SECRET env var)
- **MinDays** (optional): Only delete users with days_since_last_login >= this value
- **DryRun** (switch): Simulate deletion without making actual changes

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
