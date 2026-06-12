<#
.SYNOPSIS
    Reports MFA registration gaps across the tenant — who isn't registered,
    who isn't MFA-capable, and (worst case) which admins fall into either
    bucket.

.DESCRIPTION
    Pulls the authentication methods registration report from Microsoft Graph
    and turns it into a prioritized gap list. Admin accounts without MFA are
    surfaced first because they're the accounts attackers want and the ones a
    single phished password fully compromises.

    Also breaks down registered methods so weak-method reliance (SMS-only) is
    visible alongside outright gaps.

    Read-only.

.PARAMETER OutputPath
    Folder for the CSV export. Defaults to .\output.

.EXAMPLE
    .\Get-MfaRegistrationReport.ps1

.NOTES
    Author : Salim Rashid
    Requires: Microsoft.Graph.Reports
    Scopes  : AuditLog.Read.All
    License : Authentication methods reporting requires Entra ID P1 or higher.
#>
#Requires -Modules Microsoft.Graph.Reports

[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputPath = ".\output"
)

Connect-MgGraph -Scopes 'AuditLog.Read.All' -NoWelcome

Write-Host 'Retrieving authentication method registration details...' -ForegroundColor Cyan
$details = Get-MgReportAuthenticationMethodUserRegistrationDetail -All

$report = foreach ($entry in $details) {
    $methods = @($entry.MethodsRegistered)
    $smsOnly = ($methods.Count -gt 0) -and -not ($methods | Where-Object { $_ -notmatch 'mobilePhone|sms|voice' })

    $risk =
        if ($entry.IsAdmin -and -not $entry.IsMfaRegistered) { '1-Critical: Admin without MFA' }
        elseif (-not $entry.IsMfaRegistered)                 { '2-High: No MFA registered' }
        elseif (-not $entry.IsMfaCapable)                    { '3-Medium: Registered but not MFA-capable' }
        elseif ($smsOnly)                                    { '4-Low: Phone-based methods only' }
        else                                                 { '5-OK' }

    [PSCustomObject]@{
        UserPrincipalName = $entry.UserPrincipalName
        DisplayName       = $entry.UserDisplayName
        IsAdmin           = $entry.IsAdmin
        IsMfaRegistered   = $entry.IsMfaRegistered
        IsMfaCapable      = $entry.IsMfaCapable
        IsSsprRegistered  = $entry.IsSsprRegistered
        MethodsRegistered = $methods -join '; '
        Risk              = $risk
    }
}

$gaps = $report | Where-Object { $_.Risk -ne '5-OK' } | Sort-Object -Property Risk, UserPrincipalName

# Console summary
$total = ($report | Measure-Object).Count
Write-Host ''
Write-Host ("Users in registration report : {0}" -f $total)
$report | Group-Object -Property Risk | Sort-Object -Property Name | ForEach-Object {
    $color = if ($_.Name -like '1-*') { 'Red' } elseif ($_.Name -like '5-*') { 'Green' } else { 'Yellow' }
    Write-Host ("  {0,-42} {1}" -f $_.Name, $_.Count) -ForegroundColor $color
}

if (-not (Test-Path -Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}
$csvFile = Join-Path -Path $OutputPath -ChildPath ("MfaGaps-{0:yyyy-MM-dd}.csv" -f (Get-Date))
$gaps | Export-Csv -Path $csvFile -NoTypeInformation -Encoding UTF8
Write-Host "Gap report exported to $csvFile" -ForegroundColor Green
