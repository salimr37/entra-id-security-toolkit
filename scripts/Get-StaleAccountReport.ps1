<#
.SYNOPSIS
    Reports stale Entra ID accounts: enabled users (members and guests) with
    no sign-in activity in N days, or that have never signed in at all.

.DESCRIPTION
    Stale-but-enabled accounts are standing attack surface — credentials that
    still work, attached to nobody who would notice them being used. This
    report separates members from guests (guests rot fastest), flags
    never-signed-in accounts past a grace window, and includes creation dates
    so genuinely abandoned accounts are easy to distinguish from new ones.

    Read-only.

.PARAMETER StaleDays
    Days without any sign-in (interactive or non-interactive) before an
    enabled account is considered stale. Default: 90.

.PARAMETER NeverSignedInGraceDays
    Accounts younger than this are never flagged as "never signed in".
    Default: 30.

.PARAMETER OutputPath
    Folder for the CSV export. Defaults to .\output.

.EXAMPLE
    .\Get-StaleAccountReport.ps1 -StaleDays 90

.NOTES
    Author : Salim Rashid
    Requires: Microsoft.Graph.Users
    Scopes  : User.Read.All, AuditLog.Read.All
    License : signInActivity requires Microsoft Entra ID P1 or higher.
#>
#Requires -Modules Microsoft.Graph.Users

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateRange(14, 730)]
    [int]$StaleDays = 90,

    [Parameter()]
    [ValidateRange(7, 180)]
    [int]$NeverSignedInGraceDays = 30,

    [Parameter()]
    [string]$OutputPath = ".\output"
)

Connect-MgGraph -Scopes 'User.Read.All', 'AuditLog.Read.All' -NoWelcome

Write-Host 'Retrieving enabled users with sign-in activity (large tenants: this takes a few minutes)...' -ForegroundColor Cyan
$properties = 'id,displayName,userPrincipalName,accountEnabled,userType,createdDateTime,signInActivity,department,onPremisesSyncEnabled'
$users = Get-MgUser -All -Property $properties -Filter 'accountEnabled eq true'

$staleCutoff = (Get-Date).AddDays(-$StaleDays)
$graceCutoff = (Get-Date).AddDays(-$NeverSignedInGraceDays)

$stale = foreach ($user in $users) {
    $lastSeen = ($user.SignInActivity.LastSignInDateTime,
                 $user.SignInActivity.LastNonInteractiveSignInDateTime |
                 Where-Object { $_ } | Measure-Object -Maximum).Maximum

    $status = $null
    if (-not $lastSeen) {
        if ($user.CreatedDateTime -lt $graceCutoff) { $status = 'NeverSignedIn' }
    }
    elseif ($lastSeen -lt $staleCutoff) {
        $status = "Stale>$($StaleDays)d"
    }
    if (-not $status) { continue }

    [PSCustomObject]@{
        DisplayName       = $user.DisplayName
        UserPrincipalName = $user.UserPrincipalName
        UserType          = $user.UserType
        Status            = $status
        LastSignIn        = if ($lastSeen) { $lastSeen.ToString('yyyy-MM-dd') } else { 'Never' }
        DaysSinceSignIn   = if ($lastSeen) { [int]((Get-Date) - $lastSeen).TotalDays } else { $null }
        CreatedDate       = $user.CreatedDateTime.ToString('yyyy-MM-dd')
        Department        = $user.Department
        Source            = if ($user.OnPremisesSyncEnabled) { 'Hybrid (AD-synced)' } else { 'Cloud-only' }
    }
}

$stale = $stale | Sort-Object -Property UserType, DaysSinceSignIn -Descending

# Console summary
Write-Host ''
Write-Host ("Enabled accounts analyzed : {0}" -f ($users | Measure-Object).Count)
Write-Host ("Stale/never-signed-in     : {0}" -f ($stale | Measure-Object).Count) -ForegroundColor Yellow
$stale | Group-Object -Property UserType | ForEach-Object {
    Write-Host ("  {0,-8} {1}" -f $_.Name, $_.Count)
}

if (-not (Test-Path -Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}
$csvFile = Join-Path -Path $OutputPath -ChildPath ("StaleAccounts-{0:yyyy-MM-dd}.csv" -f (Get-Date))
$stale | Export-Csv -Path $csvFile -NoTypeInformation -Encoding UTF8
Write-Host "Report exported to $csvFile" -ForegroundColor Green
