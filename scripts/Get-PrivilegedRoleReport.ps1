<#
.SYNOPSIS
    Audits Entra ID privileged role membership: who holds what, with flags for
    Global Admin sprawl, guests in privileged roles, stale privileged
    accounts, and service principals holding directory roles.

.DESCRIPTION
    Answers the question every identity review starts with: "who can actually
    do damage in this tenant?" Enumerates active directory role assignments
    and applies the checks that matter:

      - Global Administrator count vs. Microsoft's guidance (2-4, fewer than 5)
      - Guest accounts holding any privileged role
      - Privileged accounts with no sign-in in N days (dormant admin access)
      - Service principals assigned to directory roles

    Read-only. (PIM-eligible assignments are a roadmap item — this covers
    *active* assignments, which is where standing risk lives.)

.PARAMETER StaleAdminDays
    Days without sign-in before a privileged account is flagged dormant.
    Default: 45.

.PARAMETER OutputPath
    Folder for the CSV export. Defaults to .\output.

.EXAMPLE
    .\Get-PrivilegedRoleReport.ps1 -StaleAdminDays 30

.NOTES
    Author : Salim Rashid
    Requires: Microsoft.Graph.Identity.DirectoryManagement, Microsoft.Graph.Users
    Scopes  : RoleManagement.Read.Directory, User.Read.All, AuditLog.Read.All
#>
#Requires -Modules Microsoft.Graph.Identity.DirectoryManagement, Microsoft.Graph.Users

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateRange(7, 365)]
    [int]$StaleAdminDays = 45,

    [Parameter()]
    [string]$OutputPath = ".\output"
)

$GlobalAdminTemplateId = '62e90394-69f5-4237-9190-012177145e10'

Connect-MgGraph -Scopes 'RoleManagement.Read.Directory', 'User.Read.All', 'AuditLog.Read.All' -NoWelcome

Write-Host 'Enumerating active directory roles and members...' -ForegroundColor Cyan
$roles = Get-MgDirectoryRole -All
$staleCutoff = (Get-Date).AddDays(-$StaleAdminDays)
$userCache = @{}

$assignments = foreach ($role in $roles) {
    $members = Get-MgDirectoryRoleMember -DirectoryRoleId $role.Id -All
    foreach ($member in $members) {
        $odataType = $member.AdditionalProperties.'@odata.type'

        switch ($odataType) {
            '#microsoft.graph.user' {
                # Cache user lookups — the same admin often holds several roles
                if (-not $userCache.ContainsKey($member.Id)) {
                    $userCache[$member.Id] = Get-MgUser -UserId $member.Id `
                        -Property 'id,displayName,userPrincipalName,accountEnabled,userType,signInActivity' `
                        -ErrorAction SilentlyContinue
                }
                $user = $userCache[$member.Id]
                if (-not $user) { continue }

                $lastSeen = ($user.SignInActivity.LastSignInDateTime,
                             $user.SignInActivity.LastNonInteractiveSignInDateTime |
                             Where-Object { $_ } | Measure-Object -Maximum).Maximum

                $flags = [System.Collections.Generic.List[string]]::new()
                if ($role.RoleTemplateId -eq $GlobalAdminTemplateId) { $flags.Add('GlobalAdmin') }
                if ($user.UserType -eq 'Guest') { $flags.Add('GUEST-IN-PRIVILEGED-ROLE') }
                if (-not $user.AccountEnabled) { $flags.Add('DisabledAccountHoldsRole') }
                if (-not $lastSeen -or $lastSeen -lt $staleCutoff) { $flags.Add("DormantAdmin>$($StaleAdminDays)d") }

                [PSCustomObject]@{
                    Role           = $role.DisplayName
                    PrincipalType  = 'User'
                    DisplayName    = $user.DisplayName
                    Identifier     = $user.UserPrincipalName
                    AccountEnabled = $user.AccountEnabled
                    LastSignIn     = if ($lastSeen) { $lastSeen.ToString('yyyy-MM-dd') } else { 'Never' }
                    Flags          = $flags -join '; '
                }
            }
            '#microsoft.graph.servicePrincipal' {
                [PSCustomObject]@{
                    Role           = $role.DisplayName
                    PrincipalType  = 'ServicePrincipal'
                    DisplayName    = $member.AdditionalProperties.displayName
                    Identifier     = $member.Id
                    AccountEnabled = $null
                    LastSignIn     = $null
                    Flags          = 'ServicePrincipalHoldsDirectoryRole'
                }
            }
            default {
                [PSCustomObject]@{
                    Role           = $role.DisplayName
                    PrincipalType  = ($odataType -replace '#microsoft.graph.', '')
                    DisplayName    = $member.AdditionalProperties.displayName
                    Identifier     = $member.Id
                    AccountEnabled = $null
                    LastSignIn     = $null
                    Flags          = 'ReviewManually'
                }
            }
        }
    }
}

# Console summary
$gaCount = ($assignments | Where-Object { $_.Flags -match 'GlobalAdmin' } | Select-Object -Unique -Property Identifier | Measure-Object).Count
$gaColor = if ($gaCount -ge 5 -or $gaCount -lt 2) { 'Red' } else { 'Green' }

Write-Host ''
Write-Host ("Active role assignments  : {0}" -f ($assignments | Measure-Object).Count)
Write-Host ("Global Administrators    : {0}  (Microsoft guidance: 2-4, fewer than 5)" -f $gaCount) -ForegroundColor $gaColor
foreach ($pattern in 'GUEST-IN-PRIVILEGED-ROLE', 'DormantAdmin', 'DisabledAccountHoldsRole', 'ServicePrincipalHoldsDirectoryRole') {
    $count = ($assignments | Where-Object { $_.Flags -match $pattern } | Measure-Object).Count
    if ($count -gt 0) { Write-Host ("  {0,-36} {1}" -f $pattern, $count) -ForegroundColor Yellow }
}

if (-not (Test-Path -Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}
$csvFile = Join-Path -Path $OutputPath -ChildPath ("PrivilegedRoles-{0:yyyy-MM-dd}.csv" -f (Get-Date))
$assignments | Sort-Object -Property Role, DisplayName | Export-Csv -Path $csvFile -NoTypeInformation -Encoding UTF8
Write-Host "Report exported to $csvFile" -ForegroundColor Green
