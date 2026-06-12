<#
.SYNOPSIS
    Exports every Conditional Access policy to human-readable Markdown (plus a
    raw JSON snapshot) — instant CA documentation for audits, reviews, and
    change tracking.

.DESCRIPTION
    Conditional Access is the tenant's actual security policy, but in the
    portal it's only readable one policy at a time. This script flattens all
    policies into a single Markdown document with GUIDs resolved to names,
    well-known values translated, and a findings section flagging:

      - Policies sitting in report-only mode
      - Disabled policies (documented intent that isn't enforced)
      - No enabled policy requiring MFA for all users (heuristic)

    The JSON snapshot alongside it is diff-friendly: commit each export and
    `git diff` shows exactly what changed in your CA posture between runs.
    Useful for ISO 27001 / SOC 2 evidence collection.

    Read-only.

.PARAMETER OutputPath
    Folder for the Markdown + JSON exports. Defaults to .\output.

.EXAMPLE
    .\Export-ConditionalAccessReport.ps1

.NOTES
    Author : Salim Rashid
    Requires: Microsoft.Graph.Identity.SignIns, Microsoft.Graph.Users, Microsoft.Graph.Groups
    Scopes  : Policy.Read.All, User.Read.All, Group.Read.All
#>
#Requires -Modules Microsoft.Graph.Identity.SignIns, Microsoft.Graph.Users, Microsoft.Graph.Groups

[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputPath = ".\output"
)

Connect-MgGraph -Scopes 'Policy.Read.All', 'User.Read.All', 'Group.Read.All' -NoWelcome

$wellKnown = @{
    'All'                                  = 'All users'
    'None'                                 = 'None'
    'GuestsOrExternalUsers'                = 'Guests / external users'
    'Office365'                            = 'Office 365 (app group)'
    'MicrosoftAdminPortals'                = 'Microsoft Admin Portals'
    '00000002-0000-0ff1-ce00-000000000000' = 'Exchange Online'
    '00000003-0000-0ff1-ce00-000000000000' = 'SharePoint Online'
}
$nameCache = @{}

function Resolve-DirectoryObjectName {
    param([string]$Id)
    if ($wellKnown.ContainsKey($Id)) { return $wellKnown[$Id] }
    if ($nameCache.ContainsKey($Id)) { return $nameCache[$Id] }

    $name = $Id
    $user = Get-MgUser -UserId $Id -Property 'displayName' -ErrorAction SilentlyContinue
    if ($user) { $name = "$($user.DisplayName) (user)" }
    else {
        $group = Get-MgGroup -GroupId $Id -Property 'displayName' -ErrorAction SilentlyContinue
        if ($group) { $name = "$($group.DisplayName) (group)" }
    }
    $nameCache[$Id] = $name
    return $name
}

function Format-IdList {
    param($Ids)
    $clean = @($Ids | Where-Object { $_ })
    if ($clean.Count -eq 0) { return '—' }
    ($clean | ForEach-Object { Resolve-DirectoryObjectName -Id $_ }) -join ', '
}

Write-Host 'Retrieving Conditional Access policies...' -ForegroundColor Cyan
$policies = Get-MgIdentityConditionalAccessPolicy -All | Sort-Object -Property DisplayName

if (-not (Test-Path -Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}

$markdown = [System.Text.StringBuilder]::new()
[void]$markdown.AppendLine("# Conditional Access Policy Report")
[void]$markdown.AppendLine("")
[void]$markdown.AppendLine("Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm') · Policies: $(@($policies).Count)")
[void]$markdown.AppendLine("")

foreach ($policy in $policies) {
    $stateLabel = switch ($policy.State) {
        'enabled'                         { '✅ Enabled' }
        'disabled'                        { '⛔ Disabled' }
        'enabledForReportingButNotEnforced' { '👁 Report-only' }
        default                           { $policy.State }
    }

    $users = $policy.Conditions.Users
    $apps  = $policy.Conditions.Applications
    $grant = $policy.GrantControls

    [void]$markdown.AppendLine("## $($policy.DisplayName)")
    [void]$markdown.AppendLine("")
    [void]$markdown.AppendLine("| Setting | Value |")
    [void]$markdown.AppendLine("|---|---|")
    [void]$markdown.AppendLine("| State | $stateLabel |")
    [void]$markdown.AppendLine("| Users included | $(Format-IdList (@($users.IncludeUsers) + @($users.IncludeGroups))) |")
    [void]$markdown.AppendLine("| Users excluded | $(Format-IdList (@($users.ExcludeUsers) + @($users.ExcludeGroups))) |")
    [void]$markdown.AppendLine("| Roles included | $(if ($users.IncludeRoles) { @($users.IncludeRoles).Count.ToString() + ' role(s)' } else { '—' }) |")
    [void]$markdown.AppendLine("| Apps included | $(Format-IdList $apps.IncludeApplications) |")
    [void]$markdown.AppendLine("| Apps excluded | $(Format-IdList $apps.ExcludeApplications) |")
    [void]$markdown.AppendLine("| Client app types | $(if ($policy.Conditions.ClientAppTypes) { $policy.Conditions.ClientAppTypes -join ', ' } else { '—' }) |")
    [void]$markdown.AppendLine("| Grant controls | $(if ($grant.BuiltInControls) { "$($grant.Operator): $($grant.BuiltInControls -join ', ')" } else { '—' }) |")
    [void]$markdown.AppendLine("| Session controls | $(if ($policy.SessionControls.SignInFrequency.IsEnabled) { "Sign-in frequency: $($policy.SessionControls.SignInFrequency.Value) $($policy.SessionControls.SignInFrequency.Type)" } else { '—' }) |")
    [void]$markdown.AppendLine("")
}

# Findings
$reportOnly = @($policies | Where-Object { $_.State -eq 'enabledForReportingButNotEnforced' })
$disabled   = @($policies | Where-Object { $_.State -eq 'disabled' })
$mfaForAll  = @($policies | Where-Object {
    $_.State -eq 'enabled' -and
    $_.Conditions.Users.IncludeUsers -contains 'All' -and
    $_.GrantControls.BuiltInControls -contains 'mfa'
})

[void]$markdown.AppendLine("## Findings")
[void]$markdown.AppendLine("")
[void]$markdown.AppendLine("- Report-only policies (monitored, not enforced): **$(@($reportOnly).Count)**$(if ($reportOnly) { ' — ' + (($reportOnly.DisplayName) -join '; ') })")
[void]$markdown.AppendLine("- Disabled policies: **$(@($disabled).Count)**$(if ($disabled) { ' — ' + (($disabled.DisplayName) -join '; ') })")
if (@($mfaForAll).Count -eq 0) {
    [void]$markdown.AppendLine("- ⚠️ **No enabled policy requiring MFA for all users was detected.** (Heuristic — verify against your CA design; risk-based or per-app policies may cover this.)")
}
else {
    [void]$markdown.AppendLine("- MFA-for-all-users coverage: **$(($mfaForAll.DisplayName) -join '; ')**")
}

$stamp  = Get-Date -Format 'yyyy-MM-dd'
$mdFile = Join-Path -Path $OutputPath -ChildPath "ConditionalAccess-$stamp.md"
$jsonFile = Join-Path -Path $OutputPath -ChildPath "ConditionalAccess-$stamp.json"

$markdown.ToString() | Set-Content -Path $mdFile -Encoding UTF8
$policies | ConvertTo-Json -Depth 10 | Set-Content -Path $jsonFile -Encoding UTF8

Write-Host "Markdown report : $mdFile" -ForegroundColor Green
Write-Host "JSON snapshot   : $jsonFile (commit these to diff CA changes over time)" -ForegroundColor Green
