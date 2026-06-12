# Entra ID Security Toolkit

Four read-only PowerShell scripts that produce a security snapshot of a Microsoft Entra ID tenant in about 15 minutes: stale accounts, MFA gaps, privileged role sprawl, and a full Conditional Access policy export. Built to turn "we should review identity hygiene sometime" into a recurring, evidence-producing routine.

![PowerShell](https://img.shields.io/badge/PowerShell-7%2B-blue) ![Entra ID](https://img.shields.io/badge/Microsoft-Entra%20ID-green) ![License](https://img.shields.io/badge/license-MIT-lightgrey)

## Why this exists

Identity is the perimeter now — most real-world compromises start with an account, not a firewall. After working the identity side of a token-theft incident response, I rebuilt my post-incident audit checklist as code so it could run monthly instead of "after the next incident." Every script answers a question a security review (or an ISO 27001 / SOC 2 auditor) will ask anyway:

| Question | Script | Output |
|---|---|---|
| Which enabled accounts has nobody used in months? | `Get-StaleAccountReport.ps1` | CSV: members vs. guests, never-signed-in, days dormant, AD-synced vs. cloud |
| Who still doesn't have MFA — and are any of them admins? | `Get-MfaRegistrationReport.ps1` | CSV: risk-ranked gaps (admin-no-MFA first), SMS-only reliance flagged |
| Who actually holds privileged roles? | `Get-PrivilegedRoleReport.ps1` | CSV: GA count vs. Microsoft guidance, guests in roles, dormant admins, service principals |
| What does our Conditional Access actually say? | `Export-ConditionalAccessReport.ps1` | Markdown doc with GUIDs resolved to names + diff-friendly JSON snapshot |

All four are **strictly read-only** — safe to run in production, safe to hand to a junior admin, safe to schedule.

## Prerequisites

- PowerShell 7+ recommended
- Microsoft Graph PowerShell SDK:

```powershell
Install-Module Microsoft.Graph.Users, Microsoft.Graph.Groups, Microsoft.Graph.Reports, Microsoft.Graph.Identity.SignIns, Microsoft.Graph.Identity.DirectoryManagement -Scope CurrentUser
```

- Delegated scopes (consented on first run): `User.Read.All`, `Group.Read.All`, `AuditLog.Read.All`, `RoleManagement.Read.Directory`, `Policy.Read.All`
- Microsoft Entra ID **P1 or higher** for `signInActivity` and the authentication methods report

## Quick start

```powershell
cd scripts

.\Get-StaleAccountReport.ps1 -StaleDays 90
.\Get-MfaRegistrationReport.ps1
.\Get-PrivilegedRoleReport.ps1 -StaleAdminDays 45
.\Export-ConditionalAccessReport.ps1
```

Example console output from the privileged role audit:

```
Active role assignments  : 38
Global Administrators    : 6  (Microsoft guidance: 2-4, fewer than 5)
  GUEST-IN-PRIVILEGED-ROLE             1
  DormantAdmin>45d                     3
  ServicePrincipalHoldsDirectoryRole   2
```

## Using this as audit evidence

- Run all four on a schedule (monthly works well) and keep the dated CSVs — they map cleanly onto access-control and identity-management evidence requests in ISO 27001 / SOC 2 audits.
- The Conditional Access script writes a **JSON snapshot** alongside the Markdown. Commit each snapshot to a private repo and `git diff` becomes your CA change history — when a policy quietly moved from enforced to report-only, you'll see exactly when.

## Design notes

- **Read-only by principle.** Reporting and remediation are different risk classes; this repo deliberately stays in the first one. Act on the findings through your normal change process.
- **Heuristics are labeled as heuristics.** The "no MFA-for-all-users policy" finding, for example, says so explicitly — risk-based or per-app designs can be fine and the report won't pretend otherwise.
- **Caches where it counts.** Role members and CA object names are resolved through lookup caches, so the scripts stay polite to Graph even in larger tenants.

## Roadmap

- PIM-eligible assignment coverage (current report covers active/standing assignments)
- Risky sign-in summary (Identity Protection, requires P2)
- HTML executive summary combining all four reports

## About

Built by **Salim Rashid** — IT administrator focused on Microsoft 365, Entra ID, and Intune at enterprise scale.

[LinkedIn](https://www.linkedin.com/in/salimr) · [Live M365 governance dashboard demo](https://salimr37.github.io/m365-governance-demo) · Related: [m365-license-optimizer](https://github.com/salimr37/m365-license-optimizer) · [intune-remediation-library](https://github.com/salimr37/intune-remediation-library)

MIT licensed. Issues and PRs welcome.
