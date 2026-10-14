# Backlog

Open work for the Microsoft 365 Admin Toolkit. Append new entries directly rather than keeping
them only in chat/memory, so they travel with the repo.

## Open

- **Inbox rule scan speed.** The tenant-wide scan makes one Exchange call per mailbox (two for mailboxes with
  a flagged rule). Several parallel runspaces would cut the time on a big tenant; today it is sequential,
  with progress and cancel.
- **Findings report formats.** The report is plain text. A CSV bundle or an HTML version with the lists as
  tables would be easier to hand to someone else.

- **Rename the folder.** The script is now `Microsoft365AdminToolkit.ps1`, but the `O365UserProvisioning`
  folder keeps the old name so existing shortcuts and open editor sessions don't break. A rename is a folder
  move plus a README edit.
- **Audit Tenant: connector actions.** The connectors check is read-only. Disabling or removing a connector
  (`Set-InboundConnector -Enabled` / `Remove-InboundConnector`, and the outbound equivalents) from the list
  would close the loop for an incident, behind a confirmation dialog.

- **Audit Tenant: Premium registration report fast path.** On tenants with Entra ID P1/P2 the
  authentication-methods registration report returns every user's MFA registration in one paged call;
  using it when available would make the full MFA report much faster on very large tenants than the
  batched per-user reads used today (which work everywhere).

- **Offboard: finer-grained shared mailbox access control.** Both the create and offboard flows
  currently grant/revoke Full Access + Send As together per mailbox checkbox. Splitting them into
  separate checkboxes per mailbox is a small change (the underlying functions already accept
  per-mailbox `AccessRights` arrays) but the GUI doesn't expose it yet.
- **Audit tab: an "Isolate Account" one-click combo.** Right now the response actions (reset
  password, revoke sessions, require MFA re-register) are independent buttons by design (see
  README), but after actually using this during a real incident it may turn out admins always hit
  all three together — worth revisiting once there's real usage to judge against, rather than
  guessing now.
- **Audit tab: sign-in log risk detail.** `Get-UserSignInActivity` doesn't currently surface Entra
  ID Protection risk state/risk level per sign-in (`riskState`, `riskLevelDuringSignIn`), which
  would need `IdentityProtection.Read.All` and an Entra ID P2 tenant — worth adding as an optional
  column if the P2 report call fails gracefully like the MFA registration report already does.

- **Audit Tenant: per-user "password never expires".** The tab sets the tenant/domain policy. If
  individual accounts carry `DisablePasswordExpiration` / are set to expire explicitly, a per-user
  list-and-set (`Update-MgUser -PasswordPolicies`) would complement it. Not built because the
  request read as the tenant-wide setting.
- **Audit Tenant: role-based admin-consent reviewers.** Reviewers are the Global Administrators at
  the moment of the click, as explicit users. A role-based reviewer (so new Global Admins are picked
  up automatically) needs the exact Graph query syntax confirmed against a live tenant first.
- **Audit Tenant: wider "admin privileges" coverage.** The list shows active Entra ID role
  assignments only. PIM-eligible assignments (P2) and Exchange role groups (Organization Management,
  etc.) are not included.
- **Audit Tenant: mailbox-level forwarding sweep.** Blocking external forwarding at the outbound
  spam policy stops delivery, but doesn't list which mailboxes or inbox rules have forwarding
  configured; a scan (`ForwardingSmtpAddress` / `ForwardingAddress`) would show where to clean up.
- **Audit Tenant: Conditional Access.** The MFA / Security Defaults checks say Conditional Access is
  not evaluated; reading CA policies (Entra ID P1) would close that gap on tenants that use it.

## Done

- **Click-to-sort columns** (2026-10-14). Every list (sign-ins, audit log, devices, inbox rules, forwarding,
  message trace, admins, MFA report, connectors, forwarding use, inbox scan, SPF/DMARC) sorts ascending/descending
  by clicking a column header, numeric/date/text aware, via the shared `New-ListView`. Also dropped the
  invalid `-ConsistencyLevel` parameter from the directory-audit call.
- **Mail-security checks, Run All, findings report, on-demand loading** (2026-10-14). New backend module
  [Modules/AuditMailSecurity.psm1](Modules/AuditMailSecurity.psm1). Audit User gets a Forwarding sub-tab
  (mailbox forwarding + forwarding/redirect inbox rules incl. hidden). Audit Tenant gets External forwarding in
  use (mailbox forwards + mail flow rules), a suspicious-inbox-rule scan of every mailbox, the common
  attachment filter, DKIM, and SPF/DMARC analysis (public DNS, nested-include lookup counting, parent-domain
  DMARC inheritance). A Run All Checks button at the top runs every check (slow scans optional, failures marked
  per section, cancellable) and Export Findings Report at the bottom writes a text report of the findings and a
  session change journal covering every tab. Connecting no longer loads users/licenses/groups: each is loaded the
  first time a tab needs it (plus a Load Tenant Data button). Also fixed a layout bug: lists added after a
  toolbar were laid out underneath it (hiding their column headers) on the Audit User sub-tabs; found by
  testing WinForms docking order directly. Verified with stand-in Exchange/Graph/DNS responses on PowerShell 7
  and 5.1 (93 mail-security, 89 backend, 46 connector, 44 report-engine, 91 screen, 116 new-feature and 47
  full-form checks); not yet run against a real tenant.

- **Admin license check, Exchange connectors check, rename** (2026-10-14). (1) The admin accounts list has a
  Licenses column: admins holding a user license (a mailbox / Office / Teams / SharePoint plan that is on for
  them) are flagged red and counted in the summary; other licenses such as Entra ID P2 are shown but not
  flagged, and an unreadable lookup shows Unknown. Colouring is now per cell so a flagged cell stands out on a
  highlighted Global Administrator row. License names come from a shared helper in GraphHelpers. (2) New
  Exchange mail flow connectors section (Get-TenantMailConnectors): every inbound/outbound connector with
  High / Review flags, read-only, CSV export. (3) The app is now the Microsoft 365 Admin Toolkit; the name lives
  in one variable. Verified with stand-in responses on PowerShell 7 and 5.1 (89 backend, 46 connector, 91
  screen, 47 full-form, 44 report checks); not yet run against a real tenant.

- **Full user MFA report on the Audit Tenant tab** (2026-10-14). Run MFA Report lists every member user
  with registered MFA methods, what enforces MFA for them (Security Defaults / per-user MFA) and a
  combined Status (Protected / Registered, not enforced / Enforced, not registered / UNPROTECTED /
  Unknown), worst first, with include-disabled, include-guests and only-gaps options and a full CSV
  export. Reads through the Graph batch endpoint (20 users per request, throttling retried), works
  without Entra ID Premium, shows live progress on the status line (new optional shared progress
  object on the background worker) and is cancellable. Verified with stand-in Graph responses on
  PowerShell 7 and 5.1 (44 report-engine, 64 screen, 74 backend, 44 full-form checks); not yet run
  against a real tenant. Does not evaluate Conditional Access.

- **MFA column on the admin accounts list** (2026-10-14). Each listed admin's registered MFA-capable
  methods are read from their own authentication methods (no Premium needed) and shown as 'Yes: ...' /
  'NONE' / 'Unknown'; enabled admins with no MFA are red and turn the section red, and the CSV gains
  Mfa / MfaMethods columns. Verified with stand-in responses on PowerShell 7 and 5.1 (74 backend + 40 screen
  checks); not yet seen against a real tenant. It reports registration, not enforcement.


- **MFA methods check returned "BadRequest"** (2026-10-14). The method list was read by listing the
  `.../authenticationMethodConfigurations` sub-collection, which the service rejects with a 400;
  Microsoft returns those configurations as part of the parent `authenticationMethodsPolicy`, so that is
  what is read now (beta, then v1.0). Disable PATCHes go to whichever version answered. Errors from
  Graph calls now show the response body's code and message via `Modules/GraphHelpers.psm1` (used by
  every module) instead of the generic status text. Verified with stand-in Graph responses on
  PowerShell 7 and 5.1 (69 backend checks, plus the form tests re-run); the real 400 reason from your
  tenant was never seen, so if the check still fails, the message will now say why.


- **Disconnect Tenant button + status line fix** (2026-10-14). Added **Disconnect Tenant** next to
  Connect: disconnects Graph and Exchange Online on the worker, closes the worker runspace (so the
  Exchange session is discarded outright), and resets every tab, cached list, picker, export and
  Audit Tenant section to its not-connected state. The status text was clipped because its label was
  one line tall; it now has its own full-width two-line row under the buttons (form height 860 -> 894
  to make room), and the Audit User inner tab was trimmed so it no longer overhangs its page. The
  real form was built headlessly on PowerShell 7 and Windows PowerShell 5.1 and the layout geometry,
  a worst-case status string and the Disconnect handler were checked (37 checks); not looked at on
  screen.

- **Audit Tenant tab** (2026-10-14). Fourth top-level tab with tenant-wide checks and fixes, backed by
  the new [Modules/AuditTenant.psm1](Modules/AuditTenant.psm1) (Security Defaults check lives in
  `TenantData.psm1`): Exchange organization customization, Security Defaults, unified audit log
  search, Direct Send (`RejectDirectSend`), external auto-forwarding (outbound spam policies),
  password expiration (per verified managed domain), user consent to applications + admin consent
  workflow (workflow enabled first, then user consent removed), Voice / Microsoft Authenticator
  push MFA methods (refuses to remove the last MFA-capable method), and a list/export of every user
  holding an admin role. Each fix confirms first and reads the setting back. Backend (56 checks) and
  screen construction/rendering (32 checks) verified headlessly on PowerShell 7 and Windows
  PowerShell 5.1 with stand-in Exchange/Graph responses; not yet run against a real tenant. New
  Graph scopes: `RoleManagement.Read.Directory`, `Domain.ReadWrite.All`,
  `Policy.ReadWrite.Authorization`, `Policy.ReadWrite.ConsentRequest`.

- **Background worker for all tenant calls** (2026-10-14). Connecting appeared to hang because
  sign-in, and every later Graph/Exchange call, ran on the UI thread: the window froze (and could
  deadlock against the WinForms message loop) while a WAM sign-in dialog that can open behind other
  windows waited for input. All tenant calls now go through `Invoke-Worker` in
  [Microsoft365AdminToolkit.ps1](Microsoft365AdminToolkit.ps1) onto one persistent STA runspace, with live status text, a
  Cancel button, a 5-minute sign-in timeout, per-list warnings on connect, and `-DisableWAM` for
  Exchange Online when the installed module supports it. The worker mechanism (argument binding,
  error unwrapping, timeout, cancel, clean process exit) was verified headlessly on PowerShell 7 and
  Windows PowerShell 5.1; the sign-in itself still needs a real tenant to confirm. Found along the
  way: `Runspace.CloseAsync()` leaves a foreground thread that stops the host process from exiting,
  so teardown uses a synchronous `Close()` instead.

- **User offboard feature** (2026-09-22). Added an "Offboard User" tab next to "New User" in
  [Microsoft365AdminToolkit.ps1](Microsoft365AdminToolkit.ps1): pick an existing user, the tool loads what they actually
  hold (licenses, security groups, Teams, distribution lists, shared mailbox access) via
  `Get-UserOffboardContext`, pre-checks all of it for removal, and lets the admin uncheck anything
  to keep. `Remove-O365UserAccount` (both in
  [Modules/UserProvisioning.psm1](Modules/UserProvisioning.psm1)) disables the account and revokes
  sign-in sessions (`Revoke-MgUserSignInSession`, from the newly-added
  `Microsoft.Graph.Users.Actions` module dependency) by default, removes the checked
  licenses/memberships, and optionally converts the mailbox to shared with a manager access grant.
  Not yet tested against a live tenant — see README's "not yet tested" section.
- **Audit User feature** (2026-09-22). Added an "Audit User" tab for running a secondary check
  after a suspected account compromise, backed by a new
  [Modules/AuditUser.psm1](Modules/AuditUser.psm1): recent sign-ins and directory audit events,
  registered devices sorted by most recent, password reset (random-generated, forced change),
  revoke active sessions, require MFA re-register (deletes all registered MFA methods), verify MFA
  registration status (Entra ID P1/P2 report), inbox rule listing with forward/redirect/delete
  rules flagged, restricted-sender-list check, and a message trace with CSV export that chunks the
  requested date range into ≤10-day windows against the new `Get-MessageTraceV2` (the legacy
  `Get-MessageTrace` is deprecated as of Sept 2025). Added `Microsoft.Graph.Identity.SignIns` and
  `Microsoft.Graph.Reports` as required modules, and `AuditLog.Read.All` / `Reports.Read.All` /
  `UserAuthenticationMethod.ReadWrite.All` as additional Graph scopes. Not yet tested against a
  live tenant — see README's "not yet tested" section for the specific risk areas (the
  directory-audit lambda filter, the P1/P2 dependency, and the
  `Get-MessageTraceV2` module-version dependency).
