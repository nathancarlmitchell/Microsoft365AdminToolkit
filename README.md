# Microsoft 365 Admin Toolkit

A WinForms GUI, run from PowerShell, for administering a Microsoft 365 / Entra ID tenant: onboarding
and offboarding users, investigating a suspected compromise, and auditing and hardening the tenant.
It has four tabs: **New User**, **Offboard User**, **Audit User** and **Audit Tenant**.

## New User tab

- First/last name entry, with **Display Name** and **email/UPN auto-suggested** from the tenant's
  existing naming convention (e.g. `first`, `flast`, `first.last`, `firstlast`, ...) — inferred by
  comparing every existing user's `GivenName`/`Surname` against their actual UPN and voting for the
  best-matching pattern. Both fields stay editable.
- A password field you type yourself (not auto-generated, not marked temporary — the user is not
  forced to change it at next sign-in).
- Live license list pulled from the tenant (`Get-MgSubscribedSku`), showing available seats per
  SKU; you can't check a SKU with zero seats left.
- Checklists of the tenant's existing security groups, Teams, distribution lists, and shared
  mailboxes to add the new user to (shared mailbox selection grants both Full Access + Send As).

## Offboard User tab

- Pick an existing user from a searchable dropdown (type to filter).
- The tool looks up what that user *actually* holds right now — assigned licenses, security
  group / Team / distribution list memberships, and shared mailbox Full Access / Send As grants —
  and pre-checks all of it as "will be removed." Uncheck anything the admin wants the user to keep
  (e.g. a company-wide "All Staff" DL) before offboarding.
- **Disable account** and **Revoke active sign-in sessions** are checked by default; both can be
  unchecked if you only want to strip access without disabling the account yet.
- Optional **Convert mailbox to shared**, with an optional manager UPN to grant Full Access + Send
  As on the now-shared mailbox for mail continuity.
- Same per-step success/failure reporting as the create flow — a failed step doesn't abort the rest
  of the run.

## Audit User tab

Secondary-check tooling for running after a suspected account compromise. Pick a user from the
searchable dropdown; unlike Offboard, nothing loads automatically — each sub-tab below pulls its
own data on demand, since sign-ins/devices/inbox rules/message trace are each independently
expensive.

- **Sign-Ins** — recent interactive sign-ins (date/time, app, IP, location, success/failure,
  per-sign-in MFA requirement), most recent first, count selectable (25/50/100/200).
- **Directory Audit** — recent directory changes made *to* this account (role/group/attribute
  changes, who made them), most recent first.
- **Devices** — the user's registered devices, sorted by most recent sign-in first — useful for
  spotting an unfamiliar device that registered itself during the compromise window.
- **Security Actions**:
  - **Reset Password** — type or **Generate** a cryptographically random password (shown once,
    with a **Copy** button), with **Force change at next sign-in** checked by default. This is
    intentionally a different password flow from the New User tab: incident response wants a
    random password forced to change, not an admin-chosen permanent one.
  - **Revoke Active Sessions** — signs the account out everywhere immediately.
  - **Require MFA Re-Register** — deletes every registered MFA method (Authenticator, phone,
    FIDO2, Windows Hello, software OATH, email, Temporary Access Pass) so the user must re-enroll
    on next sign-in. Shows exactly what was removed/failed/skipped — a method that's currently the
    account's *default* MFA method often can't be deleted until another is made default first;
    that shows up as a failure, not a silent no-op.
  - **Verify MFA Is Enforced** — reports whether the user has an MFA method registered and whether
    anything enforces it. Registration comes from the authentication-methods registration report
    when the tenant has Entra ID P1/P2; on a non-premium tenant (where that report errors with
    "Tenant is not a B2C tenant and doesn't have premium license") it falls back to reading the
    user's registered methods directly. Enforcement is checked through **Security Defaults** and
    **per-user MFA**, the two mechanisms that exist without Conditional Access. Conditional Access
    policies (P1) are not evaluated, and the log says so.
  - **Check Restricted Sender List** — checks whether Exchange Online's outbound-spam protection
    has already blocked this account from sending mail (a strong compromise signal on its own).
  - **Per-User MFA** — pick **enforced** (default), **enabled** or **disabled** and click **Set
    Per-User MFA**. Works without Entra ID Premium, so it is the way to require MFA on a single
    account when Security Defaults is off. A confirmation dialog spells out the effect first
    (for *enforced*: the user registers a method at next sign-in if they have none, and anything
    that can't show an MFA prompt, such as older mail clients or scripts using basic auth, stops
    working for that account). The new state is read back to confirm it took, and the log shows
    `before -> after`. Needs the `Policy.ReadWrite.AuthenticationMethod` Graph scope, so the next
    Connect asks you to consent to it once. It uses the beta endpoint
    `/beta/users/{id}/authentication/requirements`, not yet tested against a live tenant.
- **Inbox Rules** — every inbox rule on the mailbox; rules that forward, redirect, or auto-delete
  mail are highlighted in red as classic post-compromise indicators (an attacker hiding their
  tracks or exfiltrating mail).
- **Forwarding** - **Check External Forwarding** lists every way this mailbox's mail is forwarded:
  mailbox-level forwarding (set on the mailbox itself, invisible in Outlook) and forwarding or redirect
  inbox rules, including rules hidden from Outlook and OWA. Each row says whether the target is outside
  the tenant (its accepted domains), whether the mailbox keeps a copy, and whether the rule is hidden.
  External or hidden rows are red; forwarding to another internal recipient is orange.
- **Message Trace** — date range pickers (defaults to the last 7 days) + Sent/Received/Both, **Run
  Trace**, then **Export to CSV...**. Internally chunks the requested range into ≤10-day windows
  against `Get-MessageTraceV2` (the old `Get-MessageTrace` is deprecated) and merges the results,
  so a multi-week range still works in one click.

## Audit Tenant tab

Tenant-wide checks and hardening actions, as opposed to the per-account checks on the Audit User
tab. Connect first. **Run All Checks** (top of the tab) clicks every Check in turn, slow scans last, with a tick
box to leave the two slow ones out (the full user MFA report and the every-mailbox inbox rule scan). A check
that fails marks its own section *Could not be read* and the run carries on; **Cancel** stops it. It ends
with a summary of problems and items to review. **Export Findings Report...** (bottom of the tab) saves a
text file: a summary, one line per check, the details behind each (including the rows of the list
sections), checks that were not run, and **every change this tool made in the session** across all tabs
(new users, offboarding, password resets, MFA changes, tenant fixes), each with its outcome. Passwords are never
written to it. The sections scroll. Every section has a **Check** button that only reads
(status shown green / orange / red), and where there is a fix, a separate action button that asks
for confirmation first, applies the change, then reads the setting back to confirm it took.

| Section | Check | Fix |
|---|---|---|
| **Exchange Online organization customization** | Whether the org is "dehydrated" (`Get-OrganizationConfig`). | **Enable Organization Customization** (`Enable-OrganizationCustomization`). One-time and one-way; some Exchange settings can't be changed without it, so do this first if other fixes fail with a customization error. |
| **Security Defaults** | ON / OFF. | Check only. |
| **Unified audit log search** | Whether audit log ingestion is on. | **Enable Audit Log Search**. Can take up to 60 minutes to start returning data. |
| **Direct Send** | Whether unauthenticated Direct Send is allowed (`RejectDirectSend`). | **Disable Direct Send** sets `RejectDirectSend = True`. Scanners, printers and apps that send straight to your domain without authenticating will be rejected until they use authenticated SMTP or a mail flow connector. |
| **Forwarding to external domains** | `AutoForwardingMode` on every outbound spam filter policy. | **Disable External Forwarding** sets every policy to `Off`. Existing forwards stay configured but stop delivering externally. |
| **Password expiration** | Validity period per domain. | **Set Passwords to Never Expire** sets every verified, managed domain to never expire. Federated and unverified domains are skipped. Individually-set accounts are not overridden. |
| **User consent to applications** | Whether users can consent, and whether the admin consent workflow is on. | **Block User Consent + Enable Admin Requests**: turns the admin consent workflow on first (reviewers = every enabled Global Administrator, merged with any reviewers already set), and only then clears users' ability to consent. If the workflow can't be enabled, consent is left untouched. |
| **MFA verification methods** | State of every method in the authentication methods policy. | **Disable Selected Methods** for Voice call and/or Microsoft Authenticator (push notification). Refuses if that would leave no MFA-capable method enabled. |
| **Accounts with admin privileges** | **List Admin Accounts**: every user holding an Entra ID admin role, directly or via a role-assignable group, Global Administrators highlighted, with **MFA** and **Licenses** columns (red when an admin has no MFA method or holds a user license); **Export CSV...**. | Read-only. |
| **Full user MFA report** | **Run MFA Report**: every user's registered MFA methods, what enforces MFA for them, and a combined Status; filter to gaps, **Export CSV...**. | Read-only. |
| **Exchange mail flow connectors** | **List Connectors**: every inbound and outbound connector with its scope, endpoints, TLS setting and creation date, flagged when unsafe or worth confirming; **Export CSV...**. | Read-only (change connectors in the Exchange admin center). |
| **External forwarding in use** | **Scan for External Forwarding**: mailboxes that forward to an address outside the tenant, and mail flow rules that redirect or copy mail to one (a disabled rule is only Review). | Read-only. |
| **Suspicious inbox rules (every mailbox)** | **Scan All Mailboxes**: opens each user mailbox (shared ones optionally) and flags rules that look like business-email-compromise persistence; **Export CSV...**. Slow on a big tenant: progress is shown and it can be cancelled. | Read-only. |
| **Common attachment filter** | Whether the anti-malware common attachments filter is on in the default and every custom policy, the action, and whether the file-type list still covers the common risky types. | Read-only. |
| **DKIM signing** | Whether DKIM signing is enabled for every domain, and for domains where it is off whether the selector CNAMEs are already published (ready to enable). | Read-only. |
| **SPF and DMARC** | Reads each domain's SPF and DMARC from public DNS and analyzes them; **Export CSV...**. | Read-only. |

Notes on the less obvious ones:

- **Password expiration** is set per verified managed domain (the same thing the Microsoft 365
  admin center's "set passwords to never expire" does). Do it only with MFA in place, because a
  stolen password then stays valid until it is changed. It does not touch the per-user
  "password never expires" flag.
- **Full user MFA report** works on any tenant (no Entra ID Premium). For every member user it reads
  the registered authentication methods and the legacy per-user MFA state, in batches of 20 users per
  request, and combines them with the tenant's Security Defaults setting. **Status** means:
  **Protected** = an MFA-capable method is registered *and* something enforces MFA (Security Defaults
  or per-user MFA); **Registered, not enforced** = has a method but nothing requires it;
  **Enforced, not registered** = will be prompted to register at next sign-in; **UNPROTECTED** =
  neither. Worst rows sort first; disabled accounts and guests are left out unless you tick
  *Include disabled accounts* / *Include guests*, and *Only show users that are not Protected*
  filters the list without re-running it. The CSV always contains the full report. The status line
  shows live progress and the report can be cancelled. Throttled requests are retried honoring
  Retry-After; a user whose methods still can't be read shows as **Unknown** (never as "no MFA").
  Conditional Access (Entra ID P1) is not evaluated, so on a tenant that uses it, "not enforced" may
  be covered by a policy. A very large tenant takes a few minutes (roughly two small requests per
  20 users).
- **Inbox rule scan.** For every mailbox it reads the rules *including hidden ones* (`Get-InboxRule
  -IncludeHidden`) and flags: a forward or redirect to an address outside the tenant (High); a rule that
  deletes mail, or moves it to RSS / Conversation History / Deleted Items / Junk / Archive, when its
  conditions mention words attackers hide (security, password, invoice, payment, wire, bank and similar)
  (High); a rule that deletes *all* incoming mail (High); a rule hidden from Outlook and OWA (High); and,
  as Review, forwards to another internal recipient, other deleting/moving rules, mark-as-read combined
  with hiding, and odd rule names (blank, one or two characters, punctuation only). The built-in hidden
  *Junk E-mail Rule* is ignored. Reading rules needs rights such as Organization Management: Global Reader
  is not enough, and mailboxes that can't be read are counted and listed instead of silently skipped.
- **External forwarding** is judged against the tenant's accepted domains. A mailbox's `ForwardingAddress`
  can point at a mail contact, so it is resolved to the contact's real external address.
- **SPF and DMARC** are read from public DNS (a public resolver is asked first, then the system resolver)
  so an internal DNS zone for the same domain can't hide or fake the public records. SPF is checked for
  presence, a single record, the ending (`-all` / `~all` good; `?all` or none weak; `+all` allows
  everyone), the number of DNS lookups through nested includes (more than 10 breaks SPF; 8 or 9 is a
  warning) and whether it authorizes Microsoft 365. DMARC is checked for presence, one record, the policy
  (`p=none` is monitoring only), `pct`, a report address (`rua`) and a weaker subdomain policy; a
  subdomain with no record of its own inherits its parent's. Microsoft's `*.onmicrosoft.com` domains are
  skipped. DKIM is shown separately because Exchange, not DNS, says whether signing is on.- **Licenses column** is the check that admin accounts are not also user accounts. **USER LICENSE**
  means the admin holds a license with a mailbox, Office apps, Teams or SharePoint plan that is
  switched on for them (a license with those plans individually switched off doesn't count);
  **Other** means only licenses without those plans, such as Entra ID P1/P2, which admins can
  legitimately need for Conditional Access or PIM; **None** is what an admin account should show.
  Rationale: a licensed admin has a mailbox, so one phished email is also a compromised admin.
  Enabled admins with a user license turn the section red; **Unknown** means the license lookup
  failed, not that the account is unlicensed. The CSV includes the license names.
- **Mail flow connectors** matter because they decide who may deliver mail into the tenant and
  where outgoing mail goes, and a new one is a classic way to spoof a domain or divert mail.
  **Red** (High) = unsafe as configured: an inbound connector that treats its mail as internal
  (skipping spam filtering), accepts any sender domain, or accepts a partner's domain with no IP or
  certificate restriction. **Orange** (Review) = unusual or worth confirming: created in the last 30
  days, TLS not required, all outbound mail sent through a smart host, MTA-STS/DANE validation
  turned off, or used by a mail flow rule. **Grey** = disabled (disabled connectors raise no
  configuration flags). Gateway and hybrid setups legitimately trigger some Review flags; the point
  is to confirm each connector is one you created.
- **MFA column** shows the MFA-capable methods each admin has *registered* (Authenticator, phone,
  passkey, OATH token, Windows Hello); password, email and Temporary Access Pass don't count. It reads
  each admin's own authentication methods, so it works without Entra ID Premium, but it shows what is
  registered, not whether sign-in *enforces* it (use Security Defaults and Verify MFA Is Enforced for
  that). An enabled admin with **NONE** is shown in red and turns the section red; **Unknown** means the
  methods couldn't be read for that account (usually a missing permission), not that it has no MFA.
  The CSV export includes the MFA columns.
- **Admin accounts** lists *active* Entra ID role assignments. PIM-eligible assignments (Entra ID
  P2) and Exchange role groups (e.g. Organization Management) are not included, and service
  principals holding roles are only counted, not listed. Microsoft recommends 2 to 4 Global
  Administrators; the status turns orange outside that range.
- **Consent reviewers are the Global Administrators at the moment you click**, as explicit users.
  A Global Administrator added later is not a reviewer until you run it again. (Role-based
  reviewers exist in the portal, but the exact Graph syntax couldn't be confirmed, so explicit
  users are used.)
- **Disabling Microsoft Authenticator** also turns off its passwordless sign-in. The method list is
  read from the `authenticationMethodsPolicy` resource itself (beta first, then v1.0 if beta is
  rejected; only beta exposes Voice) because the service rejects listing the configurations
  sub-collection directly with a 400. Changes are sent to whichever API version answered.
- **Error messages show the service's own reason** (for example `Authorization_RequestDenied:
  Insufficient privileges...`) instead of the bare "BadRequest (Bad Request)" Graph raises, via the
  shared `GraphHelpers.psm1`.
- Each action's outcome (what changed, what was skipped, any per-item failure) is written to the log
  panel at the bottom.

## Prerequisites

- PowerShell 7+ recommended (Windows PowerShell 5.1 also works).
- Modules (the script offers to install any that are missing, `-Scope CurrentUser`):
  - `Microsoft.Graph.Authentication`
  - `Microsoft.Graph.Users`
  - `Microsoft.Graph.Users.Actions` (needed for `Revoke-MgUserSignInSession` in the offboard and
    audit flows)
  - `Microsoft.Graph.Groups`
  - `Microsoft.Graph.Identity.DirectoryManagement`
  - `Microsoft.Graph.Identity.SignIns` (authentication-method read/delete for MFA re-register, in
    the audit flow)
  - `Microsoft.Graph.Reports` (sign-in/audit logs and MFA registration report, in the audit flow)
  - `ExchangeOnlineManagement`
- The Audit Tenant tab asks for extra Graph permissions at sign-in (`RoleManagement.Read.Directory`,
  `Domain.ReadWrite.All`, `Policy.ReadWrite.Authorization`, `Policy.ReadWrite.ConsentRequest`,
  `Policy.ReadWrite.AuthenticationMethod`, `Policy.Read.All`). A Global Admin can consent to them;
  if you connected before they were added, click **Connect to Tenant** again.
- A Global Admin account (or User Administrator + Exchange Administrator + License Administrator +
  Security Reader), since you sign in interactively when the tool connects. The Audit tab's
  password reset / session revoke / MFA reset actions need Authentication Administrator or
  Privileged Authentication Administrator rights over the target account, not just Global Admin's
  default reach, if that account holds an admin role of equal or higher privilege itself.

## Running

```powershell
.\Microsoft365AdminToolkit.ps1
```

1. Click **Connect to Tenant...** — this triggers two interactive sign-ins (a browser popup for
   Microsoft Graph, then one for Exchange Online). Both need to succeed before anything else loads.
2. Connecting loads nothing. Tenant data is loaded **on demand**, the first time something needs it:
   opening the **Audit User** tab loads the user list; opening **Offboard User** loads the users plus
   licenses, groups, Teams, distribution lists and shared mailboxes (it needs them to show a user's
   memberships); on **New User**, focusing a name box loads the user list (for the naming suggestions)
   and opening the list tabs loads the rest, or press **Load Tenant Data** to load it all now (it also
   reloads). The Audit Tenant tab loads nothing: each check fetches what it needs. The status line under the buttons shows progress and
   the result; it wraps to two lines rather than cutting long text off. **Disconnect Tenant** (next
   to Connect) signs out of Graph and Exchange Online, discards the background session, and clears
   every tab back to its not-connected state; it's available whenever a sign-in exists and no
   operation is running. Click **Connect to Tenant...** again to reconnect, or to pick up newly
   added permissions.
3. Enter First Name / Last Name — Display Name and the suggested UPN populate automatically; edit
   either freely.
4. Set the password (shown in the hint what's checked client-side; Entra ID's own password policy
   is still the real gatekeeper and can reject it server-side).
5. Check whichever licenses / groups / Teams / DLs / shared mailboxes apply.
6. **Create User** — shows a confirmation summary, then reports exactly which steps succeeded or
   failed (partial failures, e.g. a license running out of seats mid-session, are reported per-item
   rather than aborting the whole thing).

## Design notes / things worth knowing

- **Every table sorts by clicking a column header.** Click once for ascending, again for descending; an
  arrow on the header shows the current sort. Columns are compared as numbers, then dates, then text, so
  `9` sorts before `10` and timestamps sort chronologically; empty cells sort last when ascending. The
  sort is kept when a list is reloaded.
- **All Graph / Exchange Online calls run on one background runspace**, not the UI thread, so the
  window keeps repainting and the status line shows live progress ("Loading users (12s)"). A
  single persistent runspace is deliberate: `Connect-ExchangeOnline` imports its cmdlets into the
  runspace it ran in, so every later Exchange call has to run there too. While a call is running
  the tabs are disabled, and the window can't be closed mid-operation.
- **Sign-in can be cancelled.** Connect and the read-only lookups show a **Cancel** button. If a
  sign-in is stuck inside Windows/MSAL code and doesn't stop within 5 seconds, that runspace is
  abandoned and the next action starts a fresh one (which means signing in again).
- **Shared mailbox grants are all-or-nothing (Full Access + Send As) per checkbox.** If you want
  finer-grained control (Full Access only, or Send As only) per mailbox, that's a small change to
  `Modules/UserProvisioning.psm1` (`New-O365UserAccount`'s `$SharedMailboxAssignments` shape already
  supports separate access-rights arrays — the GUI just doesn't expose the split yet).
- **Naming-convention inference** only votes using users that have both `GivenName` and `Surname`
  populated in Entra ID; sparse directories (contractors/service accounts without those fields set)
  won't skew the vote, but also means very small or inconsistent tenants may get a weak/empty
  suggestion — the UPN field is always editable as a fallback.
- **Usage Location** defaults to `US` — required by Graph before a license can be assigned; change
  it in the field next to the UPN box for tenants outside the US.
- License friendly names are mapped for common SKUs (`SPE_E3`, `ENTERPRISEPACK`, etc.) in
  `Get-TenantLicenses` (`Modules/TenantData.psm1`); anything unmapped just shows its raw
  `SkuPartNumber` — add entries there as needed for tenant-specific SKUs.
- The password field is cleared from the form immediately after a create attempt; it is never
  logged, written to disk, or transmitted anywhere except the one Graph API call that sets it.
- **Offboard membership lookups are per-user, not cached.** Selecting a user re-checks their
  distribution list memberships and shared mailbox permissions live (one Exchange Online call per
  candidate DL/mailbox), since Graph doesn't expose EXO-only constructs like DLs. On a tenant with
  a lot of DLs/shared mailboxes this lookup can take a few seconds — that's expected, not a hang.
- **Offboard removes only what's checked, defaulting to everything found.** The account itself is
  never deleted by this tool, only disabled — actual deletion (and the Entra ID soft-delete/restore
  window that comes with it) is left to the admin center if it's ever truly needed.
- **Audit tab actions are independent, not a guided incident-response wizard.** There's no "do
  everything" button by design — an analyst investigating a suspected compromise should look at
  sign-ins/devices/inbox rules *before* deciding which response actions (password reset, session
  revoke, MFA wipe) actually apply, rather than the tool assuming all of them are warranted.
- **MFA method type coverage.** `Reset-UserAuthenticationMethods`
  (`Modules/AuditUser.psm1`) maps the common authentication method types (phone, Microsoft
  Authenticator, software OATH, FIDO2, Windows Hello for Business, email, Temporary Access Pass)
  to their delete cmdlets. A type not in that map (e.g. a newer passwordless method type Microsoft
  adds later) is reported as "skipped — no removal cmdlet mapped" rather than silently ignored or
  erroring, so the log will tell you if the account has something this tool doesn't yet know how
  to strip.

## Troubleshooting sign-in

- **The sign-in window may open behind this app or your editor.** Microsoft Graph SDK 2.34+ and
  ExchangeOnlineManagement 3.7+ use the Windows account broker (WAM) by default, and that dialog
  can appear behind other windows. The status line says "finish in the sign-in window (check the
  taskbar if you do not see it)" while it waits; look for a flashing taskbar icon. Sign-in times
  out after 5 minutes, and **Cancel** works at any point.
- **"A window handle must be configured"** - the module is too old to cope with a GUI/ISE host.
  Run `Update-Module Microsoft.Graph.Authentication, ExchangeOnlineManagement`, then restart
  PowerShell. The tool already passes `-DisableWAM` to Exchange Online when your module version
  supports it (3.7.2+), which sends that sign-in through the browser instead.
- **Graph sign-in can't skip WAM** with the default Microsoft Graph app id (Microsoft's
  restriction, not this tool's), so Graph still uses the broker on Windows.
- If the status line stops at a particular step ("Microsoft Graph sign-in", "Exchange Online
  sign-in", "Loading ..."), that step is the one to look at; a slow list load is reported as a
  warning in the log rather than failing the whole connect.

## Not yet tested against a live tenant

This was authored and syntax-checked but not run against a real Microsoft 365 tenant. Before
relying on it for real provisioning:

- Try it once against a **non-production/test tenant** if you have one.
- Watch the log panel and PowerShell console for cmdlet errors on first real run — Graph module
  cmdlet parameter names occasionally shift between module versions.
- Confirm `Get-MgGroup -Filter "resourceProvisioningOptions/Any(x:x eq 'Team')"` returns your
  Teams correctly; if your Graph module version has `$Filter` behave differently, that line in
  `Get-TenantTeams` (`Modules/TenantData.psm1`) may need `-ConsistencyLevel eventual -CountVariable`
  added (some `Get-MgGroup -Filter` queries require it depending on module version).
- The Audit tab's directory-audit lookup (`Get-UserDirectoryAuditActivity` in
  `Modules/AuditUser.psm1`) uses a `targetResources/any(...)` lambda filter. It does not
  take `-ConsistencyLevel` (the cmdlet has no such parameter and the audit endpoint ignores the header);
  an earlier build passed it and failed with "A parameter cannot be found". The filter itself is still
  unverified against a live tenant.
- **Verify MFA Is Enforced** on a non-premium tenant relies on `Policy.Read.All` (Security Defaults
  and per-user MFA state), a Graph scope added after the first release - the next Connect will
  prompt you to consent to it. The per-user MFA read uses the *beta* Graph endpoint
  (`/beta/users/{id}/authentication/requirements`) through `Invoke-MgGraphRequest`; if Microsoft
  changes it, that line degrades to a note in the log ("Per-user MFA state could not be read")
  rather than failing the check.
- **Message Trace** depends on `Get-MessageTraceV2`, which is new as of 2025 — confirm your
  tenant's `ExchangeOnlineManagement` module version actually exposes it (`Get-Command
  Get-MessageTraceV2`); older module versions may only have the now-deprecated `Get-MessageTrace`.
- **Audit Tenant tab:** the backend logic and the screen were exercised with stand-in Exchange and
  Graph responses, but none of the tenant calls have run against a real tenant. Least certain, in
  order: the admin-consent request policy update (`Update-MgPolicyAdminConsentRequestPolicy
  -BodyParameter`, reviewers as `/users/{id}`), the beta authentication-methods PATCH for Voice and
  Microsoft Authenticator, and `RejectDirectSend` (new in 2025). Anything that fails reports the
  error in the log and a dialog rather than being silently skipped.
