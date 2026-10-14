<#
.SYNOPSIS
    Microsoft 365 Admin Toolkit: a WinForms front-end for administering a Microsoft 365 / Entra ID
    tenant, in four tabs.
      New User      - onboarding: auto-suggested UPN from the tenant's naming convention, an
                      admin-supplied non-temporary password, licenses against real available seats,
                      and membership in existing groups / Teams / distribution lists / shared mailboxes.
      Offboard User - disable + revoke sessions, remove the licenses and memberships the user
                      actually has, optionally convert the mailbox to shared.
      Audit User    - incident-response checks and actions on one account (sign-ins, devices, MFA,
                      inbox rules, message trace, password reset, session revoke).
      Audit Tenant  - tenant-wide security checks and hardening (Security Defaults, audit log, Direct
                      Send, forwarding, consent, MFA report, admin accounts, mail flow connectors).

.NOTES
    Run interactively. You will be prompted to sign in twice: once for Microsoft Graph
    (user/license/group creation) and once for Exchange Online (distribution lists / shared
    mailboxes). Both need to be a Global Admin or a role with equivalent User Administrator +
    Exchange Administrator rights.

    Required modules (the script will offer to install any that are missing):
      - Microsoft.Graph.Authentication
      - Microsoft.Graph.Users
      - Microsoft.Graph.Users.Actions
      - Microsoft.Graph.Groups
      - Microsoft.Graph.Identity.DirectoryManagement
      - ExchangeOnlineManagement
#>

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$scriptRoot = $PSScriptRoot

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()

Import-Module (Join-Path $scriptRoot 'Modules\NamingConvention.psm1') -Force
Import-Module (Join-Path $scriptRoot 'Modules\TenantData.psm1') -Force
Import-Module (Join-Path $scriptRoot 'Modules\UserProvisioning.psm1') -Force
Import-Module (Join-Path $scriptRoot 'Modules\AuditUser.psm1') -Force
Import-Module (Join-Path $scriptRoot 'Modules\AuditTenant.psm1') -Force
Import-Module (Join-Path $scriptRoot 'Modules\AuditMailSecurity.psm1') -Force

# ---------------------------------------------------------------------------
# Prerequisite module check
# ---------------------------------------------------------------------------
$requiredModules = @(
    'Microsoft.Graph.Authentication',
    'Microsoft.Graph.Users',
    'Microsoft.Graph.Users.Actions',
    'Microsoft.Graph.Groups',
    'Microsoft.Graph.Identity.DirectoryManagement',
    'Microsoft.Graph.Identity.SignIns',
    'Microsoft.Graph.Reports',
    'ExchangeOnlineManagement'
)
$missing = $requiredModules | Where-Object { -not (Get-Module -ListAvailable -Name $_) }
if ($missing) {
    $msg = "The following required PowerShell modules are not installed:`n`n$($missing -join "`n")`n`nInstall them now for the current user?"
    $choice = [System.Windows.Forms.MessageBox]::Show($msg, 'Missing Modules', [System.Windows.Forms.MessageBoxButtons]::YesNo, [System.Windows.Forms.MessageBoxIcon]::Warning)
    if ($choice -eq [System.Windows.Forms.DialogResult]::Yes) {
        foreach ($m in $missing) { Install-Module -Name $m -Scope CurrentUser -Force -AllowClobber }
    } else {
        [System.Windows.Forms.MessageBox]::Show('Cannot continue without required modules.', 'Exiting', [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error) | Out-Null
        exit 1
    }
}

# ---------------------------------------------------------------------------
# Script-scoped state populated after Connect
# ---------------------------------------------------------------------------
$script:Connected        = $false
$script:HasSession       = $false   # a Graph/Exchange sign-in exists, even if the connect didn't finish
$script:UsersLoaded      = $false   # tenant data is loaded on demand, not at connect
$script:ListsLoaded      = $false
$script:QuietChecks      = $false   # true while Run All Checks is clicking each check
$script:RunAllCancelled  = $false
$script:ConnectedAccount = ''
$script:ConnectedTenantId = ''
$script:TenantReport     = [ordered]@{}   # check results, for the findings report
$script:ChangeJournal    = New-Object System.Collections.ArrayList   # every change made this session
$script:ExistingUsers    = @()
$script:Licenses         = @()
$script:SecurityGroups   = @()
$script:Teams            = @()
$script:DistLists        = @()
$script:SharedMailboxes  = @()

# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------
function New-Label($text, $x, $y, $w = 120) {
    $l = New-Object System.Windows.Forms.Label
    $l.Text = $text
    $l.Location = New-Object System.Drawing.Point($x, $y)
    $l.Size = New-Object System.Drawing.Size($w, 20)
    return $l
}

function New-CheckedListTab($tabControl, $title) {
    $tab = New-Object System.Windows.Forms.TabPage
    $tab.Text = $title
    $clb = New-Object System.Windows.Forms.CheckedListBox
    $clb.Dock = [System.Windows.Forms.DockStyle]::Fill
    $clb.CheckOnClick = $true
    $clb.DisplayMember = 'Label'
    $tab.Controls.Add($clb)
    $tabControl.TabPages.Add($tab)
    return $clb
}

function Set-AllChecked($checkedListBox, [bool]$checked) {
    for ($i = 0; $i -lt $checkedListBox.Items.Count; $i++) {
        $checkedListBox.SetItemChecked($i, $checked)
    }
}

# Click-to-sort for every ListView. The comparer treats a column as numbers, then dates, then text, so
# "9" sorts before "10" and timestamps sort chronologically. Empty cells always sort last when ascending.
if (-not ('ListViewColumnComparer' -as [type])) {
    Add-Type -ReferencedAssemblies System.Windows.Forms -TypeDefinition @'
using System;
using System.Collections;
using System.Globalization;
using System.Windows.Forms;

public class ListViewColumnComparer : IComparer
{
    public int Column;
    public bool Descending;
    public ListViewColumnComparer(int column, bool descending) { Column = column; Descending = descending; }

    public int Compare(object x, object y)
    {
        string a = Cell((ListViewItem)x);
        string b = Cell((ListViewItem)y);
        int r;
        bool ea = a.Length == 0, eb = b.Length == 0;
        if (ea || eb) { r = ea == eb ? 0 : (ea ? 1 : -1); return Descending ? -r : r; }
        double da, db;
        DateTime ta, tb;
        if (double.TryParse(a, NumberStyles.Any, CultureInfo.CurrentCulture, out da) &&
            double.TryParse(b, NumberStyles.Any, CultureInfo.CurrentCulture, out db))
            r = da.CompareTo(db);
        else if (DateTime.TryParse(a, CultureInfo.CurrentCulture, DateTimeStyles.None, out ta) &&
                 DateTime.TryParse(b, CultureInfo.CurrentCulture, DateTimeStyles.None, out tb))
            r = ta.CompareTo(tb);
        else
            r = string.Compare(a, b, StringComparison.CurrentCultureIgnoreCase);
        return Descending ? -r : r;
    }

    string Cell(ListViewItem item)
    {
        return Column < item.SubItems.Count ? item.SubItems[Column].Text : "";
    }
}
'@
}

function Invoke-ListViewSort($lv) {
    $state = $lv.Tag
    if (-not $state -or $state.Column -lt 0) { return }
    $lv.ListViewItemSorter = New-Object ListViewColumnComparer -ArgumentList $state.Column, $state.Descending
    $lv.Sort()
    # Leave no sorter attached: with one attached, WinForms re-sorts on every later change to the items.
    $lv.ListViewItemSorter = $null
}

function New-ListView($parent, [string[]]$columns, [int[]]$widths) {
    $lv = New-Object System.Windows.Forms.ListView
    $lv.View = [System.Windows.Forms.View]::Details
    $lv.FullRowSelect = $true
    $lv.GridLines = $true
    $lv.Dock = [System.Windows.Forms.DockStyle]::Fill
    for ($i = 0; $i -lt $columns.Count; $i++) {
        $w = if ($widths -and $i -lt $widths.Count) { $widths[$i] } else { 120 }
        $header = $lv.Columns.Add($columns[$i], $w)
        $header.Tag = $columns[$i]    # plain title; the header text gets an arrow while sorted
    }
    $lv.Tag = @{ Column = -1; Descending = $false }
    $lv.Add_ColumnClick({
        param($sender, $e)
        $state = $sender.Tag
        if ($state.Column -eq $e.Column) { $state.Descending = -not $state.Descending }
        else { $state.Column = $e.Column; $state.Descending = $false }
        $arrow = if ($state.Descending) { [string][char]0x25BC } else { [string][char]0x25B2 }
        foreach ($c in $sender.Columns) { $c.Text = [string]$c.Tag }
        $sender.Columns[$state.Column].Text = "$($sender.Columns[$state.Column].Tag) $arrow"
        Invoke-ListViewSort $sender
    })
    $parent.Controls.Add($lv)
    # A Fill control is docked after the ones in front of it; without this the list starts at y=0, underneath
    # a toolbar that was added to the same parent first.
    $lv.BringToFront()
    return $lv
}

function Set-ListViewRows($listView, [array]$rows, [string[]]$properties) {
    $listView.BeginUpdate()
    $listView.Items.Clear()
    foreach ($row in $rows) {
        $item = New-Object System.Windows.Forms.ListViewItem([string]$row.($properties[0]))
        for ($i = 1; $i -lt $properties.Count; $i++) {
            [void]$item.SubItems.Add([string]$row.($properties[$i]))
        }
        $item.Tag = $row
        [void]$listView.Items.Add($item)
    }
    $listView.EndUpdate()
}

# ---------------------------------------------------------------------------
# Background worker runspace
# ---------------------------------------------------------------------------
# Every Graph / Exchange Online call runs on one dedicated STA runspace instead of the UI thread.
# That keeps the window responsive (and repainting) during slow calls, avoids the sign-in code
# deadlocking against the WinForms message loop, and lets a stuck sign-in be cancelled. One
# persistent runspace is required because Connect-ExchangeOnline imports its cmdlets into the
# runspace it ran in, so all later Exchange calls must run there too.
$script:WorkerRunspace   = $null
$script:WorkerBusy       = $false
$script:CancelRequested  = $false

function Initialize-Worker {
    $rs = [runspacefactory]::CreateRunspace()
    $rs.ApartmentState = [System.Threading.ApartmentState]::STA
    $rs.ThreadOptions  = [System.Management.Automation.Runspaces.PSThreadOptions]::ReuseThread
    $rs.Open()

    $ps = [powershell]::Create()
    $ps.Runspace = $rs
    try {
        $init = {
            param($moduleDir)
            $global:ErrorActionPreference = 'Stop'
            foreach ($m in 'TenantData', 'UserProvisioning', 'AuditUser', 'AuditTenant', 'AuditMailSecurity') {
                Import-Module (Join-Path $moduleDir "$m.psm1") -Force
            }
        }
        [void]$ps.AddScript($init.ToString(), $true).AddArgument((Join-Path $scriptRoot 'Modules'))
        [void]$ps.Invoke()
    }
    finally { $ps.Dispose() }

    $script:WorkerRunspace = $rs
}

function Invoke-Worker {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)] [scriptblock] $ScriptBlock,
        [object[]] $ArgumentList = @(),
        [string]   $Status,
        [switch]   $Cancellable,
        [int]      $TimeoutSeconds = 0,
        [hashtable] $Progress
    )

    if ($script:WorkerBusy) { throw 'Another tenant operation is still running.' }
    if (-not $script:WorkerRunspace) { Initialize-Worker }

    $script:WorkerBusy = $true
    $script:CancelRequested = $false

    $prevTabsEnabled    = $outerTabs.Enabled
    $prevConnectEnabled = $btnConnect.Enabled
    $prevStatusText     = $lblStatus.Text
    $prevStatusColor    = $lblStatus.ForeColor
    $outerTabs.Enabled  = $false
    $btnConnect.Enabled = $false
    $btnDisconnect.Enabled = $false
    $btnCancel.Visible  = [bool]$Cancellable
    $btnCancel.Enabled  = $true
    $form.Cursor = [System.Windows.Forms.Cursors]::WaitCursor
    if ($Status) { $lblStatus.ForeColor = [System.Drawing.Color]::DimGray }

    $ps = [powershell]::Create()
    $ps.Runspace = $script:WorkerRunspace
    $abandoned = $false
    try {
        [void]$ps.AddScript($ScriptBlock.ToString(), $true)
        foreach ($a in $ArgumentList) { [void]$ps.AddArgument($a) }
        $async = $ps.BeginInvoke()

        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $abort = $null
        while (-not $async.IsCompleted) {
            [System.Windows.Forms.Application]::DoEvents()
            if ($form.IsDisposed)                { $abort = 'Window closed.' }
            elseif ($script:CancelRequested)     { $abort = 'Cancelled.' }
            elseif ($TimeoutSeconds -gt 0 -and $sw.Elapsed.TotalSeconds -gt $TimeoutSeconds) { $abort = "Timed out after $TimeoutSeconds seconds." }
            if ($abort) { break }
            if ($Status) {
                $line = $Status
                if ($Progress -and $Progress['Text']) { $line = "$Status - $($Progress['Text'])" }
                $lblStatus.Text = "$line ($([int]$sw.Elapsed.TotalSeconds)s)"
            }
            Start-Sleep -Milliseconds 40
        }

        if ($abort) {
            [void]$ps.BeginStop($null, $null)
            $stopSw = [System.Diagnostics.Stopwatch]::StartNew()
            while (-not $async.IsCompleted -and $stopSw.Elapsed.TotalSeconds -lt 5) {
                [System.Windows.Forms.Application]::DoEvents()
                Start-Sleep -Milliseconds 40
            }
            if (-not $async.IsCompleted) {
                # Stuck inside native/async sign-in code: abandon this runspace (its pipeline thread is a
                # background thread, so it can't keep the process alive). The next call builds a fresh
                # runspace, which means signing in again. Not CloseAsync() - that leaves a foreground
                # thread that stops the host process from exiting.
                $abandoned = $true
                $script:WorkerRunspace = $null
                $script:Connected = $false
                $script:HasSession = $false
            }
            throw $abort
        }

        try { $out = $ps.EndInvoke($async) }
        catch {
            $inner = $_.Exception
            while ($inner.InnerException) { $inner = $inner.InnerException }
            throw $inner.Message
        }
        return $out
    }
    finally {
        if (-not $abandoned) { $ps.Dispose() }
        $script:WorkerBusy = $false
        if ($form.IsDisposed) { Close-Worker }
        else { $btnCancel.Visible = $false }
        if ($Status -and -not $form.IsDisposed) {
            $lblStatus.Text = $prevStatusText
            $lblStatus.ForeColor = $prevStatusColor
        }
        if (-not $form.IsDisposed) {
            $outerTabs.Enabled  = $prevTabsEnabled
            $btnConnect.Enabled = $prevConnectEnabled
            $btnDisconnect.Enabled = [bool]$script:HasSession
            $form.Cursor = [System.Windows.Forms.Cursors]::Default
        }
    }
}

function Close-Worker {
    # Only acts on an idle worker; a running call is stopped by Invoke-Worker's own abort path, which
    # calls this again once it has finished.
    if ($script:WorkerBusy -or -not $script:WorkerRunspace) { return }
    $rs = $script:WorkerRunspace
    $script:WorkerRunspace = $null
    try {
        $ps = [powershell]::Create()
        $ps.Runspace = $rs
        $disconnect = {
            try { Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue } catch {}
            try { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null } catch {}
        }
        [void]$ps.AddScript($disconnect.ToString(), $true)
        $async = $ps.BeginInvoke()
        if ($async.AsyncWaitHandle.WaitOne(10000)) {
            $ps.Dispose()
            $rs.Close()
        }
    }
    catch {}
}

# ---------------------------------------------------------------------------
# Form shell
# ---------------------------------------------------------------------------
$form = New-Object System.Windows.Forms.Form
$script:AppName = 'Microsoft 365 Admin Toolkit'
$form.Text = $script:AppName
$form.Size = New-Object System.Drawing.Size(800, 894)
$form.StartPosition = 'CenterScreen'
$form.MinimumSize = New-Object System.Drawing.Size(800, 894)

$y = 10

# --- Connect bar (shared across both tabs) ---
$btnConnect = New-Object System.Windows.Forms.Button
$btnConnect.Text = 'Connect to Tenant...'
$btnConnect.Location = New-Object System.Drawing.Point(10, $y)
$btnConnect.Size = New-Object System.Drawing.Size(150, 30)
$form.Controls.Add($btnConnect)

$btnDisconnect = New-Object System.Windows.Forms.Button
$btnDisconnect.Text = 'Disconnect Tenant'
$btnDisconnect.Location = New-Object System.Drawing.Point(168, $y)
$btnDisconnect.Size = New-Object System.Drawing.Size(140, 30)
$btnDisconnect.Enabled = $false
$form.Controls.Add($btnDisconnect)

$btnCancel = New-Object System.Windows.Forms.Button
$btnCancel.Text = 'Cancel'
$btnCancel.Location = New-Object System.Drawing.Point(695, $y)
$btnCancel.Size = New-Object System.Drawing.Size(75, 30)
$btnCancel.Visible = $false
$form.Controls.Add($btnCancel)
$btnCancel.add_Click({
    $script:CancelRequested = $true
    $btnCancel.Enabled = $false
    $lblStatus.Text = 'Cancelling...'
})
$y += 34

# Status gets its own full-width row, two lines tall, so long progress and result text wraps
# instead of being cut off.
$lblStatus = New-Object System.Windows.Forms.Label
$lblStatus.Text = 'Not connected.'
$lblStatus.AutoSize = $false
$lblStatus.Location = New-Object System.Drawing.Point(10, $y)
$lblStatus.Size = New-Object System.Drawing.Size(760, 34)
$lblStatus.ForeColor = [System.Drawing.Color]::DarkRed
$form.Controls.Add($lblStatus)
$y += 40

# --- Outer tabs: New User / Offboard User ---
$outerTabs = New-Object System.Windows.Forms.TabControl
$outerTabs.Location = New-Object System.Drawing.Point(10, $y)
$outerTabs.Size = New-Object System.Drawing.Size(760, 640)
$form.Controls.Add($outerTabs)
$y += 650

$tabNewUser = New-Object System.Windows.Forms.TabPage
$tabNewUser.Text = 'New User'
$outerTabs.TabPages.Add($tabNewUser)

$tabOffboard = New-Object System.Windows.Forms.TabPage
$tabOffboard.Text = 'Offboard User'
$outerTabs.TabPages.Add($tabOffboard)

$tabAudit = New-Object System.Windows.Forms.TabPage
$tabAudit.Text = 'Audit User'
$outerTabs.TabPages.Add($tabAudit)

$tabAuditTenant = New-Object System.Windows.Forms.TabPage
$tabAuditTenant.Text = 'Audit Tenant'
$outerTabs.TabPages.Add($tabAuditTenant)

# --- Shared result log (below all tabs) ---
$txtLog = New-Object System.Windows.Forms.TextBox
$txtLog.Location = New-Object System.Drawing.Point(10, $y)
$txtLog.Size = New-Object System.Drawing.Size(760, 100)
$txtLog.Multiline = $true
$txtLog.ScrollBars = 'Vertical'
$txtLog.ReadOnly = $true
$form.Controls.Add($txtLog)

# ===========================================================================
# "New User" tab contents
# ===========================================================================
$ny = 10

$grpName = New-Object System.Windows.Forms.GroupBox
$grpName.Text = 'New User'
$grpName.Location = New-Object System.Drawing.Point(10, $ny)
$grpName.Size = New-Object System.Drawing.Size(730, 200)
$tabNewUser.Controls.Add($grpName)

$grpName.Controls.Add((New-Label 'First Name:' 10 25))
$txtFirst = New-Object System.Windows.Forms.TextBox
$txtFirst.Location = New-Object System.Drawing.Point(140, 22)
$txtFirst.Size = New-Object System.Drawing.Size(200, 20)
$grpName.Controls.Add($txtFirst)

$grpName.Controls.Add((New-Label 'Last Name:' 10 55))
$txtLast = New-Object System.Windows.Forms.TextBox
$txtLast.Location = New-Object System.Drawing.Point(140, 52)
$txtLast.Size = New-Object System.Drawing.Size(200, 20)
$grpName.Controls.Add($txtLast)

$grpName.Controls.Add((New-Label 'Display Name:' 10 85))
$txtDisplayName = New-Object System.Windows.Forms.TextBox
$txtDisplayName.Location = New-Object System.Drawing.Point(140, 82)
$txtDisplayName.Size = New-Object System.Drawing.Size(300, 20)
$grpName.Controls.Add($txtDisplayName)

$grpName.Controls.Add((New-Label 'Email / UPN:' 10 115))
$cmbUpn = New-Object System.Windows.Forms.ComboBox
$cmbUpn.Location = New-Object System.Drawing.Point(140, 112)
$cmbUpn.Size = New-Object System.Drawing.Size(300, 20)
$cmbUpn.DropDownStyle = [System.Windows.Forms.ComboBoxStyle]::DropDown
$grpName.Controls.Add($cmbUpn)

$grpName.Controls.Add((New-Label 'Usage Location:' 460 115 100))
$txtUsageLocation = New-Object System.Windows.Forms.TextBox
$txtUsageLocation.Location = New-Object System.Drawing.Point(560, 112)
$txtUsageLocation.Size = New-Object System.Drawing.Size(40, 20)
$txtUsageLocation.Text = 'US'
$grpName.Controls.Add($txtUsageLocation)

$grpName.Controls.Add((New-Label 'Password:' 10 145))
$txtPassword = New-Object System.Windows.Forms.TextBox
$txtPassword.Location = New-Object System.Drawing.Point(140, 142)
$txtPassword.Size = New-Object System.Drawing.Size(200, 20)
$txtPassword.UseSystemPasswordChar = $true
$grpName.Controls.Add($txtPassword)

$grpName.Controls.Add((New-Label 'Confirm Password:' 360 145 110))
$txtPasswordConfirm = New-Object System.Windows.Forms.TextBox
$txtPasswordConfirm.Location = New-Object System.Drawing.Point(475, 142)
$txtPasswordConfirm.Size = New-Object System.Drawing.Size(200, 20)
$txtPasswordConfirm.UseSystemPasswordChar = $true
$grpName.Controls.Add($txtPasswordConfirm)

$chkShowPassword = New-Object System.Windows.Forms.CheckBox
$chkShowPassword.Text = 'Show'
$chkShowPassword.Location = New-Object System.Drawing.Point(680, 142)
$chkShowPassword.Size = New-Object System.Drawing.Size(60, 20)
$grpName.Controls.Add($chkShowPassword)

$lblPasswordHint = New-Object System.Windows.Forms.Label
$lblPasswordHint.Text = 'Min 8 chars, upper + lower + digit + special. Not marked temporary - user will not be forced to change it.'
$lblPasswordHint.Location = New-Object System.Drawing.Point(140, 170)
$lblPasswordHint.Size = New-Object System.Drawing.Size(560, 20)
$lblPasswordHint.ForeColor = [System.Drawing.Color]::Gray
$grpName.Controls.Add($lblPasswordHint)

$btnLoadTenantData = New-Object System.Windows.Forms.Button
$btnLoadTenantData.Text = 'Load Tenant Data'
$btnLoadTenantData.Location = New-Object System.Drawing.Point(480, 22)
$btnLoadTenantData.Size = New-Object System.Drawing.Size(200, 26)
$grpName.Controls.Add($btnLoadTenantData)

$lblLoadHint = New-Object System.Windows.Forms.Label
$lblLoadHint.Text = 'Connect to a tenant first.'
$lblLoadHint.ForeColor = [System.Drawing.Color]::Gray
$lblLoadHint.Location = New-Object System.Drawing.Point(480, 52)
$lblLoadHint.Size = New-Object System.Drawing.Size(240, 52)
$grpName.Controls.Add($lblLoadHint)

$ny += 210

# --- Inner tabs: Licenses / Security Groups / Teams / Distribution Lists / Shared Mailboxes ---
$tabsNewUser = New-Object System.Windows.Forms.TabControl
$tabsNewUser.Location = New-Object System.Drawing.Point(10, $ny)
$tabsNewUser.Size = New-Object System.Drawing.Size(730, 300)
$tabNewUser.Controls.Add($tabsNewUser)

$clbLicenses  = New-CheckedListTab $tabsNewUser 'Licenses'
$clbSecGroups = New-CheckedListTab $tabsNewUser 'Security Groups'
$clbTeams     = New-CheckedListTab $tabsNewUser 'Teams'
$clbDls       = New-CheckedListTab $tabsNewUser 'Distribution Lists'
$clbMailboxes = New-CheckedListTab $tabsNewUser 'Shared Mailboxes (Full Access + Send As)'

# Prevent checking a license with zero seats available
$clbLicenses.add_ItemCheck({
    param($s, $e)
    $item = $clbLicenses.Items[$e.Index]
    if ($e.NewValue -eq [System.Windows.Forms.CheckState]::Checked -and $item.Available -le 0) {
        $e.NewValue = [System.Windows.Forms.CheckState]::Unchecked
        [System.Windows.Forms.MessageBox]::Show("No available seats for $($item.FriendlyName).", 'License Unavailable', [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning) | Out-Null
    }
})

$ny += 310

$btnCreate = New-Object System.Windows.Forms.Button
$btnCreate.Text = 'Create User'
$btnCreate.Location = New-Object System.Drawing.Point(10, $ny)
$btnCreate.Size = New-Object System.Drawing.Size(150, 34)
$btnCreate.Enabled = $false
$tabNewUser.Controls.Add($btnCreate)

# ===========================================================================
# "Offboard User" tab contents
# ===========================================================================
$oy = 10

$tabOffboard.Controls.Add((New-Label 'Select User:' 10 $oy 90))
$cmbOffboardUser = New-Object System.Windows.Forms.ComboBox
$cmbOffboardUser.Location = New-Object System.Drawing.Point(110, $oy)
$cmbOffboardUser.Size = New-Object System.Drawing.Size(300, 20)
$cmbOffboardUser.DropDownStyle = [System.Windows.Forms.ComboBoxStyle]::DropDown
$cmbOffboardUser.DisplayMember = 'Label'
$cmbOffboardUser.AutoCompleteMode = [System.Windows.Forms.AutoCompleteMode]::SuggestAppend
$cmbOffboardUser.AutoCompleteSource = [System.Windows.Forms.AutoCompleteSource]::ListItems
$tabOffboard.Controls.Add($cmbOffboardUser)

$lblOffboardHint = New-Label 'Pick a user to load their current memberships.' 420 $oy 340
$lblOffboardHint.Height = 30    # long messages wrap to a second line
$lblOffboardHint.ForeColor = [System.Drawing.Color]::Gray
$tabOffboard.Controls.Add($lblOffboardHint)
$oy += 30

# --- Inner tabs: current Licenses / Security Groups / Teams / Distribution Lists / Shared Mailboxes ---
# Populated per-selected-user with only what they actually hold, all pre-checked = "will be
# removed" - uncheck anything the admin wants this user to keep.
$tabsOffboard = New-Object System.Windows.Forms.TabControl
$tabsOffboard.Location = New-Object System.Drawing.Point(10, $oy)
$tabsOffboard.Size = New-Object System.Drawing.Size(730, 260)
$tabOffboard.Controls.Add($tabsOffboard)

$clbOffLicenses  = New-CheckedListTab $tabsOffboard 'Licenses'
$clbOffSecGroups = New-CheckedListTab $tabsOffboard 'Security Groups'
$clbOffTeams     = New-CheckedListTab $tabsOffboard 'Teams'
$clbOffDls       = New-CheckedListTab $tabsOffboard 'Distribution Lists'
$clbOffMailboxes = New-CheckedListTab $tabsOffboard 'Shared Mailboxes'

$oy += 270

$chkDisableAccount = New-Object System.Windows.Forms.CheckBox
$chkDisableAccount.Text = 'Disable account (recommended)'
$chkDisableAccount.Location = New-Object System.Drawing.Point(10, $oy)
$chkDisableAccount.Size = New-Object System.Drawing.Size(260, 20)
$chkDisableAccount.Checked = $true
$tabOffboard.Controls.Add($chkDisableAccount)

$chkRevokeSessions = New-Object System.Windows.Forms.CheckBox
$chkRevokeSessions.Text = 'Revoke active sign-in sessions (recommended)'
$chkRevokeSessions.Location = New-Object System.Drawing.Point(280, $oy)
$chkRevokeSessions.Size = New-Object System.Drawing.Size(320, 20)
$chkRevokeSessions.Checked = $true
$tabOffboard.Controls.Add($chkRevokeSessions)
$oy += 28

$chkConvertShared = New-Object System.Windows.Forms.CheckBox
$chkConvertShared.Text = 'Convert mailbox to shared'
$chkConvertShared.Location = New-Object System.Drawing.Point(10, $oy)
$chkConvertShared.Size = New-Object System.Drawing.Size(180, 20)
$tabOffboard.Controls.Add($chkConvertShared)

$tabOffboard.Controls.Add((New-Label 'Grant access to (manager UPN, optional):' 200 $oy 230))
$txtGrantAccessTo = New-Object System.Windows.Forms.TextBox
$txtGrantAccessTo.Location = New-Object System.Drawing.Point(435, $oy)
$txtGrantAccessTo.Size = New-Object System.Drawing.Size(250, 20)
$txtGrantAccessTo.Enabled = $false
$tabOffboard.Controls.Add($txtGrantAccessTo)
$oy += 36

$btnOffboard = New-Object System.Windows.Forms.Button
$btnOffboard.Text = 'Offboard User'
$btnOffboard.Location = New-Object System.Drawing.Point(10, $oy)
$btnOffboard.Size = New-Object System.Drawing.Size(150, 34)
$btnOffboard.Enabled = $false
$tabOffboard.Controls.Add($btnOffboard)

# ===========================================================================
# "Audit User" tab contents
# ===========================================================================
# Secondary-check tooling for a suspected-compromised account. Every sub-tab acts on
# $script:SelectedAuditUser, set when a user is picked from the combo below; unlike the
# Offboard tab, nothing is pre-loaded on selection - each sub-tab pulls its own data on demand,
# since sign-ins/devices/inbox rules/message trace are each independently expensive and an
# analyst investigating one account rarely needs all of them at once.
$script:SelectedAuditUser = $null
$script:LastMessageTraceResults = @()

$ay = 10
$tabAudit.Controls.Add((New-Label 'Select User:' 10 $ay 90))
$cmbAuditUser = New-Object System.Windows.Forms.ComboBox
$cmbAuditUser.Location = New-Object System.Drawing.Point(110, $ay)
$cmbAuditUser.Size = New-Object System.Drawing.Size(300, 20)
$cmbAuditUser.DropDownStyle = [System.Windows.Forms.ComboBoxStyle]::DropDown
$cmbAuditUser.DisplayMember = 'Label'
$cmbAuditUser.AutoCompleteMode = [System.Windows.Forms.AutoCompleteMode]::SuggestAppend
$cmbAuditUser.AutoCompleteSource = [System.Windows.Forms.AutoCompleteSource]::ListItems
$tabAudit.Controls.Add($cmbAuditUser)

$lblAuditHint = New-Label 'Pick a user, then use each sub-tab to pull that data on demand.' 420 $ay 340
$lblAuditHint.Height = 30    # long messages wrap to a second line
$lblAuditHint.ForeColor = [System.Drawing.Color]::Gray
$tabAudit.Controls.Add($lblAuditHint)
$ay += 30

$tabsAudit = New-Object System.Windows.Forms.TabControl
$tabsAudit.Location = New-Object System.Drawing.Point(10, $ay)
$tabsAudit.Size = New-Object System.Drawing.Size(730, 560)
$tabAudit.Controls.Add($tabsAudit)

# --- Sub-tab: Sign-Ins ---
$tabSignIns = New-Object System.Windows.Forms.TabPage
$tabSignIns.Text = 'Sign-Ins'
$tabsAudit.TabPages.Add($tabSignIns)

$pnlSignIns = New-Object System.Windows.Forms.Panel
$pnlSignIns.Dock = [System.Windows.Forms.DockStyle]::Top
$pnlSignIns.Height = 36
$tabSignIns.Controls.Add($pnlSignIns)
$pnlSignIns.Controls.Add((New-Label 'Show last:' 5 8 70))
$cmbSignInTop = New-Object System.Windows.Forms.ComboBox
$cmbSignInTop.Location = New-Object System.Drawing.Point(80, 5)
$cmbSignInTop.Size = New-Object System.Drawing.Size(70, 20)
$cmbSignInTop.DropDownStyle = [System.Windows.Forms.ComboBoxStyle]::DropDownList
@('25', '50', '100', '200') | ForEach-Object { $cmbSignInTop.Items.Add($_) | Out-Null }
$cmbSignInTop.SelectedItem = '50'
$pnlSignIns.Controls.Add($cmbSignInTop)
$btnRefreshSignIns = New-Object System.Windows.Forms.Button
$btnRefreshSignIns.Text = 'Refresh Sign-Ins'
$btnRefreshSignIns.Location = New-Object System.Drawing.Point(160, 4)
$btnRefreshSignIns.Size = New-Object System.Drawing.Size(120, 26)
$pnlSignIns.Controls.Add($btnRefreshSignIns)

$lvSignIns = New-ListView $tabSignIns @('Date/Time', 'App', 'IP Address', 'Location', 'Status', 'MFA', 'Client App') @(130, 130, 100, 140, 160, 70, 90)

# --- Sub-tab: Directory Audit ---
$tabDirAudit = New-Object System.Windows.Forms.TabPage
$tabDirAudit.Text = 'Directory Audit'
$tabsAudit.TabPages.Add($tabDirAudit)

$pnlDirAudit = New-Object System.Windows.Forms.Panel
$pnlDirAudit.Dock = [System.Windows.Forms.DockStyle]::Top
$pnlDirAudit.Height = 36
$tabDirAudit.Controls.Add($pnlDirAudit)
$pnlDirAudit.Controls.Add((New-Label 'Show last:' 5 8 70))
$cmbAuditLogTop = New-Object System.Windows.Forms.ComboBox
$cmbAuditLogTop.Location = New-Object System.Drawing.Point(80, 5)
$cmbAuditLogTop.Size = New-Object System.Drawing.Size(70, 20)
$cmbAuditLogTop.DropDownStyle = [System.Windows.Forms.ComboBoxStyle]::DropDownList
@('25', '50', '100', '200') | ForEach-Object { $cmbAuditLogTop.Items.Add($_) | Out-Null }
$cmbAuditLogTop.SelectedItem = '50'
$pnlDirAudit.Controls.Add($cmbAuditLogTop)
$btnRefreshAuditLog = New-Object System.Windows.Forms.Button
$btnRefreshAuditLog.Text = 'Refresh Audit Log'
$btnRefreshAuditLog.Location = New-Object System.Drawing.Point(160, 4)
$btnRefreshAuditLog.Size = New-Object System.Drawing.Size(120, 26)
$pnlDirAudit.Controls.Add($btnRefreshAuditLog)

$lvAuditEvents = New-ListView $tabDirAudit @('Date/Time', 'Activity', 'Initiated By', 'Result') @(150, 220, 200, 100)

# --- Sub-tab: Devices ---
$tabDevices = New-Object System.Windows.Forms.TabPage
$tabDevices.Text = 'Devices'
$tabsAudit.TabPages.Add($tabDevices)

$pnlDevices = New-Object System.Windows.Forms.Panel
$pnlDevices.Dock = [System.Windows.Forms.DockStyle]::Top
$pnlDevices.Height = 36
$tabDevices.Controls.Add($pnlDevices)
$btnRefreshDevices = New-Object System.Windows.Forms.Button
$btnRefreshDevices.Text = 'Refresh Devices'
$btnRefreshDevices.Location = New-Object System.Drawing.Point(5, 4)
$btnRefreshDevices.Size = New-Object System.Drawing.Size(130, 26)
$pnlDevices.Controls.Add($btnRefreshDevices)

$lvDevices = New-ListView $tabDevices @('Device Name', 'Operating System', 'Trust Type', 'Managed', 'Compliant', 'Last Sign-In (most recent first)') @(160, 150, 100, 70, 70, 160)

# --- Sub-tab: Security Actions ---
$tabSecurity = New-Object System.Windows.Forms.TabPage
$tabSecurity.Text = 'Security Actions'
$tabsAudit.TabPages.Add($tabSecurity)

$grpPasswordReset = New-Object System.Windows.Forms.GroupBox
$grpPasswordReset.Text = 'Reset Password (Incident Response)'
$grpPasswordReset.Location = New-Object System.Drawing.Point(10, 10)
$grpPasswordReset.Size = New-Object System.Drawing.Size(700, 110)
$tabSecurity.Controls.Add($grpPasswordReset)

$grpPasswordReset.Controls.Add((New-Label 'New Password:' 10 25 100))
$txtIncidentPassword = New-Object System.Windows.Forms.TextBox
$txtIncidentPassword.Location = New-Object System.Drawing.Point(120, 22)
$txtIncidentPassword.Size = New-Object System.Drawing.Size(230, 20)
$txtIncidentPassword.UseSystemPasswordChar = $true
$grpPasswordReset.Controls.Add($txtIncidentPassword)

$btnGeneratePassword = New-Object System.Windows.Forms.Button
$btnGeneratePassword.Text = 'Generate'
$btnGeneratePassword.Location = New-Object System.Drawing.Point(360, 20)
$btnGeneratePassword.Size = New-Object System.Drawing.Size(80, 24)
$grpPasswordReset.Controls.Add($btnGeneratePassword)

$btnCopyPassword = New-Object System.Windows.Forms.Button
$btnCopyPassword.Text = 'Copy'
$btnCopyPassword.Location = New-Object System.Drawing.Point(445, 20)
$btnCopyPassword.Size = New-Object System.Drawing.Size(60, 24)
$grpPasswordReset.Controls.Add($btnCopyPassword)

$chkShowIncidentPassword = New-Object System.Windows.Forms.CheckBox
$chkShowIncidentPassword.Text = 'Show'
$chkShowIncidentPassword.Location = New-Object System.Drawing.Point(515, 22)
$chkShowIncidentPassword.Size = New-Object System.Drawing.Size(60, 20)
$grpPasswordReset.Controls.Add($chkShowIncidentPassword)

$chkForceChangeNextSignIn = New-Object System.Windows.Forms.CheckBox
$chkForceChangeNextSignIn.Text = 'Force change at next sign-in (recommended)'
$chkForceChangeNextSignIn.Location = New-Object System.Drawing.Point(10, 55)
$chkForceChangeNextSignIn.Size = New-Object System.Drawing.Size(320, 20)
$chkForceChangeNextSignIn.Checked = $true
$grpPasswordReset.Controls.Add($chkForceChangeNextSignIn)

$btnResetIncidentPassword = New-Object System.Windows.Forms.Button
$btnResetIncidentPassword.Text = 'Reset Password'
$btnResetIncidentPassword.Location = New-Object System.Drawing.Point(10, 80)
$btnResetIncidentPassword.Size = New-Object System.Drawing.Size(150, 24)
$grpPasswordReset.Controls.Add($btnResetIncidentPassword)

$btnRevokeSessions = New-Object System.Windows.Forms.Button
$btnRevokeSessions.Text = 'Revoke Active Sessions'
$btnRevokeSessions.Location = New-Object System.Drawing.Point(10, 130)
$btnRevokeSessions.Size = New-Object System.Drawing.Size(220, 30)
$tabSecurity.Controls.Add($btnRevokeSessions)

$btnRequireMfaReregister = New-Object System.Windows.Forms.Button
$btnRequireMfaReregister.Text = 'Require MFA Re-Register'
$btnRequireMfaReregister.Location = New-Object System.Drawing.Point(240, 130)
$btnRequireMfaReregister.Size = New-Object System.Drawing.Size(220, 30)
$tabSecurity.Controls.Add($btnRequireMfaReregister)

$btnVerifyMfa = New-Object System.Windows.Forms.Button
$btnVerifyMfa.Text = 'Verify MFA Is Enforced'
$btnVerifyMfa.Location = New-Object System.Drawing.Point(10, 170)
$btnVerifyMfa.Size = New-Object System.Drawing.Size(220, 30)
$tabSecurity.Controls.Add($btnVerifyMfa)

$btnCheckRestricted = New-Object System.Windows.Forms.Button
$btnCheckRestricted.Text = 'Check Restricted Sender List'
$btnCheckRestricted.Location = New-Object System.Drawing.Point(240, 170)
$btnCheckRestricted.Size = New-Object System.Drawing.Size(220, 30)
$tabSecurity.Controls.Add($btnCheckRestricted)

$grpPerUserMfa = New-Object System.Windows.Forms.GroupBox
$grpPerUserMfa.Text = 'Per-User MFA'
$grpPerUserMfa.Location = New-Object System.Drawing.Point(10, 215)
$grpPerUserMfa.Size = New-Object System.Drawing.Size(700, 70)
$tabSecurity.Controls.Add($grpPerUserMfa)

$grpPerUserMfa.Controls.Add((New-Label 'State:' 10 30 40))
$cmbPerUserMfaState = New-Object System.Windows.Forms.ComboBox
$cmbPerUserMfaState.Location = New-Object System.Drawing.Point(55, 27)
$cmbPerUserMfaState.Size = New-Object System.Drawing.Size(110, 20)
$cmbPerUserMfaState.DropDownStyle = [System.Windows.Forms.ComboBoxStyle]::DropDownList
@('enforced', 'enabled', 'disabled') | ForEach-Object { $cmbPerUserMfaState.Items.Add($_) | Out-Null }
$cmbPerUserMfaState.SelectedItem = 'enforced'
$grpPerUserMfa.Controls.Add($cmbPerUserMfaState)

$btnSetPerUserMfa = New-Object System.Windows.Forms.Button
$btnSetPerUserMfa.Text = 'Set Per-User MFA'
$btnSetPerUserMfa.Location = New-Object System.Drawing.Point(180, 25)
$btnSetPerUserMfa.Size = New-Object System.Drawing.Size(150, 26)
$grpPerUserMfa.Controls.Add($btnSetPerUserMfa)

$lblPerUserMfaHint = New-Label 'Enforced = MFA required at every sign-in; the user registers a method at next sign-in if they have none.' 340 22 350
$lblPerUserMfaHint.Height = 40
$lblPerUserMfaHint.ForeColor = [System.Drawing.Color]::Gray
$grpPerUserMfa.Controls.Add($lblPerUserMfaHint)

# --- Sub-tab: Inbox Rules ---
$tabInboxRules = New-Object System.Windows.Forms.TabPage
$tabInboxRules.Text = 'Inbox Rules'
$tabsAudit.TabPages.Add($tabInboxRules)

$pnlInboxRules = New-Object System.Windows.Forms.Panel
$pnlInboxRules.Dock = [System.Windows.Forms.DockStyle]::Top
$pnlInboxRules.Height = 36
$tabInboxRules.Controls.Add($pnlInboxRules)
$btnRefreshInboxRules = New-Object System.Windows.Forms.Button
$btnRefreshInboxRules.Text = 'Refresh Inbox Rules'
$btnRefreshInboxRules.Location = New-Object System.Drawing.Point(5, 4)
$btnRefreshInboxRules.Size = New-Object System.Drawing.Size(140, 26)
$pnlInboxRules.Controls.Add($btnRefreshInboxRules)
$pnlInboxRules.Controls.Add((New-Label 'Rows in red move/forward/redirect/delete mail - a classic compromise indicator.' 155 10 500))

$lvInboxRules = New-ListView $tabInboxRules @('Name', 'Enabled', 'Priority', 'Summary') @(180, 70, 60, 400)

# --- Sub-tab: Forwarding ---
$tabForwarding = New-Object System.Windows.Forms.TabPage
$tabForwarding.Text = 'Forwarding'
$tabsAudit.TabPages.Add($tabForwarding)

$pnlForwarding = New-Object System.Windows.Forms.Panel
$pnlForwarding.Dock = [System.Windows.Forms.DockStyle]::Top
$pnlForwarding.Height = 36
$tabForwarding.Controls.Add($pnlForwarding)
$btnCheckForwarding = New-Object System.Windows.Forms.Button
$btnCheckForwarding.Text = 'Check External Forwarding'
$btnCheckForwarding.Location = New-Object System.Drawing.Point(5, 4)
$btnCheckForwarding.Size = New-Object System.Drawing.Size(180, 26)
$pnlForwarding.Controls.Add($btnCheckForwarding)
$pnlForwarding.Controls.Add((New-Label 'Mailbox forwarding and forwarding / redirect inbox rules (hidden ones too). Red = leaves the tenant, or is hidden.' 195 10 520))

$lvForwarding = New-ListView $tabForwarding @('Type', 'Name', 'Target', 'External', 'Keeps copy', 'Hidden', 'Enabled', 'Detail') @(105, 140, 170, 60, 70, 55, 55, 300)

# --- Sub-tab: Message Trace ---
$tabMsgTrace = New-Object System.Windows.Forms.TabPage
$tabMsgTrace.Text = 'Message Trace'
$tabsAudit.TabPages.Add($tabMsgTrace)

$pnlMsgTrace = New-Object System.Windows.Forms.Panel
$pnlMsgTrace.Dock = [System.Windows.Forms.DockStyle]::Top
$pnlMsgTrace.Height = 40
$tabMsgTrace.Controls.Add($pnlMsgTrace)

$pnlMsgTrace.Controls.Add((New-Label 'From:' 5 10 40))
$dtpTraceStart = New-Object System.Windows.Forms.DateTimePicker
$dtpTraceStart.Location = New-Object System.Drawing.Point(45, 7)
$dtpTraceStart.Size = New-Object System.Drawing.Size(130, 20)
$dtpTraceStart.Format = [System.Windows.Forms.DateTimePickerFormat]::Short
$dtpTraceStart.Value = (Get-Date).AddDays(-7)
$pnlMsgTrace.Controls.Add($dtpTraceStart)

$pnlMsgTrace.Controls.Add((New-Label 'To:' 185 10 30))
$dtpTraceEnd = New-Object System.Windows.Forms.DateTimePicker
$dtpTraceEnd.Location = New-Object System.Drawing.Point(215, 7)
$dtpTraceEnd.Size = New-Object System.Drawing.Size(130, 20)
$dtpTraceEnd.Format = [System.Windows.Forms.DateTimePickerFormat]::Short
$dtpTraceEnd.Value = Get-Date
$pnlMsgTrace.Controls.Add($dtpTraceEnd)

$pnlMsgTrace.Controls.Add((New-Label 'Direction:' 355 10 60))
$cmbTraceDirection = New-Object System.Windows.Forms.ComboBox
$cmbTraceDirection.Location = New-Object System.Drawing.Point(415, 7)
$cmbTraceDirection.Size = New-Object System.Drawing.Size(90, 20)
$cmbTraceDirection.DropDownStyle = [System.Windows.Forms.ComboBoxStyle]::DropDownList
@('Both', 'Sent', 'Received') | ForEach-Object { $cmbTraceDirection.Items.Add($_) | Out-Null }
$cmbTraceDirection.SelectedItem = 'Both'
$pnlMsgTrace.Controls.Add($cmbTraceDirection)

$btnRunTrace = New-Object System.Windows.Forms.Button
$btnRunTrace.Text = 'Run Trace'
$btnRunTrace.Location = New-Object System.Drawing.Point(515, 5)
$btnRunTrace.Size = New-Object System.Drawing.Size(90, 26)
$pnlMsgTrace.Controls.Add($btnRunTrace)

$btnExportTrace = New-Object System.Windows.Forms.Button
$btnExportTrace.Text = 'Export to CSV...'
$btnExportTrace.Location = New-Object System.Drawing.Point(610, 5)
$btnExportTrace.Size = New-Object System.Drawing.Size(110, 26)
$btnExportTrace.Enabled = $false
$pnlMsgTrace.Controls.Add($btnExportTrace)

$lvMessageTrace = New-ListView $tabMsgTrace @('Received', 'Sender', 'Recipient', 'Subject', 'Status', 'Size') @(130, 170, 170, 200, 90, 70)

# ===========================================================================
# "Audit Tenant" tab contents
# ===========================================================================
# Tenant-wide checks and hardening actions (the Audit User tab covers single accounts). Each section
# has a Check button that only reads and, where there is a fix, a separate action button that asks
# for confirmation first. The sections sit in a scrolling panel because there are more than fit.
$pnlTenant = New-Object System.Windows.Forms.Panel
$pnlTenant.Dock = [System.Windows.Forms.DockStyle]::Fill
$pnlTenant.AutoScroll = $true
$tabAuditTenant.Controls.Add($pnlTenant)

# Run All sits above the sections and the findings report below them, both outside the scrolling area so
# they stay visible. The scrolling panel was added first, so it is laid out last and fills what is left.
$pnlTenantHeader = New-Object System.Windows.Forms.Panel
$pnlTenantHeader.Dock = [System.Windows.Forms.DockStyle]::Top
$pnlTenantHeader.Height = 44
$tabAuditTenant.Controls.Add($pnlTenantHeader)
$btnRunAll = New-Object System.Windows.Forms.Button
$btnRunAll.Text = 'Run All Checks'
$btnRunAll.Location = New-Object System.Drawing.Point(8, 8)
$btnRunAll.Size = New-Object System.Drawing.Size(150, 28)
$pnlTenantHeader.Controls.Add($btnRunAll)
$chkRunAllSlow = New-Object System.Windows.Forms.CheckBox
$chkRunAllSlow.Text = 'Include the slow scans (full user MFA report, every-mailbox inbox rule scan)'
$chkRunAllSlow.Checked = $true
$chkRunAllSlow.Location = New-Object System.Drawing.Point(170, 12)
$chkRunAllSlow.Size = New-Object System.Drawing.Size(540, 22)
$pnlTenantHeader.Controls.Add($chkRunAllSlow)

$pnlTenantFooter = New-Object System.Windows.Forms.Panel
$pnlTenantFooter.Dock = [System.Windows.Forms.DockStyle]::Bottom
$pnlTenantFooter.Height = 44
$tabAuditTenant.Controls.Add($pnlTenantFooter)
$btnExportReport = New-Object System.Windows.Forms.Button
$btnExportReport.Text = 'Export Findings Report...'
$btnExportReport.Location = New-Object System.Drawing.Point(8, 8)
$btnExportReport.Size = New-Object System.Drawing.Size(200, 28)
$pnlTenantFooter.Controls.Add($btnExportReport)
$pnlTenantFooter.Controls.Add((New-Label 'Text file: every check result below, plus every change made in this session.' 218 14 500))
$pnlTenant.BringToFront()

$script:TenantSectionTop = 5
$script:TenantColors = @{
    Good    = [System.Drawing.Color]::DarkGreen
    Bad     = [System.Drawing.Color]::Firebrick
    Warn    = [System.Drawing.Color]::DarkOrange
    Neutral = [System.Drawing.Color]::Gray
}

function New-TenantSection {
    param(
        [string]   $Title,
        [string[]] $Buttons,
        [string]   $Help,
        [int]      $Height = 120,
        [int]      $StateTop = 58
    )
    $top = $script:TenantSectionTop
    $grp = New-Object System.Windows.Forms.GroupBox
    $grp.Text = $Title
    $grp.Location = New-Object System.Drawing.Point(5, $top)
    $grp.Size = New-Object System.Drawing.Size(695, $Height)
    $pnlTenant.Controls.Add($grp)
    $script:TenantSectionTop = $top + $Height + 8

    $btns = @{}
    $x = 10
    foreach ($label in $Buttons) {
        $w = [int](20 + 6.5 * $label.Length)
        $b = New-Object System.Windows.Forms.Button
        $b.Text = $label
        $b.Location = New-Object System.Drawing.Point($x, 22)
        $b.Size = New-Object System.Drawing.Size($w, 28)
        $grp.Controls.Add($b)
        $btns[$label] = $b
        $x = $x + $w + 8
    }

    $state = New-Object System.Windows.Forms.Label
    $state.Text = 'Not checked yet.'
    $state.Font = New-Object System.Drawing.Font('Segoe UI', 10, [System.Drawing.FontStyle]::Bold)
    $state.ForeColor = $script:TenantColors.Neutral
    $state.Location = New-Object System.Drawing.Point(10, $StateTop)
    $state.Size = New-Object System.Drawing.Size(675, 22)
    $grp.Controls.Add($state)

    $detailTop = $StateTop + 24
    $detailHeight = $Height - $detailTop - 6
    $detail = New-Object System.Windows.Forms.TextBox
    $detail.Multiline = $true
    $detail.ReadOnly = $true
    $detail.TabStop = $false
    $detail.BorderStyle = [System.Windows.Forms.BorderStyle]::None
    $detail.BackColor = [System.Drawing.SystemColors]::Control
    $detail.ForeColor = [System.Drawing.Color]::DimGray
    $detail.ScrollBars = [System.Windows.Forms.ScrollBars]::Vertical
    $detail.Location = New-Object System.Drawing.Point(10, $detailTop)
    $detail.Size = New-Object System.Drawing.Size(675, $detailHeight)
    $detail.Text = $Help
    if (-not $Help) { $detail.Visible = $false }
    $grp.Controls.Add($detail)

    [pscustomobject]@{ Title = $Title; Group = $grp; Buttons = $btns; State = $state; Detail = $detail; Help = $Help }
}

function Set-TenantSection {
    param($Section, [string]$State, $Color, [string]$Detail)
    $Section.State.Text = $State
    $Section.State.ForeColor = $Color
    $detailForReport = $null
    if ($PSBoundParameters.ContainsKey('Detail')) { $Section.Detail.Text = $Detail; $detailForReport = $Detail }
    Register-Finding $Section $State $Color $detailForReport
}

$secOrg = New-TenantSection -Title 'Exchange Online - organization customization' `
    -Buttons @('Check', 'Enable Organization Customization') -Height 122 `
    -Help 'Many Exchange settings, including some of the changes on this tab, cannot be modified until the organization has been customized. Enabling it is a one-time, one-way change.'

$secSd = New-TenantSection -Title 'Security Defaults' -Buttons @('Check Security Defaults') -Height 132 `
    -Help 'Security Defaults is a free, tenant-wide baseline: every user must register for MFA, admins are always challenged, legacy (basic-auth) sign-in is blocked, and privileged actions require MFA. It cannot be used together with Conditional Access.'

$secUal = New-TenantSection -Title 'Unified audit log search' -Buttons @('Check', 'Enable Audit Log Search') -Height 122 `
    -Help 'Audit log search records user and admin activity across Microsoft 365. Without it an investigation has no activity trail. After enabling it can take up to 60 minutes before searches return data.'

$secDirect = New-TenantSection -Title 'Direct Send' -Buttons @('Check', 'Disable Direct Send') -Height 140 `
    -Help 'Direct Send lets devices and apps send mail to your own domain without authenticating, which also lets attackers spoof your domain. Disabling it rejects that unauthenticated mail. Scanners, printers and apps that rely on Direct Send will stop working unless they use authenticated SMTP or a mail flow connector.'

$secFwd = New-TenantSection -Title 'Forwarding to external domains' -Buttons @('Check', 'Disable External Forwarding') -Height 150 `
    -Help 'Blocks automatic forwarding of mail to external domains by setting AutoForwardingMode to Off on every outbound spam filter policy. Existing forwarding rules and mailbox forwards stay configured, but external delivery is blocked.'

$secPwd = New-TenantSection -Title 'Password expiration' -Buttons @('Check', 'Set Passwords to Never Expire') -Height 150 `
    -Help 'Sets the password validity period on each verified, managed domain to never expire (2147483647 days), which current Microsoft and CIS guidance recommends when MFA is in place. Federated domains are skipped; their password policy is managed on-premises.'

$secConsent = New-TenantSection -Title 'User consent to applications' -Buttons @('Check', 'Block User Consent + Enable Admin Requests') -Height 150 `
    -Help 'Stops users from granting consent to applications themselves, and turns on the admin consent workflow so users can submit a request that Global Administrators review and approve. The workflow is enabled first, so blocking consent never leaves users with no way to ask.'

$secMfa = New-TenantSection -Title 'MFA verification methods: call and push notification' -Buttons @('Check', 'Disable Selected Methods') -Height 178 -StateTop 84 `
    -Help 'Disables the selected methods in the authentication methods policy. Anyone whose only method is one of these will have to register another one, and the tool refuses to proceed if it would leave no MFA-capable method enabled at all.'
$chkDisableVoice = New-Object System.Windows.Forms.CheckBox
$chkDisableVoice.Text = 'Voice call'
$chkDisableVoice.Checked = $true
$chkDisableVoice.Location = New-Object System.Drawing.Point(10, 56)
$chkDisableVoice.Size = New-Object System.Drawing.Size(110, 22)
$secMfa.Group.Controls.Add($chkDisableVoice)
$chkDisablePush = New-Object System.Windows.Forms.CheckBox
$chkDisablePush.Text = 'Microsoft Authenticator (push notification)'
$chkDisablePush.Checked = $true
$chkDisablePush.Location = New-Object System.Drawing.Point(130, 56)
$chkDisablePush.Size = New-Object System.Drawing.Size(300, 22)
$secMfa.Group.Controls.Add($chkDisablePush)

$secAdmins = New-TenantSection -Title 'Accounts with admin privileges' -Buttons @('List Admin Accounts', 'Export CSV...') -Height 330 -Help ''
$lvAdmins = New-ListView $secAdmins.Group @('Name', 'User principal name', 'Enabled', 'Global admin', 'MFA', 'Licenses', 'Roles') @(105, 160, 50, 70, 130, 170, 280)
$lvAdmins.Dock = [System.Windows.Forms.DockStyle]::None
$lvAdmins.Location = New-Object System.Drawing.Point(10, 86)
$lvAdmins.Size = New-Object System.Drawing.Size(675, 232)
$secAdmins.Buttons['Export CSV...'].Enabled = $false
$script:LastAdminList = @()

$secMfaReport = New-TenantSection -Title 'Full user MFA report' -Buttons @('Run MFA Report', 'Export CSV...') -Height 430 -StateTop 84 -Help ''
$chkMfaDisabled = New-Object System.Windows.Forms.CheckBox
$chkMfaDisabled.Text = 'Include disabled accounts'
$chkMfaDisabled.Location = New-Object System.Drawing.Point(10, 56)
$chkMfaDisabled.Size = New-Object System.Drawing.Size(170, 22)
$secMfaReport.Group.Controls.Add($chkMfaDisabled)
$chkMfaGuests = New-Object System.Windows.Forms.CheckBox
$chkMfaGuests.Text = 'Include guests'
$chkMfaGuests.Location = New-Object System.Drawing.Point(190, 56)
$chkMfaGuests.Size = New-Object System.Drawing.Size(110, 22)
$secMfaReport.Group.Controls.Add($chkMfaGuests)
$chkMfaGapsOnly = New-Object System.Windows.Forms.CheckBox
$chkMfaGapsOnly.Text = 'Only show users that are not Protected'
$chkMfaGapsOnly.Location = New-Object System.Drawing.Point(310, 56)
$chkMfaGapsOnly.Size = New-Object System.Drawing.Size(280, 22)
$secMfaReport.Group.Controls.Add($chkMfaGapsOnly)
$lvMfaReport = New-ListView $secMfaReport.Group @('Name', 'User principal name', 'Status', 'Methods', 'Enforced by', 'Per-user MFA', 'Enabled', 'Type') @(110, 170, 170, 140, 150, 80, 55, 55)
$lvMfaReport.Dock = [System.Windows.Forms.DockStyle]::None
$lvMfaReport.Location = New-Object System.Drawing.Point(10, 112)
$lvMfaReport.Size = New-Object System.Drawing.Size(675, 306)
$secMfaReport.Buttons['Export CSV...'].Enabled = $false
$script:LastMfaReport = $null

$secConnectors = New-TenantSection -Title 'Exchange mail flow connectors' -Buttons @('List Connectors', 'Export CSV...') -Height 390 -Help ''
$lvConnectors = New-ListView $secConnectors.Group @('Direction', 'Name', 'Enabled', 'Type', 'Scope', 'Endpoints', 'TLS', 'Created', 'Flags') @(65, 150, 55, 110, 150, 170, 85, 80, 320)
$lvConnectors.Dock = [System.Windows.Forms.DockStyle]::None
$lvConnectors.Location = New-Object System.Drawing.Point(10, 86)
$lvConnectors.Size = New-Object System.Drawing.Size(675, 294)
$secConnectors.Buttons['Export CSV...'].Enabled = $false
$script:LastConnectors = @()

$secFwdUse = New-TenantSection -Title 'External forwarding in use (mailboxes and mail flow rules)' -Buttons @('Scan for External Forwarding', 'Export CSV...') -Height 380 -Help ''
$lvFwdUse = New-ListView $secFwdUse.Group @('Source', 'Name', 'Target', 'External', 'Keeps copy', 'Enabled', 'Detail') @(95, 170, 170, 60, 70, 55, 300)
$lvFwdUse.Dock = [System.Windows.Forms.DockStyle]::None
$lvFwdUse.Location = New-Object System.Drawing.Point(10, 86)
$lvFwdUse.Size = New-Object System.Drawing.Size(675, 284)
$secFwdUse.Buttons['Export CSV...'].Enabled = $false
$script:LastFwdUse = @()

$secInboxScan = New-TenantSection -Title 'Suspicious inbox rules (every mailbox)' -Buttons @('Scan All Mailboxes', 'Export CSV...') -Height 420 -StateTop 84 -Help ''
$chkScanShared = New-Object System.Windows.Forms.CheckBox
$chkScanShared.Text = 'Include shared mailboxes'
$chkScanShared.Location = New-Object System.Drawing.Point(10, 56)
$chkScanShared.Size = New-Object System.Drawing.Size(200, 22)
$secInboxScan.Group.Controls.Add($chkScanShared)
$lvInboxScan = New-ListView $secInboxScan.Group @('Mailbox', 'Rule', 'Severity', 'Findings', 'Hidden', 'Enabled') @(160, 130, 60, 340, 50, 55)
$lvInboxScan.Dock = [System.Windows.Forms.DockStyle]::None
$lvInboxScan.Location = New-Object System.Drawing.Point(10, 112)
$lvInboxScan.Size = New-Object System.Drawing.Size(675, 298)
$secInboxScan.Buttons['Export CSV...'].Enabled = $false
$script:LastInboxScan = @()

$secAttach = New-TenantSection -Title 'Common attachment filter (anti-malware policies)' -Buttons @('Check') -Height 175 `
    -Help 'The common attachments filter blocks messages that carry file types often used to deliver malware (.exe, .js, .vbs and so on), whatever the file really contains. It is on by default; this checks it is still on in every anti-malware policy and that the file-type list still covers the common risky types.'

$secDkim = New-TenantSection -Title 'DKIM signing' -Buttons @('Check') -Height 175 `
    -Help 'DKIM adds a signature to outgoing mail so receivers can prove it came from your domain. This checks that signing is enabled for every domain in the tenant and, for domains where it is off, whether the DNS records needed to turn it on are already published.'

$secMailAuth = New-TenantSection -Title 'SPF and DMARC' -Buttons @('Check', 'Export CSV...') -Height 400 -Help ''
$lvMailAuth = New-ListView $secMailAuth.Group @('Domain', 'SPF', 'Lookups', 'DMARC', 'Reports', 'Findings') @(150, 140, 60, 200, 60, 420)
$lvMailAuth.Dock = [System.Windows.Forms.DockStyle]::None
$lvMailAuth.Location = New-Object System.Drawing.Point(10, 86)
$lvMailAuth.Size = New-Object System.Drawing.Size(675, 304)
$secMailAuth.Buttons['Export CSV...'].Enabled = $false
$script:LastMailAuth = @()

# Every section, in screen order (for the findings report), and every check Run All Checks clicks, fast ones
# first. Slow = opens every mailbox / every user.
$script:TenantSectionList = @($secOrg, $secSd, $secUal, $secDirect, $secFwd, $secPwd, $secConsent, $secMfa, $secAdmins, $secMfaReport,
    $secConnectors, $secFwdUse, $secInboxScan, $secAttach, $secDkim, $secMailAuth)
function New-CheckEntry($Section, [string]$ButtonLabel, [bool]$Slow) {
    [pscustomobject]@{ Section = $Section; Button = $Section.Buttons[$ButtonLabel]; Slow = $Slow }
}
$script:TenantCheckList = @(
    (New-CheckEntry $secOrg 'Check' $false),
    (New-CheckEntry $secSd 'Check Security Defaults' $false),
    (New-CheckEntry $secUal 'Check' $false),
    (New-CheckEntry $secDirect 'Check' $false),
    (New-CheckEntry $secFwd 'Check' $false),
    (New-CheckEntry $secPwd 'Check' $false),
    (New-CheckEntry $secConsent 'Check' $false),
    (New-CheckEntry $secMfa 'Check' $false),
    (New-CheckEntry $secAdmins 'List Admin Accounts' $false),
    (New-CheckEntry $secConnectors 'List Connectors' $false),
    (New-CheckEntry $secFwdUse 'Scan for External Forwarding' $false),
    (New-CheckEntry $secAttach 'Check' $false),
    (New-CheckEntry $secDkim 'Check' $false),
    (New-CheckEntry $secMailAuth 'Check' $false),
    (New-CheckEntry $secMfaReport 'Run MFA Report' $true),
    (New-CheckEntry $secInboxScan 'Scan All Mailboxes' $true))

# ---------------------------------------------------------------------------
# Behavior - shared / New User
# ---------------------------------------------------------------------------
$chkShowPassword.add_CheckedChanged({
    $txtPassword.UseSystemPasswordChar = -not $chkShowPassword.Checked
    $txtPasswordConfirm.UseSystemPasswordChar = -not $chkShowPassword.Checked
})

$chkConvertShared.add_CheckedChanged({ $txtGrantAccessTo.Enabled = $chkConvertShared.Checked })

$script:userEditedDisplayName = $false
$script:userEditedUpn = $false
$txtDisplayName.add_TextChanged({ $script:userEditedDisplayName = $true })
$cmbUpn.add_TextChanged({ $script:userEditedUpn = $true })

function Update-Suggestions {
    if (-not $script:Connected) { return }
    $first = $txtFirst.Text.Trim()
    $last  = $txtLast.Text.Trim()
    if (-not $first -or -not $last) { return }

    if (-not $script:userEditedDisplayName -or [string]::IsNullOrWhiteSpace($txtDisplayName.Text)) {
        $script:userEditedDisplayName = $false
        $txtDisplayName.Text = "$first $last"
        $script:userEditedDisplayName = $false
    }

    if (-not $script:userEditedUpn) {
        $suggestions = Get-NamingConventionSuggestions -ExistingUsers $script:ExistingUsers -FirstName $first -LastName $last
        $cmbUpn.Items.Clear()
        foreach ($s in $suggestions) { $cmbUpn.Items.Add($s.Upn) | Out-Null }
        if ($cmbUpn.Items.Count -gt 0) {
            $script:userEditedUpn = $false
            $cmbUpn.Text = $cmbUpn.Items[0]
            $script:userEditedUpn = $false
        }
    }
}
$txtFirst.add_TextChanged({ Update-Suggestions })
$txtLast.add_TextChanged({ Update-Suggestions })

# ---------------------------------------------------------------------------
# On-demand tenant data
# ---------------------------------------------------------------------------
# Nothing is loaded when you connect. The user list (pickers, naming suggestions) and the licenses /
# groups / Teams / distribution lists / shared mailboxes (New User, Offboard) can each take a while on a
# big tenant, so each is loaded the first time something needs it: opening the Offboard or Audit User
# tab, starting to type a name, opening the New User lists, or the Load Tenant Data button.
function Update-LoadedHint {
    if (-not $script:Connected) { $lblLoadHint.Text = 'Connect to a tenant first.'; return }
    $parts = @()
    if ($script:UsersLoaded) { $parts += "$($script:ExistingUsers.Count) users" }
    if ($script:ListsLoaded) {
        $parts += "$($script:Licenses.Count) license SKUs, $($script:SecurityGroups.Count) security groups, $($script:Teams.Count) Teams, $($script:DistLists.Count) distribution lists, $($script:SharedMailboxes.Count) shared mailboxes"
    }
    if ($parts.Count -eq 0) {
        $lblLoadHint.Text = 'Nothing is loaded yet. Tenant data loads when needed: click to load it now, or just start typing a name.'
    }
    else { $lblLoadHint.Text = 'Loaded: ' + ($parts -join '; ') + '.' }
}

function Update-TenantUsers {
    param([switch] $Force)
    if (-not $script:Connected) { return }
    if ($script:UsersLoaded -and -not $Force) { return }
    try {
        $users = @(Invoke-Worker -Status 'Loading users' -Cancellable { Get-TenantExistingUsers })
    }
    catch {
        $txtLog.Text = "Users could not be loaded: $($_.Exception.Message)"
        return
    }
    $script:ExistingUsers = $users
    $cmbOffboardUser.Items.Clear()
    $cmbAuditUser.Items.Clear()
    foreach ($u in $users) {
        $wrapped = [pscustomobject]@{ Label = "$($u.DisplayName) <$($u.UserPrincipalName)>"; User = $u }
        $cmbOffboardUser.Items.Add($wrapped) | Out-Null
        $cmbAuditUser.Items.Add($wrapped) | Out-Null
    }
    $script:UsersLoaded = $true
    Update-LoadedHint
}

function Update-TenantLists {
    param([switch] $Force)
    if (-not $script:Connected) { return }
    if ($script:ListsLoaded -and -not $Force) { return }
    $script:LoadWarnings = @()

    # Loads one list; a failure in one list is reported but doesn't abort the rest.
    $loadStep = {
        param([string]$Label, [string]$Command)
        try {
            return @(Invoke-Worker -Status "Loading $Label" -Cancellable -ArgumentList @($Command) { param($cmd) & $cmd })
        }
        catch {
            if ($_.Exception.Message -match '^(Cancelled|Window closed|Timed out)') { throw }
            $script:LoadWarnings += "${Label}: $($_.Exception.Message)"
            return @()
        }
    }

    try {
        $licenses = @(& $loadStep 'licenses' 'Get-TenantLicenses')
        $groups = @(& $loadStep 'security groups' 'Get-TenantSecurityGroups')
        $teams = @(& $loadStep 'Teams' 'Get-TenantTeams')
        $dls = @(& $loadStep 'distribution lists' 'Get-TenantDistributionLists')
        $mailboxes = @(& $loadStep 'shared mailboxes' 'Get-TenantSharedMailboxes')
    }
    catch {
        $txtLog.Text = 'Loading tenant lists was cancelled.'
        return
    }
    $script:Licenses = $licenses
    $script:SecurityGroups = $groups
    $script:Teams = $teams
    $script:DistLists = $dls
    $script:SharedMailboxes = $mailboxes

    $clbLicenses.Items.Clear()
    foreach ($l in $script:Licenses) {
        $l | Add-Member -NotePropertyName Label -NotePropertyValue "$($l.FriendlyName)  ($($l.Available) of $($l.Total) available)" -Force
        $clbLicenses.Items.Add($l) | Out-Null
    }
    $clbSecGroups.Items.Clear()
    foreach ($g in $script:SecurityGroups) {
        $g | Add-Member -NotePropertyName Label -NotePropertyValue $g.DisplayName -Force
        $clbSecGroups.Items.Add($g) | Out-Null
    }
    $clbTeams.Items.Clear()
    foreach ($t in $script:Teams) {
        $t | Add-Member -NotePropertyName Label -NotePropertyValue $t.DisplayName -Force
        $clbTeams.Items.Add($t) | Out-Null
    }
    $clbDls.Items.Clear()
    foreach ($d in $script:DistLists) {
        $d | Add-Member -NotePropertyName Label -NotePropertyValue "$($d.DisplayName) <$($d.PrimarySmtpAddress)>" -Force
        $clbDls.Items.Add($d) | Out-Null
    }
    $clbMailboxes.Items.Clear()
    foreach ($m in $script:SharedMailboxes) {
        $m | Add-Member -NotePropertyName Label -NotePropertyValue "$($m.DisplayName) <$($m.PrimarySmtpAddress)>" -Force
        $clbMailboxes.Items.Add($m) | Out-Null
    }

    $script:ListsLoaded = $true
    Update-LoadedHint
    if ($script:LoadWarnings.Count -gt 0) {
        $txtLog.Text = "Some tenant data could not be loaded:`r`n" + ($script:LoadWarnings -join "`r`n")
    }
}

# Loads whatever the tab being shown needs; the New User tab loads on first use instead (see below).
function Invoke-TabDataLoad {
    if (-not $script:Connected) { return }
    $selected = $outerTabs.SelectedTab
    if ($selected -eq $tabOffboard) { Update-TenantUsers; Update-TenantLists }
    elseif ($selected -eq $tabAudit) { Update-TenantUsers }
}
$outerTabs.add_SelectedIndexChanged({ Invoke-TabDataLoad })

$btnLoadTenantData.add_Click({
    Update-TenantUsers -Force
    Update-TenantLists -Force
    Update-Suggestions
})
# Focusing a name box loads the user list for the naming suggestions; focus goes back once it's loaded.
$txtFirst.add_Enter({
    if ($script:Connected -and -not $script:UsersLoaded) { Update-TenantUsers; [void]$txtFirst.Focus(); Update-Suggestions }
})
$txtLast.add_Enter({
    if ($script:Connected -and -not $script:UsersLoaded) { Update-TenantUsers; [void]$txtLast.Focus(); Update-Suggestions }
})
$tabsNewUser.add_SelectedIndexChanged({
    if ($script:Connected -and -not $script:ListsLoaded) { Update-TenantLists }
})

$btnConnect.add_Click({
    $btnConnect.Enabled = $false
    $lblStatus.ForeColor = [System.Drawing.Color]::DimGray
    $scopes = @('User.ReadWrite.All', 'Group.ReadWrite.All', 'Organization.Read.All', 'Directory.ReadWrite.All',
                'AuditLog.Read.All', 'Reports.Read.All', 'UserAuthenticationMethod.ReadWrite.All', 'Policy.Read.All', 'Policy.ReadWrite.AuthenticationMethod',
                'RoleManagement.Read.Directory', 'Domain.ReadWrite.All', 'Policy.ReadWrite.Authorization', 'Policy.ReadWrite.ConsentRequest')

    try {
        # The sign-in window (Windows account broker or browser) can open behind this window or the
        # editor running the script, so say where to look instead of letting it seem hung.
        Invoke-Worker -Status 'Microsoft Graph sign-in: finish in the sign-in window (check the taskbar if you do not see it)' -Cancellable -TimeoutSeconds 300 -ArgumentList @(, $scopes) {
            param($scopes)
            Connect-MgGraph -Scopes $scopes -NoWelcome | Out-Null
        } | Out-Null
        $script:HasSession = $true

        Invoke-Worker -Status 'Exchange Online sign-in: finish in the sign-in window (check the taskbar if you do not see it)' -Cancellable -TimeoutSeconds 300 {
            $p = @{ ShowBanner = $false }
            # WAM needs a parent window handle that GUI/ISE hosts do not provide; the browser path does not.
            if ((Get-Command Connect-ExchangeOnline).Parameters.ContainsKey('DisableWAM')) { $p['DisableWAM'] = $true }
            Connect-ExchangeOnline @p
        } | Out-Null

        $form.Activate()
        $info = Invoke-Worker -Status 'Verifying connection' { $c = Get-MgContext; "$($c.Account)|$($c.TenantId)" }
        $parts = "$info".Split('|')
        $account = $parts[0]

        # Reconnecting may mean a different tenant: drop whatever the previous connection left behind.
        if ($script:Connected) { Reset-TenantUi }
        $script:HasSession = $true
        $script:Connected = $true
        $script:ConnectedAccount = $account
        $script:ConnectedTenantId = ''
        if ($parts.Count -gt 1) { $script:ConnectedTenantId = $parts[1] }
        $btnCreate.Enabled = $true
        $btnDisconnect.Enabled = $true
        $lblStatus.Text = "Connected as $account. Tenant data is loaded when a tab needs it; nothing has been loaded yet."
        $lblStatus.ForeColor = [System.Drawing.Color]::DarkGreen
        Update-LoadedHint

        # Only if a tab that needs data is already showing (Offboard / Audit User): its picker would be empty.
        Invoke-TabDataLoad
    }
    catch {
        $msg = $_.Exception.Message
        if ($msg -match 'window handle') {
            $msg += ' (Update the module that raised this: Update-Module Microsoft.Graph.Authentication, ExchangeOnlineManagement - then restart PowerShell.)'
        }
        $lblStatus.Text = "Connection failed: $msg"
        $lblStatus.ForeColor = [System.Drawing.Color]::DarkRed
        $txtLog.Text = "Connection failed: $msg"
    }
    finally {
        $btnConnect.Enabled = $true
        $btnDisconnect.Enabled = [bool]$script:HasSession
    }
})

# Puts every screen back to its "not connected" state and drops the cached tenant data.
function Reset-TenantUi {
    $script:Connected = $false
    $script:HasSession = $false
    $script:UsersLoaded = $false
    $script:ListsLoaded = $false
    Update-LoadedHint
    $script:ExistingUsers = @(); $script:Licenses = @(); $script:SecurityGroups = @()
    $script:Teams = @(); $script:DistLists = @(); $script:SharedMailboxes = @()

    foreach ($clb in @($clbLicenses, $clbSecGroups, $clbTeams, $clbDls, $clbMailboxes, $clbOffLicenses, $clbOffSecGroups, $clbOffTeams, $clbOffDls, $clbOffMailboxes)) { $clb.Items.Clear() }
    foreach ($cmb in @($cmbOffboardUser, $cmbAuditUser)) { $cmb.Items.Clear(); $cmb.Text = '' }
    $cmbUpn.Items.Clear()
    $btnCreate.Enabled = $false
    $btnOffboard.Enabled = $false
    $lblOffboardHint.Text = 'Pick a user to load their current memberships.'
    $lblOffboardHint.ForeColor = [System.Drawing.Color]::Gray
    $lblAuditHint.Text = 'Pick a user, then use each sub-tab to pull that data on demand.'
    $lblAuditHint.ForeColor = [System.Drawing.Color]::Gray

    foreach ($lv in @($lvSignIns, $lvAuditEvents, $lvDevices, $lvInboxRules, $lvMessageTrace, $lvAdmins, $lvMfaReport, $lvConnectors, $lvForwarding, $lvFwdUse, $lvInboxScan, $lvMailAuth)) { $lv.Items.Clear() }
    $btnExportTrace.Enabled = $false
    $secAdmins.Buttons['Export CSV...'].Enabled = $false
    $secMfaReport.Buttons['Export CSV...'].Enabled = $false
    $secConnectors.Buttons['Export CSV...'].Enabled = $false
    $script:LastConnectors = @()
    foreach ($sec in @($secFwdUse, $secInboxScan, $secMailAuth)) { $sec.Buttons['Export CSV...'].Enabled = $false }
    $script:LastFwdUse = @(); $script:LastInboxScan = @(); $script:LastMailAuth = @()
    $script:LastMessageTraceResults = @()
    $script:LastAdminList = @()
    $script:LastMfaReport = $null
    $script:SelectedAuditUser = $null

    foreach ($s in @($secOrg, $secSd, $secUal, $secDirect, $secFwd, $secPwd, $secConsent, $secMfa, $secAdmins, $secMfaReport, $secConnectors, $secFwdUse, $secInboxScan, $secAttach, $secDkim, $secMailAuth)) {
        Set-TenantSection $s 'Not checked yet.' $script:TenantColors.Neutral $s.Help
    }
}

$btnDisconnect.add_Click({
    try {
        Invoke-Worker -Status 'Disconnecting' -Cancellable -ScriptBlock {
            try { Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue } catch {}
            try { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null } catch {}
        } | Out-Null
    }
    catch { }

    # Drop the worker runspace as well, so the Exchange session is discarded outright; the next
    # Connect builds a fresh one.
    if ($script:WorkerRunspace -and -not $script:WorkerBusy) {
        $rs = $script:WorkerRunspace
        $script:WorkerRunspace = $null
        try { $rs.Close() } catch { }
    }

    Reset-TenantUi
    $btnDisconnect.Enabled = $false
    $lblStatus.Text = 'Not connected.'
    $lblStatus.ForeColor = [System.Drawing.Color]::DarkRed
    $txtLog.Text = 'Disconnected from Microsoft Graph and Exchange Online. The tenant data held by this window was cleared.'
})

$btnCreate.add_Click({
    $first = $txtFirst.Text.Trim()
    $last  = $txtLast.Text.Trim()
    $displayName = $txtDisplayName.Text.Trim()
    $upn = $cmbUpn.Text.Trim()
    $password = $txtPassword.Text
    $passwordConfirm = $txtPasswordConfirm.Text
    $usageLocation = $txtUsageLocation.Text.Trim()

    if (-not $first -or -not $last -or -not $displayName -or -not $upn) {
        [System.Windows.Forms.MessageBox]::Show('First name, last name, display name, and UPN are all required.', 'Missing Information', 'OK', 'Warning') | Out-Null
        return
    }
    if ($password -ne $passwordConfirm) {
        [System.Windows.Forms.MessageBox]::Show('Password and confirmation do not match.', 'Password Mismatch', 'OK', 'Warning') | Out-Null
        return
    }
    $strength = Test-PasswordStrength -Password $password
    if (-not $strength.IsStrong) {
        $msg = "Password does not meet the recommended policy:`n- " + ($strength.Issues -join "`n- ") + "`n`nCreate anyway?"
        $choice = [System.Windows.Forms.MessageBox]::Show($msg, 'Weak Password', [System.Windows.Forms.MessageBoxButtons]::YesNo, [System.Windows.Forms.MessageBoxIcon]::Warning)
        if ($choice -ne [System.Windows.Forms.DialogResult]::Yes) { return }
    }

    $selectedLicenses = @($clbLicenses.CheckedItems | ForEach-Object { $_.SkuId })
    $selectedSecGroups = @($clbSecGroups.CheckedItems | ForEach-Object { $_.Id })
    $selectedTeams = @($clbTeams.CheckedItems | ForEach-Object { $_.Id })
    $selectedDls = @($clbDls.CheckedItems | ForEach-Object { $_.PrimarySmtpAddress })
    $selectedMailboxes = @($clbMailboxes.CheckedItems | ForEach-Object {
        [pscustomobject]@{ Identity = $_.PrimarySmtpAddress; AccessRights = @('FullAccess','SendAs') }
    })

    $summary = "Create user:`n  $displayName <$upn>`n`nLicenses: $($selectedLicenses.Count)`nSecurity Groups: $($selectedSecGroups.Count)`nTeams: $($selectedTeams.Count)`nDistribution Lists: $($selectedDls.Count)`nShared Mailboxes: $($selectedMailboxes.Count)`n`nProceed?"
    $confirm = [System.Windows.Forms.MessageBox]::Show($summary, 'Confirm', [System.Windows.Forms.MessageBoxButtons]::YesNo, [System.Windows.Forms.MessageBoxIcon]::Question)
    if ($confirm -ne [System.Windows.Forms.DialogResult]::Yes) { return }

    $btnCreate.Enabled = $false
    try {
        $createArgs = @{
            FirstName                  = $first
            LastName                   = $last
            DisplayName                = $displayName
            UserPrincipalName          = $upn
            Password                   = $password
            UsageLocation              = $usageLocation
            LicenseSkuIds              = $selectedLicenses
            SecurityGroupIds           = $selectedSecGroups
            TeamGroupIds               = $selectedTeams
            DistributionListIdentities = $selectedDls
            SharedMailboxAssignments   = $selectedMailboxes
        }
        $result = Invoke-Worker -Status "Creating $upn" -ArgumentList @($createArgs) { param($a) New-O365UserAccount @a }

        $lines = @()
        $lines += "User created: $($result.UserCreated)  (Id: $($result.UserId))"
        $lines += "Licenses assigned: $($result.LicenseAssigned.Count) / failed: $($result.LicenseFailed.Count)"
        $lines += "Groups added: $($result.GroupsAdded.Count) / failed: $($result.GroupsFailed.Count)"
        $lines += "DLs added: $($result.DlsAdded.Count) / failed: $($result.DlsFailed.Count)"
        $lines += "Mailbox perms granted: $($result.MailboxesGranted.Count) / failed: $($result.MailboxesFailed.Count)"
        if ($result.Errors.Count -gt 0) {
            $lines += ''
            $lines += 'Errors:'
            $lines += $result.Errors
        }
        $txtLog.Text = $lines -join "`r`n"

        Add-ChangeRecord -Area 'New User' -Title "Create user $upn" -Success ([bool]($result.UserCreated -and $result.Errors.Count -eq 0)) -Lines $lines
        if ($result.UserCreated -and $result.Errors.Count -eq 0) {
            [System.Windows.Forms.MessageBox]::Show("User $upn created successfully with all requested assignments.", 'Success', 'OK', 'Information') | Out-Null
        } else {
            [System.Windows.Forms.MessageBox]::Show("User creation completed with issues. See the log panel for details.", 'Completed With Errors', 'OK', 'Warning') | Out-Null
        }

        # Clear the password fields immediately after use
        $txtPassword.Text = ''
        $txtPasswordConfirm.Text = ''
    }
    catch {
        [System.Windows.Forms.MessageBox]::Show("Unexpected failure: $($_.Exception.Message)", 'Error', 'OK', 'Error') | Out-Null
    }
    finally {
        $form.Cursor = [System.Windows.Forms.Cursors]::Default
        $btnCreate.Enabled = $true
    }
})

# ---------------------------------------------------------------------------
# Behavior - Offboard User
# ---------------------------------------------------------------------------
$cmbOffboardUser.add_SelectedIndexChanged({
    if ($null -eq $cmbOffboardUser.SelectedItem) { return }
    $selectedUser = $cmbOffboardUser.SelectedItem.User

    $btnOffboard.Enabled = $false
    $lblOffboardHint.Text = 'Loading current memberships...'
    $lblOffboardHint.ForeColor = [System.Drawing.Color]::Gray
    $lblOffboardHint.Refresh()
    try {
        $ctxArgs = @{
            UserId                     = $selectedUser.Id
            UserPrincipalName          = $selectedUser.UserPrincipalName
            CandidateSecurityGroups    = $script:SecurityGroups
            CandidateTeams             = $script:Teams
            CandidateDistributionLists = $script:DistLists
            CandidateSharedMailboxes   = $script:SharedMailboxes
        }
        $ctx = Invoke-Worker -Status "Loading memberships for $($selectedUser.UserPrincipalName)" -Cancellable -ArgumentList @($ctxArgs) { param($a) Get-UserOffboardContext @a }

        $clbOffLicenses.Items.Clear()
        foreach ($l in $ctx.Licenses) {
            $skuInfo = $script:Licenses | Where-Object { $_.SkuId -eq $l.SkuId } | Select-Object -First 1
            $friendly = if ($skuInfo) { $skuInfo.FriendlyName } else { $l.SkuPartNumber }
            $wrapped = [pscustomobject]@{ Label = $friendly; SkuId = $l.SkuId }
            $clbOffLicenses.Items.Add($wrapped) | Out-Null
        }
        Set-AllChecked $clbOffLicenses $true

        $clbOffSecGroups.Items.Clear()
        foreach ($g in $ctx.SecurityGroups) {
            $g | Add-Member -NotePropertyName Label -NotePropertyValue $g.DisplayName -Force
            $clbOffSecGroups.Items.Add($g) | Out-Null
        }
        Set-AllChecked $clbOffSecGroups $true

        $clbOffTeams.Items.Clear()
        foreach ($t in $ctx.Teams) {
            $t | Add-Member -NotePropertyName Label -NotePropertyValue $t.DisplayName -Force
            $clbOffTeams.Items.Add($t) | Out-Null
        }
        Set-AllChecked $clbOffTeams $true

        $clbOffDls.Items.Clear()
        foreach ($d in $ctx.DistributionLists) {
            $d | Add-Member -NotePropertyName Label -NotePropertyValue "$($d.DisplayName) <$($d.PrimarySmtpAddress)>" -Force
            $clbOffDls.Items.Add($d) | Out-Null
        }
        Set-AllChecked $clbOffDls $true

        $clbOffMailboxes.Items.Clear()
        foreach ($m in $ctx.SharedMailboxAccess) {
            $m | Add-Member -NotePropertyName Label -NotePropertyValue "$($m.DisplayName) <$($m.PrimarySmtpAddress)> ($($m.AccessRights -join ', '))" -Force
            $clbOffMailboxes.Items.Add($m) | Out-Null
        }
        Set-AllChecked $clbOffMailboxes $true

        $lblOffboardHint.Text = 'Loaded. Uncheck anything this user should KEEP.'
        $lblOffboardHint.ForeColor = [System.Drawing.Color]::DarkGreen
        $btnOffboard.Enabled = $true
    }
    catch {
        $lblOffboardHint.Text = "Failed to load memberships: $($_.Exception.Message)"
        $lblOffboardHint.ForeColor = [System.Drawing.Color]::DarkRed
    }
    finally {
        $form.Cursor = [System.Windows.Forms.Cursors]::Default
    }
})

$btnOffboard.add_Click({
    if ($null -eq $cmbOffboardUser.SelectedItem) { return }
    $selectedUser = $cmbOffboardUser.SelectedItem.User

    $selectedLicenses = @($clbOffLicenses.CheckedItems | ForEach-Object { $_.SkuId })
    $selectedGroups = @($clbOffSecGroups.CheckedItems | ForEach-Object { $_.Id }) + @($clbOffTeams.CheckedItems | ForEach-Object { $_.Id })
    $selectedDls = @($clbOffDls.CheckedItems | ForEach-Object { $_.PrimarySmtpAddress })
    $selectedMailboxes = @($clbOffMailboxes.CheckedItems | ForEach-Object {
        [pscustomobject]@{ Identity = $_.PrimarySmtpAddress; AccessRights = $_.AccessRights }
    })

    $convertShared = $chkConvertShared.Checked
    $grantTo = $txtGrantAccessTo.Text.Trim()

    $summary = "Offboard user:`n  $($selectedUser.DisplayName) <$($selectedUser.UserPrincipalName)>`n`n" +
        "Disable account: $($chkDisableAccount.Checked)`n" +
        "Revoke sign-in sessions: $($chkRevokeSessions.Checked)`n" +
        "Licenses to remove: $($selectedLicenses.Count)`n" +
        "Groups/Teams to remove: $($selectedGroups.Count)`n" +
        "Distribution lists to remove: $($selectedDls.Count)`n" +
        "Shared mailbox access to remove: $($selectedMailboxes.Count)`n" +
        "Convert mailbox to shared: $convertShared" +
        $(if ($convertShared -and $grantTo) { "`nGrant mailbox access to: $grantTo" } else { '' }) +
        "`n`nThis directly modifies a real account. Proceed?"

    $confirm = [System.Windows.Forms.MessageBox]::Show($summary, 'Confirm Offboard', [System.Windows.Forms.MessageBoxButtons]::YesNo, [System.Windows.Forms.MessageBoxIcon]::Warning)
    if ($confirm -ne [System.Windows.Forms.DialogResult]::Yes) { return }

    $btnOffboard.Enabled = $false
    try {
        $offboardArgs = @{
            UserId                             = $selectedUser.Id
            UserPrincipalName                  = $selectedUser.UserPrincipalName
            DisableAccount                     = [bool]$chkDisableAccount.Checked
            RevokeSessions                     = [bool]$chkRevokeSessions.Checked
            LicenseSkuIdsToRemove              = $selectedLicenses
            GroupIdsToRemove                   = $selectedGroups
            DistributionListIdentitiesToRemove = $selectedDls
            SharedMailboxAccessToRemove        = $selectedMailboxes
            ConvertMailboxToShared             = [bool]$convertShared
            GrantMailboxAccessTo               = $grantTo
        }
        $result = Invoke-Worker -Status "Offboarding $($selectedUser.UserPrincipalName)" -ArgumentList @($offboardArgs) { param($a) Remove-O365UserAccount @a }

        $lines = @()
        $lines += "Account disabled: $($result.AccountDisabled)"
        $lines += "Sessions revoked: $($result.SessionsRevoked)"
        $lines += "Licenses removed: $($result.LicensesRemoved.Count) / failed: $($result.LicensesFailed.Count)"
        $lines += "Groups removed: $($result.GroupsRemoved.Count) / failed: $($result.GroupsFailed.Count)"
        $lines += "DLs removed: $($result.DlsRemoved.Count) / failed: $($result.DlsFailed.Count)"
        $lines += "Mailbox access removed: $($result.MailboxAccessRemoved.Count) / failed: $($result.MailboxAccessFailed.Count)"
        $lines += "Mailbox converted to shared: $($result.MailboxConverted)"
        if ($result.Errors.Count -gt 0) {
            $lines += ''
            $lines += 'Errors:'
            $lines += $result.Errors
        }
        $txtLog.Text = $lines -join "`r`n"

        Add-ChangeRecord -Area 'Offboard User' -Title "Offboard $($selectedUser.UserPrincipalName)" -Success ($result.Errors.Count -eq 0) -Lines $lines
        if ($result.Errors.Count -eq 0) {
            [System.Windows.Forms.MessageBox]::Show("$($selectedUser.UserPrincipalName) offboarded successfully.", 'Success', 'OK', 'Information') | Out-Null
        } else {
            [System.Windows.Forms.MessageBox]::Show("Offboarding completed with issues. See the log panel for details.", 'Completed With Errors', 'OK', 'Warning') | Out-Null
        }
    }
    catch {
        [System.Windows.Forms.MessageBox]::Show("Unexpected failure: $($_.Exception.Message)", 'Error', 'OK', 'Error') | Out-Null
    }
    finally {
        $form.Cursor = [System.Windows.Forms.Cursors]::Default
        $btnOffboard.Enabled = $true
    }
})

# ---------------------------------------------------------------------------
# Behavior - Audit User
# ---------------------------------------------------------------------------
function Get-RequiredAuditUser {
    if ($null -eq $cmbAuditUser.SelectedItem) {
        [System.Windows.Forms.MessageBox]::Show('Pick a user first.', 'No User Selected', 'OK', 'Warning') | Out-Null
        return $null
    }
    return $cmbAuditUser.SelectedItem.User
}

$cmbAuditUser.add_SelectedIndexChanged({
    if ($null -eq $cmbAuditUser.SelectedItem) { return }
    $script:SelectedAuditUser = $cmbAuditUser.SelectedItem.User
    $lblAuditHint.Text = "Selected: $($script:SelectedAuditUser.UserPrincipalName)"
    $lblAuditHint.ForeColor = [System.Drawing.Color]::DarkGreen
    $lvSignIns.Items.Clear()
    $lvAuditEvents.Items.Clear()
    $lvDevices.Items.Clear()
    $lvInboxRules.Items.Clear()
    $lvForwarding.Items.Clear()
    $lvMessageTrace.Items.Clear()
    $btnExportTrace.Enabled = $false
    $script:LastMessageTraceResults = @()
})

$btnRefreshSignIns.add_Click({
    $user = Get-RequiredAuditUser
    if (-not $user) { return }
    $form.Cursor = [System.Windows.Forms.Cursors]::WaitCursor
    try {
        $rows = @(Invoke-Worker -Status 'Loading sign-ins' -Cancellable -ArgumentList @($user.Id, [int]$cmbSignInTop.SelectedItem) { param($id, $top) Get-UserSignInActivity -UserId $id -Top $top })
        Set-ListViewRows $lvSignIns $rows @('CreatedDateTime', 'AppDisplayName', 'IpAddress', 'Location', 'Status', 'MfaResult', 'ClientAppUsed')
        $txtLog.Text = "Loaded $($rows.Count) sign-in event(s) for $($user.UserPrincipalName)."
    }
    catch {
        [System.Windows.Forms.MessageBox]::Show("Failed to load sign-ins: $($_.Exception.Message)", 'Error', 'OK', 'Error') | Out-Null
    }
    finally { $form.Cursor = [System.Windows.Forms.Cursors]::Default }
})

$btnRefreshAuditLog.add_Click({
    $user = Get-RequiredAuditUser
    if (-not $user) { return }
    $form.Cursor = [System.Windows.Forms.Cursors]::WaitCursor
    try {
        $rows = @(Invoke-Worker -Status 'Loading directory audit log' -Cancellable -ArgumentList @($user.Id, [int]$cmbAuditLogTop.SelectedItem) { param($id, $top) Get-UserDirectoryAuditActivity -UserId $id -Top $top })
        Set-ListViewRows $lvAuditEvents $rows @('ActivityDateTime', 'ActivityDisplayName', 'InitiatedBy', 'Result')
        $txtLog.Text = "Loaded $($rows.Count) directory audit event(s) targeting $($user.UserPrincipalName)."
    }
    catch {
        [System.Windows.Forms.MessageBox]::Show("Failed to load directory audit log: $($_.Exception.Message)", 'Error', 'OK', 'Error') | Out-Null
    }
    finally { $form.Cursor = [System.Windows.Forms.Cursors]::Default }
})

$btnRefreshDevices.add_Click({
    $user = Get-RequiredAuditUser
    if (-not $user) { return }
    $form.Cursor = [System.Windows.Forms.Cursors]::WaitCursor
    try {
        $rows = @(Invoke-Worker -Status 'Loading registered devices' -Cancellable -ArgumentList @($user.Id) { param($id) Get-UserRegisteredDevicesSorted -UserId $id })
        Set-ListViewRows $lvDevices $rows @('DisplayName', 'OperatingSystem', 'TrustType', 'IsManaged', 'IsCompliant', 'LastSignIn')
        $txtLog.Text = "Loaded $($rows.Count) registered device(s) for $($user.UserPrincipalName), sorted by most recent sign-in."
    }
    catch {
        [System.Windows.Forms.MessageBox]::Show("Failed to load devices: $($_.Exception.Message)", 'Error', 'OK', 'Error') | Out-Null
    }
    finally { $form.Cursor = [System.Windows.Forms.Cursors]::Default }
})

$btnGeneratePassword.add_Click({
    $txtIncidentPassword.Text = New-SecureRandomPassword -Length 16
    $chkShowIncidentPassword.Checked = $true
})

$btnCopyPassword.add_Click({
    if ($txtIncidentPassword.Text) {
        [System.Windows.Forms.Clipboard]::SetText($txtIncidentPassword.Text)
        $txtLog.Text = 'Password copied to clipboard.'
    }
})

$chkShowIncidentPassword.add_CheckedChanged({
    $txtIncidentPassword.UseSystemPasswordChar = -not $chkShowIncidentPassword.Checked
})

$btnResetIncidentPassword.add_Click({
    $user = Get-RequiredAuditUser
    if (-not $user) { return }
    $newPassword = $txtIncidentPassword.Text
    if (-not $newPassword) {
        [System.Windows.Forms.MessageBox]::Show('Enter or generate a password first.', 'Missing Password', 'OK', 'Warning') | Out-Null
        return
    }
    $strength = Test-PasswordStrength -Password $newPassword
    if (-not $strength.IsStrong) {
        $msg = "Password does not meet the recommended policy:`n- " + ($strength.Issues -join "`n- ") + "`n`nReset anyway?"
        $choice = [System.Windows.Forms.MessageBox]::Show($msg, 'Weak Password', [System.Windows.Forms.MessageBoxButtons]::YesNo, [System.Windows.Forms.MessageBoxIcon]::Warning)
        if ($choice -ne [System.Windows.Forms.DialogResult]::Yes) { return }
    }

    $confirm = [System.Windows.Forms.MessageBox]::Show("Reset the password for $($user.UserPrincipalName)? Force change at next sign-in: $($chkForceChangeNextSignIn.Checked)", 'Confirm Password Reset', [System.Windows.Forms.MessageBoxButtons]::YesNo, [System.Windows.Forms.MessageBoxIcon]::Warning)
    if ($confirm -ne [System.Windows.Forms.DialogResult]::Yes) { return }

    $form.Cursor = [System.Windows.Forms.Cursors]::WaitCursor
    try {
        $result = Invoke-Worker -Status "Resetting password for $($user.UserPrincipalName)" -ArgumentList @($user.Id, $newPassword, [bool]$chkForceChangeNextSignIn.Checked) { param($id, $pw, $force) Reset-UserPasswordForIncident -UserId $id -Password $pw -ForceChangeNextSignIn $force }
        $forceLine = 'The user is not required to change it at next sign-in.'
        if ($chkForceChangeNextSignIn.Checked) { $forceLine = 'The user must change the password at next sign-in.' }
        Add-ChangeRecord -Area 'Audit User' -Title "Reset password for $($user.UserPrincipalName)" -Success ([bool]$result.Success) -Lines @($forceLine) -ErrorText ([string]$result.Error)
        if ($result.Success) {
            $txtLog.Text = "Password reset for $($user.UserPrincipalName)."
            [System.Windows.Forms.MessageBox]::Show('Password reset successfully. Relay it to the user through a separate, verified channel - not the account you just secured.', 'Success', 'OK', 'Information') | Out-Null
        } else {
            $txtLog.Text = "Password reset FAILED for $($user.UserPrincipalName): $($result.Error)"
            [System.Windows.Forms.MessageBox]::Show("Password reset failed: $($result.Error)", 'Error', 'OK', 'Error') | Out-Null
        }
    }
    finally { $form.Cursor = [System.Windows.Forms.Cursors]::Default }
})

$btnRevokeSessions.add_Click({
    $user = Get-RequiredAuditUser
    if (-not $user) { return }
    $confirm = [System.Windows.Forms.MessageBox]::Show("Revoke all active sign-in sessions for $($user.UserPrincipalName)? This signs them out everywhere immediately.", 'Confirm', [System.Windows.Forms.MessageBoxButtons]::YesNo, [System.Windows.Forms.MessageBoxIcon]::Warning)
    if ($confirm -ne [System.Windows.Forms.DialogResult]::Yes) { return }
    $form.Cursor = [System.Windows.Forms.Cursors]::WaitCursor
    try {
        Invoke-Worker -Status "Revoking sessions for $($user.UserPrincipalName)" -ArgumentList @($user.Id) { param($id) Revoke-MgUserSignInSession -UserId $id | Out-Null } | Out-Null
        Add-ChangeRecord -Area 'Audit User' -Title "Revoke sign-in sessions for $($user.UserPrincipalName)" -Success $true
        $txtLog.Text = "Active sessions revoked for $($user.UserPrincipalName)."
    }
    catch {
        Add-ChangeRecord -Area 'Audit User' -Title "Revoke sign-in sessions for $($user.UserPrincipalName)" -Success $false -ErrorText $_.Exception.Message
        $txtLog.Text = "Failed to revoke sessions for $($user.UserPrincipalName): $($_.Exception.Message)"
        [System.Windows.Forms.MessageBox]::Show("Failed to revoke sessions: $($_.Exception.Message)", 'Error', 'OK', 'Error') | Out-Null
    }
    finally { $form.Cursor = [System.Windows.Forms.Cursors]::Default }
})

$btnRequireMfaReregister.add_Click({
    $user = Get-RequiredAuditUser
    if (-not $user) { return }
    $form.Cursor = [System.Windows.Forms.Cursors]::WaitCursor
    try {
        $methods = @(Invoke-Worker -Status 'Reading registered MFA methods' -Cancellable -ArgumentList @($user.Id) { param($id) Get-UserAuthenticationMethodsSummary -UserId $id })
        $mfaMethods = @($methods | Where-Object { $_.OdataType -ne '#microsoft.graph.passwordAuthenticationMethod' })
        if ($mfaMethods.Count -eq 0) {
            [System.Windows.Forms.MessageBox]::Show("$($user.UserPrincipalName) has no registered MFA methods to remove.", 'Nothing To Do', 'OK', 'Information') | Out-Null
            return
        }
        $summary = "This deletes the following registered MFA method(s) for $($user.UserPrincipalName), forcing re-registration on next sign-in:`n`n- " + (($mfaMethods | ForEach-Object { $_.Type }) -join "`n- ") + "`n`nProceed?"
        $confirm = [System.Windows.Forms.MessageBox]::Show($summary, 'Confirm MFA Reset', [System.Windows.Forms.MessageBoxButtons]::YesNo, [System.Windows.Forms.MessageBoxIcon]::Warning)
        if ($confirm -ne [System.Windows.Forms.DialogResult]::Yes) { return }

        $result = Invoke-Worker -Status 'Removing MFA methods' -ArgumentList @($user.Id, $mfaMethods) { param($id, $methods) Reset-UserAuthenticationMethods -UserId $id -Methods $methods }

        $lines = @("MFA methods removed: $($result.Removed.Count)")
        if ($result.Removed.Count -gt 0) { $lines += ($result.Removed | ForEach-Object { "  - $_" }) }
        if ($result.Failed.Count -gt 0) {
            $lines += "Failed: $($result.Failed.Count)"
            $lines += ($result.Failed | ForEach-Object { "  - $_" })
        }
        if ($result.Skipped.Count -gt 0) {
            $lines += "Skipped: $($result.Skipped.Count)"
            $lines += ($result.Skipped | ForEach-Object { "  - $_" })
        }
        $txtLog.Text = $lines -join "`r`n"
        Add-ChangeRecord -Area 'Audit User' -Title "Require MFA re-register for $($user.UserPrincipalName)" -Success ($result.Failed.Count -eq 0) -Lines $lines

        if ($result.Failed.Count -gt 0) {
            [System.Windows.Forms.MessageBox]::Show("Some MFA methods could not be removed (often because it's the account's current default - make another method default first). See the log panel.", 'Completed With Issues', 'OK', 'Warning') | Out-Null
        } else {
            [System.Windows.Forms.MessageBox]::Show('MFA methods removed. The user will be prompted to re-register on next sign-in.', 'Success', 'OK', 'Information') | Out-Null
        }
    }
    catch {
        [System.Windows.Forms.MessageBox]::Show("Failed to reset MFA methods: $($_.Exception.Message)", 'Error', 'OK', 'Error') | Out-Null
    }
    finally { $form.Cursor = [System.Windows.Forms.Cursors]::Default }
})

$btnVerifyMfa.add_Click({
    $user = Get-RequiredAuditUser
    if (-not $user) { return }
    $form.Cursor = [System.Windows.Forms.Cursors]::WaitCursor
    try {
        $status = Invoke-Worker -Status 'Checking MFA registration and enforcement' -Cancellable -ArgumentList @($user.Id, $user.UserPrincipalName) { param($id, $upn) Test-UserMfaRegistrationStatus -UserId $id -UserPrincipalName $upn }
        if ($status.Success) {
            $yn = { param($v) if ($null -eq $v) { 'unknown' } elseif ($v) { 'Yes' } else { 'No' } }
            $lines = @("MFA status for $($user.UserPrincipalName) (source: $($status.Source)):")
            $lines += "  MFA method registered: $(& $yn $status.IsMfaRegistered)"
            if ($null -ne $status.IsMfaCapable)     { $lines += "  MFA capable: $(& $yn $status.IsMfaCapable)" }
            if ($null -ne $status.IsSsprRegistered) { $lines += "  SSPR registered: $(& $yn $status.IsSsprRegistered)" }
            $lines += "  Registered methods: $($status.MethodsRegistered)"
            $lines += "  Security Defaults: $(if ($null -eq $status.SecurityDefaults) { 'unknown' } elseif ($status.SecurityDefaults) { 'ON' } else { 'off' })"
            $lines += "  Per-user MFA: $(if ($status.PerUserMfaState) { $status.PerUserMfaState } else { 'unknown' })"
            if ($status.EnforcedBy.Count -gt 0) {
                $lines += "  ENFORCED via: $($status.EnforcedBy -join '; ')"
            } else {
                $lines += '  NOT enforced by Security Defaults or per-user MFA.'
            }
            foreach ($n in $status.Notes) { $lines += "  Note: $n" }
            $txtLog.Text = $lines -join "`r`n"
        } else {
            $txtLog.Text = "Could not verify MFA status for $($user.UserPrincipalName): $($status.Error)"
        }
    }
    finally { $form.Cursor = [System.Windows.Forms.Cursors]::Default }
})

$btnCheckRestricted.add_Click({
    $user = Get-RequiredAuditUser
    if (-not $user) { return }
    $form.Cursor = [System.Windows.Forms.Cursors]::WaitCursor
    try {
        $status = Invoke-Worker -Status 'Checking restricted sender list' -Cancellable -ArgumentList @($user.UserPrincipalName) { param($upn) Test-UserRestrictedSender -UserPrincipalName $upn }
        if (-not $status.Success) {
            $txtLog.Text = "Could not check restricted sender status for $($user.UserPrincipalName): $($status.Error)"
        } elseif ($status.IsRestricted) {
            $txtLog.Text = "$($user.UserPrincipalName) IS on the restricted senders list (blocked from sending mail due to detected spam/compromise activity)."
        } else {
            $txtLog.Text = "$($user.UserPrincipalName) is NOT on the restricted senders list."
        }
    }
    finally { $form.Cursor = [System.Windows.Forms.Cursors]::Default }
})

$btnSetPerUserMfa.add_Click({
    $user = Get-RequiredAuditUser
    if (-not $user) { return }
    $state = [string]$cmbPerUserMfaState.SelectedItem

    $effect = switch ($state) {
        'enforced' { 'MFA will be required at every sign-in. If the user has no MFA method registered they will be prompted to register at their next sign-in, and anything that cannot show an MFA prompt (older mail clients, scanners, scripts using basic authentication) will stop working for this account.' }
        'enabled'  { 'The user will be prompted to register for MFA at their next sign-in.' }
        'disabled' { 'Per-user MFA will be turned OFF for this account. If nothing else in the tenant requires MFA, the account will be protected by its password alone.' }
    }
    $icon = if ($state -eq 'disabled') { [System.Windows.Forms.MessageBoxIcon]::Warning } else { [System.Windows.Forms.MessageBoxIcon]::Question }
    $confirm = [System.Windows.Forms.MessageBox]::Show("Set per-user MFA to '$state' for $($user.UserPrincipalName)?`n`n$effect", 'Confirm Per-User MFA', [System.Windows.Forms.MessageBoxButtons]::YesNo, $icon)
    if ($confirm -ne [System.Windows.Forms.DialogResult]::Yes) { return }

    try {
        $result = Invoke-Worker -Status "Setting per-user MFA for $($user.UserPrincipalName)" -ArgumentList @($user.Id, $state) { param($id, $st) Set-UserPerUserMfaState -UserId $id -State $st }
        if (-not $result.Success -or $result.Changed) {
            $mfaLines = @()
            if ($result.Success) { $mfaLines += "Per-user MFA: $($result.Before) -> $($result.After)" }
            Add-ChangeRecord -Area 'Audit User' -Title "Set per-user MFA to '$state' for $($user.UserPrincipalName)" -Success ([bool]$result.Success) -Lines $mfaLines -ErrorText ([string]$result.Error)
        }
        if (-not $result.Success) {
            $txtLog.Text = "Per-user MFA change FAILED for $($user.UserPrincipalName): $($result.Error)"
            [System.Windows.Forms.MessageBox]::Show("Per-user MFA change failed: $($result.Error)", 'Error', 'OK', 'Error') | Out-Null
        }
        elseif (-not $result.Changed) {
            $txtLog.Text = "Per-user MFA for $($user.UserPrincipalName) was already '$($result.After)'. No change made."
        }
        else {
            $txtLog.Text = "Per-user MFA for $($user.UserPrincipalName): $($result.Before) -> $($result.After)."
        }
    }
    catch {
        $txtLog.Text = "Per-user MFA change failed: $($_.Exception.Message)"
        [System.Windows.Forms.MessageBox]::Show("Per-user MFA change failed: $($_.Exception.Message)", 'Error', 'OK', 'Error') | Out-Null
    }
})

$btnCheckForwarding.add_Click({
    $user = Get-RequiredAuditUser
    if (-not $user) { return }
    try {
        $r = Invoke-Worker -Status 'Checking forwarding' -Cancellable -ArgumentList @($user.UserPrincipalName) { param($upn) Get-UserExternalForwarding -UserPrincipalName $upn }
        if (-not $r.Success) {
            $txtLog.Text = "Forwarding check failed for $($user.UserPrincipalName): $($r.Error)"
            [System.Windows.Forms.MessageBox]::Show("Forwarding check failed: $($r.Error)", 'Error', 'OK', 'Error') | Out-Null
            return
        }
        $rows = @($r.Rows)
        $lvForwarding.BeginUpdate()
        $lvForwarding.Items.Clear()
        foreach ($row in $rows) {
            $item = New-Object System.Windows.Forms.ListViewItem([string]$row.Type)
            [void]$item.SubItems.Add([string]$row.Name)
            [void]$item.SubItems.Add([string]$row.Target)
            $yn = { param($v) if ($v) { 'Yes' } else { 'No' } }
            [void]$item.SubItems.Add((& $yn $row.External))
            [void]$item.SubItems.Add((& $yn $row.KeepsCopy))
            [void]$item.SubItems.Add((& $yn $row.Hidden))
            [void]$item.SubItems.Add((& $yn $row.Enabled))
            [void]$item.SubItems.Add([string]$row.Detail)
            if ($row.Severity -eq 'High') { $item.ForeColor = [System.Drawing.Color]::Firebrick }
            elseif ($row.Severity -eq 'Review') { $item.ForeColor = [System.Drawing.Color]::DarkOrange }
            if (-not $row.Enabled) { $item.ForeColor = [System.Drawing.Color]::Gray }
            [void]$lvForwarding.Items.Add($item)
        }
        Invoke-ListViewSort $lvForwarding
        $lvForwarding.EndUpdate()
        if ($rows.Count -eq 0) {
            $txtLog.Text = "$($user.UserPrincipalName) has no mailbox forwarding and no forwarding or redirect inbox rules."
        }
        else {
            $s = $r.Summary
            $txtLog.Text = "$($user.UserPrincipalName): $($s.Total) forwarding setting(s), $($s.External) going outside the tenant, $($s.Hidden) hidden from Outlook and OWA.`r`nRed = forwards outside the tenant or is hidden; orange = forwards to another internal recipient. Mailbox forwarding is set on the mailbox itself and does not show in Outlook. 'Keeps copy' = whether the mailbox still receives the message (a redirect rule does not)."
        }
    }
    catch {
        [System.Windows.Forms.MessageBox]::Show("Forwarding check failed: $($_.Exception.Message)", 'Error', 'OK', 'Error') | Out-Null
    }
})

$btnRefreshInboxRules.add_Click({
    $user = Get-RequiredAuditUser
    if (-not $user) { return }
    $form.Cursor = [System.Windows.Forms.Cursors]::WaitCursor
    try {
        $rules = @(Invoke-Worker -Status 'Loading inbox rules' -Cancellable -ArgumentList @($user.UserPrincipalName) { param($upn) Get-UserInboxRulesList -UserPrincipalName $upn })
        $lvInboxRules.BeginUpdate()
        $lvInboxRules.Items.Clear()
        foreach ($r in $rules) {
            $item = New-Object System.Windows.Forms.ListViewItem([string]$r.Name)
            [void]$item.SubItems.Add([string]$r.Enabled)
            [void]$item.SubItems.Add([string]$r.Priority)
            [void]$item.SubItems.Add([string]$r.Summary)
            if ($r.Suspicious) {
                $item.ForeColor = [System.Drawing.Color]::White
                $item.BackColor = [System.Drawing.Color]::Firebrick
            }
            [void]$lvInboxRules.Items.Add($item)
        }
        Invoke-ListViewSort $lvInboxRules
        $lvInboxRules.EndUpdate()
        $flaggedCount = @($rules | Where-Object Suspicious).Count
        $txtLog.Text = "Loaded $($rules.Count) inbox rule(s) for $($user.UserPrincipalName). $flaggedCount flagged as suspicious (shown in red)."
    }
    catch {
        [System.Windows.Forms.MessageBox]::Show("Failed to load inbox rules: $($_.Exception.Message)", 'Error', 'OK', 'Error') | Out-Null
    }
    finally { $form.Cursor = [System.Windows.Forms.Cursors]::Default }
})

$btnRunTrace.add_Click({
    $user = Get-RequiredAuditUser
    if (-not $user) { return }
    if ($dtpTraceStart.Value -gt $dtpTraceEnd.Value) {
        [System.Windows.Forms.MessageBox]::Show('Start date must be before end date.', 'Invalid Range', 'OK', 'Warning') | Out-Null
        return
    }
    $form.Cursor = [System.Windows.Forms.Cursors]::WaitCursor
    $btnRunTrace.Enabled = $false
    try {
        $rows = @(Invoke-Worker -Status 'Running message trace' -Cancellable -ArgumentList @($user.UserPrincipalName, $dtpTraceStart.Value, $dtpTraceEnd.Value, [string]$cmbTraceDirection.SelectedItem) { param($upn, $start, $end, $dir) Get-UserMessageTraceReport -UserPrincipalName $upn -StartDate $start -EndDate $end -Direction $dir })
        $script:LastMessageTraceResults = $rows
        Set-ListViewRows $lvMessageTrace $rows @('Received', 'SenderAddress', 'RecipientAddress', 'Subject', 'Status', 'Size')
        $btnExportTrace.Enabled = ($rows.Count -gt 0)
        $txtLog.Text = "Message trace returned $($rows.Count) message(s) for $($user.UserPrincipalName) between $($dtpTraceStart.Value.ToShortDateString()) and $($dtpTraceEnd.Value.ToShortDateString())."
    }
    catch {
        [System.Windows.Forms.MessageBox]::Show("Message trace failed: $($_.Exception.Message)", 'Error', 'OK', 'Error') | Out-Null
    }
    finally {
        $form.Cursor = [System.Windows.Forms.Cursors]::Default
        $btnRunTrace.Enabled = $true
    }
})

$btnExportTrace.add_Click({
    if ($script:LastMessageTraceResults.Count -eq 0) { return }
    $dlg = New-Object System.Windows.Forms.SaveFileDialog
    $dlg.Filter = 'CSV files (*.csv)|*.csv'
    $dlg.FileName = "MessageTrace_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    if ($dlg.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        try {
            $script:LastMessageTraceResults | Export-Csv -Path $dlg.FileName -NoTypeInformation
            $txtLog.Text = "Exported $($script:LastMessageTraceResults.Count) row(s) to $($dlg.FileName)."
        }
        catch {
            [System.Windows.Forms.MessageBox]::Show("Export failed: $($_.Exception.Message)", 'Error', 'OK', 'Error') | Out-Null
        }
    }
})

# ---------------------------------------------------------------------------
# Behavior - Audit Tenant
# ---------------------------------------------------------------------------
function Format-TenantError([string]$Message) {
    if ($Message -match 'Enable-OrganizationCustomization|dehydrat') {
        return "$Message`n`nUse 'Enable Organization Customization' at the top of this tab first."
    }
    if ($Message -match 'Insufficient privileges|Authorization_RequestDenied|Forbidden|consent') {
        return "$Message`n`nA Graph permission for this setting has probably not been consented yet. Click 'Connect to Tenant' again so Microsoft prompts for the new permissions."
    }
    $Message
}

# Runs one tenant check or fix: optional confirmation, the call on the worker runspace, then a
# render callback that updates the section.
function Invoke-TenantAction {
    param(
        [Parameter(Mandatory)] [scriptblock] $Worker,
        [object[]] $WorkerArgs = @(),
        [Parameter(Mandatory)] [string] $Status,
        [Parameter(Mandatory)] [scriptblock] $Render,
        [string] $ConfirmText,
        [string] $ConfirmTitle = 'Confirm',
        [switch] $Cancellable,
        [hashtable] $Progress
    )
    if (-not $script:Connected) {
        [System.Windows.Forms.MessageBox]::Show('Connect to the tenant first.', 'Not Connected', 'OK', 'Warning') | Out-Null
        return
    }
    if ($ConfirmText) {
        $answer = [System.Windows.Forms.MessageBox]::Show($ConfirmText, $ConfirmTitle, [System.Windows.Forms.MessageBoxButtons]::YesNo, [System.Windows.Forms.MessageBoxIcon]::Warning)
        if ($answer -ne [System.Windows.Forms.DialogResult]::Yes) { return }
    }
    try {
        $result = Invoke-Worker -Status $Status -ArgumentList $WorkerArgs -Cancellable:$Cancellable -Progress $Progress -ScriptBlock $Worker
        & $Render $result
    }
    catch {
        $msg = Format-TenantError $_.Exception.Message
        if ($script:QuietChecks) {
            # Run All Checks: no dialog per failure. A cancel stops the run; any other failure marks the
            # check's own section ("Could not be read") so it still shows up in the results and the report.
            if ($_.Exception.Message -match '^(Cancelled|Window closed)') { $script:RunAllCancelled = $true }
            else { try { & $Render ([pscustomobject]@{ Success = $false; Error = $msg }) } catch { } }
            return
        }
        $txtLog.Text = "$Status failed: $msg"
        [System.Windows.Forms.MessageBox]::Show($msg, "$Status failed", 'OK', 'Error') | Out-Null
    }
}

function Show-ActionOutcome([string]$Title, $Result) {
    Add-ChangeRecord -Area 'Audit Tenant' -Title $Title -Success ([bool]$Result.Success) -Lines @($Result.Lines) -ErrorText ([string]$Result.Error)
    $lines = @("${Title}:")
    foreach ($l in @($Result.Lines)) { $lines += "  $l" }
    if ($Result.Error) { $lines += "  PROBLEM: $($Result.Error)" }
    $txtLog.Text = $lines -join "`r`n"
    if (-not $Result.Success) {
        [System.Windows.Forms.MessageBox]::Show((Format-TenantError $Result.Error), "$Title - problem", 'OK', 'Warning') | Out-Null
    }
}

function Show-ReadFailure($Section, $Result) {
    Set-TenantSection $Section 'Could not be read' $script:TenantColors.Warn (Format-TenantError $Result.Error)
}

function Show-OrgCustomization($r) {
    if (-not $r.Success) { Show-ReadFailure $secOrg $r; return }
    if ($r.CustomizationEnabled) {
        Set-TenantSection $secOrg 'ENABLED - organization is customized' $script:TenantColors.Good 'IsDehydrated is False, so Exchange configuration can be changed.'
    }
    elseif ($r.Pending) {
        Set-TenantSection $secOrg 'Requested - not showing yet' $script:TenantColors.Warn 'The command ran, but Exchange has not finished yet. Click Check again in a few minutes.'
    }
    else {
        Set-TenantSection $secOrg 'NOT ENABLED - organization is dehydrated' $script:TenantColors.Bad 'Exchange will reject many configuration changes (including some on this tab) until this is enabled. It is a one-time, one-way change.'
    }
}

function Show-SecurityDefaults($r) {
    $checked = Get-Date -Format 'g'
    if (-not $r.Success) {
        Set-TenantSection $secSd 'Could not be read' $script:TenantColors.Warn "Reading Security Defaults failed: $($r.Error)`r`n`r`nThis needs the Policy.Read.All Graph scope; click Connect to Tenant again so Microsoft prompts you to consent to it."
        $txtLog.Text = "Security Defaults could not be read: $($r.Error)"
    }
    elseif ($r.IsEnabled) {
        Set-TenantSection $secSd "ON (checked $checked)" $script:TenantColors.Good 'Security Defaults is enabled. Every user must register for MFA (within 14 days of it being turned on), administrators are challenged for MFA on every sign-in, legacy authentication (basic-auth IMAP/POP/SMTP) is blocked, and privileged actions such as the Azure portal require MFA. Conditional Access cannot be used while this is on.'
        $txtLog.Text = 'Security Defaults is ON for this tenant.'
    }
    else {
        Set-TenantSection $secSd "OFF (checked $checked)" $script:TenantColors.Bad 'Security Defaults is disabled. Nothing here forces users to use MFA unless this tenant uses Conditional Access (Entra ID P1) or per-user MFA. This tool does not evaluate Conditional Access; per-user MFA state for a single account is shown on the Audit User tab (Verify MFA Is Enforced).'
        $txtLog.Text = 'Security Defaults is OFF for this tenant.'
    }
}

function Show-UnifiedAudit($r) {
    if (-not $r.Success) { Show-ReadFailure $secUal $r; return }
    if ($r.IsEnabled) {
        $since = ''
        if ($r.FirstOptInDate) { $since = " First turned on: $($r.FirstOptInDate)." }
        Set-TenantSection $secUal 'ON - audit log search is recording' $script:TenantColors.Good "Unified audit log ingestion is enabled.$since"
    }
    else {
        Set-TenantSection $secUal 'OFF - no audit trail is being recorded' $script:TenantColors.Bad 'Unified audit log ingestion is disabled, so there is no record of user and admin activity to search after an incident. Enable it, then allow up to 60 minutes.'
    }
}

function Show-DirectSend($r) {
    if (-not $r.Success) { Show-ReadFailure $secDirect $r; return }
    if (-not $r.Available) {
        Set-TenantSection $secDirect 'Setting not available in this tenant' $script:TenantColors.Warn 'Get-OrganizationConfig does not expose RejectDirectSend here (it is newer than some tenants and not supported in sovereign clouds).'
    }
    elseif ($r.Rejected) {
        Set-TenantSection $secDirect 'DISABLED - unauthenticated Direct Send is rejected' $script:TenantColors.Good 'RejectDirectSend is True.'
    }
    else {
        Set-TenantSection $secDirect 'ALLOWED - Direct Send is enabled' $script:TenantColors.Bad 'RejectDirectSend is False, so anyone can send mail to your domain pretending to be your own address, without authenticating.'
    }
}

function Show-Forwarding($r) {
    if (-not $r.Success) { Show-ReadFailure $secFwd $r; return }
    $policies = @($r.Policies)
    $detail = (@($policies | ForEach-Object { "$($_.Name): AutoForwardingMode = $($_.AutoForwardingMode)" })) -join "`r`n"
    $on = @($policies | Where-Object { $_.AutoForwardingMode -eq 'On' })
    $auto = @($policies | Where-Object { $_.AutoForwardingMode -eq 'Automatic' })
    if ($policies.Count -eq 0) {
        Set-TenantSection $secFwd 'No outbound spam filter policies found' $script:TenantColors.Warn ''
    }
    elseif ($on.Count -gt 0) {
        Set-TenantSection $secFwd "ALLOWED - $($on.Count) of $($policies.Count) policy(ies) permit external forwarding" $script:TenantColors.Bad $detail
    }
    elseif ($auto.Count -gt 0) {
        Set-TenantSection $secFwd "System-managed (Automatic) on $($auto.Count) policy(ies)" $script:TenantColors.Warn ($detail + "`r`n`r`nAutomatic currently behaves like Off, but set Off to make it explicit.")
    }
    else {
        Set-TenantSection $secFwd 'BLOCKED - external auto-forwarding is off on every policy' $script:TenantColors.Good $detail
    }
}

function Show-PasswordExpiry($r) {
    if (-not $r.Success) { Show-ReadFailure $secPwd $r; return }
    $domains = @($r.Domains)
    $lines = @()
    foreach ($d in $domains) {
        $period = "$($d.ValidityDays) days"
        if ($d.NeverExpires) { $period = 'never expires' }
        elseif ($null -eq $d.ValidityDays) { $period = 'default (90 days)' }
        $note = $d.AuthenticationType
        if (-not $d.IsVerified) { $note += ', unverified' }
        $lines += "$($d.Id) [$note]: $period"
    }
    $detail = $lines -join "`r`n"
    $managed = @($domains | Where-Object { $_.IsVerified -and $_.AuthenticationType -eq 'Managed' })
    $expiring = @($managed | Where-Object { -not $_.NeverExpires })
    if ($managed.Count -eq 0) {
        Set-TenantSection $secPwd 'No verified managed domains found' $script:TenantColors.Warn $detail
    }
    elseif ($expiring.Count -eq 0) {
        Set-TenantSection $secPwd 'NEVER EXPIRE on every managed domain' $script:TenantColors.Good $detail
    }
    else {
        Set-TenantSection $secPwd "EXPIRE on $($expiring.Count) of $($managed.Count) managed domain(s)" $script:TenantColors.Bad $detail
    }
}

function Show-Consent($r) {
    if (-not $r.Success) { Show-ReadFailure $secConsent $r; return }
    $consentText = 'blocked'
    if ($r.UserConsentAllowed) { $consentText = 'ALLOWED (' + ($r.GrantPolicies -join ', ') + ')' }
    $workflowText = 'OFF'
    if ($r.RequestWorkflowEnabled) { $workflowText = "enabled, $($r.ReviewerCount) reviewer(s)" }
    $detail = "User consent: $consentText`r`nAdmin consent request workflow: $workflowText"
    if ($r.UserConsentAllowed) {
        Set-TenantSection $secConsent 'USERS CAN GRANT CONSENT to applications' $script:TenantColors.Bad $detail
    }
    elseif (-not $r.RequestWorkflowEnabled) {
        Set-TenantSection $secConsent 'User consent blocked, but users cannot request access' $script:TenantColors.Warn ($detail + "`r`n`r`nUsers hitting a consent prompt have no way to ask an admin. Turn the admin consent workflow on.")
    }
    else {
        Set-TenantSection $secConsent 'LOCKED DOWN - users must request, admins approve' $script:TenantColors.Good $detail
    }
}

function Show-MfaMethods($r) {
    if (-not $r.Success) { Show-ReadFailure $secMfa $r; return }
    $methods = @($r.Methods)
    $voice = $methods | Where-Object { $_.Id -eq 'Voice' } | Select-Object -First 1
    $push = $methods | Where-Object { $_.Id -eq 'MicrosoftAuthenticator' } | Select-Object -First 1
    $detail = (@($methods | Sort-Object FriendlyName | ForEach-Object { "$($_.FriendlyName): $($_.State)" })) -join "`r`n"
    $voiceState = 'n/a'
    if ($voice) { $voiceState = $voice.State }
    $pushState = 'n/a'
    if ($push) { $pushState = $push.State }
    $summary = "Voice call: $voiceState  |  Authenticator push: $pushState"
    if ($voiceState -eq 'enabled' -or $pushState -eq 'enabled') {
        Set-TenantSection $secMfa $summary $script:TenantColors.Warn $detail
    }
    else {
        Set-TenantSection $secMfa $summary $script:TenantColors.Good $detail
    }
}

# --- Organization customization ---
$secOrg.Buttons['Check'].add_Click({
    Invoke-TenantAction -Status 'Checking organization customization' -Cancellable -Worker { Get-TenantOrgCustomizationStatus } -Render { param($r) Show-OrgCustomization $r }
})
$secOrg.Buttons['Enable Organization Customization'].add_Click({
    Invoke-TenantAction -Status 'Enabling organization customization' -ConfirmTitle 'Enable Organization Customization' `
        -ConfirmText "This runs Enable-OrganizationCustomization on the tenant. It is a one-time change that cannot be undone, and Exchange can take a while to finish.`n`nProceed?" `
        -Worker { Enable-TenantOrgCustomization } -Render { param($r) Show-ActionOutcome 'Enable organization customization' $r; if ($r.Status) { Show-OrgCustomization $r.Status } }
})

# --- Security Defaults ---
$secSd.Buttons['Check Security Defaults'].add_Click({
    Invoke-TenantAction -Status 'Checking Security Defaults' -Cancellable -Worker { Get-TenantSecurityDefaultsStatus } -Render { param($r) Show-SecurityDefaults $r }
})

# --- Unified audit log ---
$secUal.Buttons['Check'].add_Click({
    Invoke-TenantAction -Status 'Checking unified audit log' -Cancellable -Worker { Get-TenantUnifiedAuditLogStatus } -Render { param($r) Show-UnifiedAudit $r }
})
$secUal.Buttons['Enable Audit Log Search'].add_Click({
    Invoke-TenantAction -Status 'Enabling unified audit log' -ConfirmTitle 'Enable Audit Log Search' `
        -ConfirmText "Turn on unified audit log ingestion for the whole tenant? It can take up to 60 minutes before searches return data.`n`nProceed?" `
        -Worker { Enable-TenantUnifiedAuditLog } -Render { param($r) Show-ActionOutcome 'Enable audit log search' $r; if ($r.Status) { Show-UnifiedAudit $r.Status } }
})

# --- Direct Send ---
$secDirect.Buttons['Check'].add_Click({
    Invoke-TenantAction -Status 'Checking Direct Send' -Cancellable -Worker { Get-TenantDirectSendStatus } -Render { param($r) Show-DirectSend $r }
})
$secDirect.Buttons['Disable Direct Send'].add_Click({
    Invoke-TenantAction -Status 'Disabling Direct Send' -ConfirmTitle 'Disable Direct Send' `
        -ConfirmText "Reject unauthenticated Direct Send mail for the whole tenant (RejectDirectSend = True)?`n`nAny scanner, printer or app that sends mail straight to your domain without authenticating will start getting 'Direct Send not allowed' rejections. Inventory those first; they need authenticated SMTP or a mail flow connector. It can take up to 30 minutes to apply.`n`nProceed?" `
        -Worker { Disable-TenantDirectSend } -Render { param($r) Show-ActionOutcome 'Disable Direct Send' $r; if ($r.Status) { Show-DirectSend $r.Status } }
})

# --- External forwarding ---
$secFwd.Buttons['Check'].add_Click({
    Invoke-TenantAction -Status 'Checking external forwarding' -Cancellable -Worker { Get-TenantExternalForwardingStatus } -Render { param($r) Show-Forwarding $r }
})
$secFwd.Buttons['Disable External Forwarding'].add_Click({
    Invoke-TenantAction -Status 'Disabling external forwarding' -ConfirmTitle 'Disable External Forwarding' `
        -ConfirmText "Set AutoForwardingMode to Off on every outbound spam filter policy, blocking automatic forwarding to external domains for the whole tenant?`n`nAnything that legitimately forwards mail outside the organization will stop being delivered.`n`nProceed?" `
        -Worker { Disable-TenantExternalForwarding } -Render { param($r) Show-ActionOutcome 'Disable external forwarding' $r; if ($r.Status) { Show-Forwarding $r.Status } }
})

# --- Password expiration ---
$secPwd.Buttons['Check'].add_Click({
    Invoke-TenantAction -Status 'Checking password expiration' -Cancellable -Worker { Get-TenantPasswordExpirationStatus } -Render { param($r) Show-PasswordExpiry $r }
})
$secPwd.Buttons['Set Passwords to Never Expire'].add_Click({
    Invoke-TenantAction -Status 'Setting passwords to never expire' -ConfirmTitle 'Passwords Never Expire' `
        -ConfirmText "Set the password validity period to 'never expires' on every verified, managed domain?`n`nThis is only a good idea with MFA (or another strong control) in place, because a stolen password then stays valid until it is changed. Accounts individually set to expire are not overridden.`n`nProceed?" `
        -Worker { Set-TenantPasswordsNeverExpire } -Render { param($r) Show-ActionOutcome 'Passwords never expire' $r; if ($r.Status) { Show-PasswordExpiry $r.Status } }
})

# --- User consent ---
$secConsent.Buttons['Check'].add_Click({
    Invoke-TenantAction -Status 'Checking application consent settings' -Cancellable -Worker { Get-TenantAppConsentStatus } -Render { param($r) Show-Consent $r }
})
$secConsent.Buttons['Block User Consent + Enable Admin Requests'].add_Click({
    Invoke-TenantAction -Status 'Locking down application consent' -ConfirmTitle 'Block User Consent' `
        -ConfirmText "This will:`n  1. Turn on the admin consent request workflow, with every enabled Global Administrator as a reviewer (existing reviewers are kept).`n  2. Then stop users from granting consent to applications themselves.`n`nUsers will see a request prompt instead, and a Global Administrator approves it. Applications users have already consented to keep working.`n`nProceed?" `
        -Worker { Set-TenantAppConsentLockdown } -Render { param($r) Show-ActionOutcome 'Application consent lockdown' $r; if ($r.Status) { Show-Consent $r.Status } }
})

# --- MFA verification methods ---
$secMfa.Buttons['Check'].add_Click({
    Invoke-TenantAction -Status 'Checking MFA verification methods' -Cancellable -Worker { Get-TenantMfaMethodPolicyStatus } -Render { param($r) Show-MfaMethods $r }
})
$secMfa.Buttons['Disable Selected Methods'].add_Click({
    $ids = @()
    $names = @()
    if ($chkDisableVoice.Checked) { $ids += 'Voice'; $names += 'Voice call' }
    if ($chkDisablePush.Checked) { $ids += 'MicrosoftAuthenticator'; $names += 'Microsoft Authenticator (push notification)' }
    if ($ids.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show('Tick at least one method to disable.', 'Nothing Selected', 'OK', 'Information') | Out-Null
        return
    }
    $nameList = $names -join "`n  - "
    Invoke-TenantAction -Status 'Disabling MFA verification methods' -ConfirmTitle 'Disable MFA Methods' -WorkerArgs @(, $ids) `
        -ConfirmText "Disable these methods for the whole tenant?`n`n  - $nameList`n`nAnyone whose only registered method is one of these will have to register a different one. Disabling Microsoft Authenticator also turns off its passwordless sign-in.`n`nProceed?" `
        -Worker { param($methodIds) Disable-TenantMfaMethods -MethodIds $methodIds } -Render { param($r) Show-ActionOutcome 'Disable MFA methods' $r; if ($r.Status) { Show-MfaMethods $r.Status } }
})

# --- Admin accounts ---
$secAdmins.Buttons['List Admin Accounts'].add_Click({
    Invoke-TenantAction -Status 'Listing admin accounts' -Cancellable -Worker { Get-TenantAdminAccounts } -Render {
        param($r)
        if (-not $r.Success) { Show-ReadFailure $secAdmins $r; return }
        $users = @($r.Users)
        $script:LastAdminList = $users
        $lvAdmins.BeginUpdate()
        $lvAdmins.Items.Clear()
        foreach ($u in $users) {
            $item = New-Object System.Windows.Forms.ListViewItem([string]$u.DisplayName)
            [void]$item.SubItems.Add([string]$u.UserPrincipalName)
            $enabledText = 'No'
            if ($u.AccountEnabled) { $enabledText = 'Yes' }
            [void]$item.SubItems.Add($enabledText)
            $gaText = ''
            if ($u.IsGlobalAdmin) { $gaText = 'Yes' }
            [void]$item.SubItems.Add($gaText)
            [void]$item.SubItems.Add([string]$u.Mfa)
            [void]$item.SubItems.Add([string]$u.LicenseText)
            [void]$item.SubItems.Add([string]$u.Roles)

            # Colour cell by cell, so a flagged cell (no MFA / a user license) stands out even on a row
            # that is highlighted as a Global Administrator or greyed as disabled.
            $item.UseItemStyleForSubItems = $false
            $rowBack = [System.Drawing.SystemColors]::Window
            if ($u.IsGlobalAdmin) { $rowBack = [System.Drawing.Color]::LemonChiffon }
            $rowFore = [System.Drawing.SystemColors]::WindowText
            if (-not $u.AccountEnabled) { $rowFore = [System.Drawing.Color]::Gray }
            foreach ($sub in $item.SubItems) { $sub.BackColor = $rowBack; $sub.ForeColor = $rowFore }
            if ($u.AccountEnabled -and $u.HasMfa -eq $false) { $item.SubItems[4].ForeColor = [System.Drawing.Color]::Firebrick }
            if ($u.AccountEnabled -and $u.HasUserLicense -eq $true) { $item.SubItems[5].ForeColor = [System.Drawing.Color]::Firebrick }
            [void]$lvAdmins.Items.Add($item)
        }
        Invoke-ListViewSort $lvAdmins
        $lvAdmins.EndUpdate()
        $secAdmins.Buttons['Export CSV...'].Enabled = ($users.Count -gt 0)
        $gaCount = @($users | Where-Object { $_.IsGlobalAdmin }).Count
        $noMfaCount = @($users | Where-Object { $_.AccountEnabled -and $_.HasMfa -eq $false }).Count
        $licensedCount = @($users | Where-Object { $_.AccountEnabled -and $_.HasUserLicense -eq $true }).Count
        $unknownCount = @($users | Where-Object { $null -eq $_.HasMfa -or $null -eq $_.HasUserLicense }).Count
        $color = $script:TenantColors.Good
        if ($gaCount -gt 4 -or $gaCount -lt 2 -or $unknownCount -gt 0) { $color = $script:TenantColors.Warn }
        if ($noMfaCount -gt 0 -or $licensedCount -gt 0) { $color = $script:TenantColors.Bad }
        $summary = "$($users.Count) account(s) hold admin roles; $gaCount Global Administrator(s); $noMfaCount enabled without MFA; $licensedCount with a user license"
        Set-TenantSection $secAdmins $summary $color
        Add-FindingLines $secAdmins (Format-FindingLines $users {
            param($x) "$($x.DisplayName) <$($x.UserPrincipalName)>$(if ($x.IsGlobalAdmin) { ' [Global Administrator]' })$(if (-not $x.AccountEnabled) { ' (disabled)' }) - MFA: $($x.Mfa); licenses: $($x.LicenseText); roles: $($x.Roles)"
        })
        $logLines = @("$($users.Count) user account(s) hold an Entra ID admin role ($gaCount Global Administrator(s), highlighted). $($r.ServicePrincipalCount) service principal(s) also hold roles and are not listed.")
        if ($noMfaCount -gt 0) { $logLines += "$noMfaCount enabled admin account(s) have NO MFA method registered (MFA cell in red)." }
        if ($licensedCount -gt 0) { $logLines += "$licensedCount enabled admin account(s) hold a USER LICENSE (a mailbox, Office apps, Teams or SharePoint) - admin accounts should be separate, unlicensed accounts so that a phished mailbox is not also an admin (Licenses cell in red)." }
        if ($unknownCount -gt 0) { $logLines += "MFA or licenses could not be read for $unknownCount account(s) (shown as Unknown) - check the UserAuthenticationMethod.Read.All and Organization.Read.All permissions." }
        $logLines += 'Licenses column: USER LICENSE = holds a license with a mailbox / Office / Teams / SharePoint plan that is switched on for that user; Other = only licenses without those (e.g. Entra ID P1/P2, which admins can legitimately need); None = unlicensed, which is what an admin account should be.'
        $logLines += 'MFA column = registered methods that can satisfy MFA; it shows what is registered, not whether sign-in enforces it. Microsoft recommends 2 to 4 Global Administrators. Only active assignments are listed: PIM-eligible assignments and Exchange role groups are not included.'
        $txtLog.Text = $logLines -join "`r`n"
    }
})
$secAdmins.Buttons['Export CSV...'].add_Click({
    if (@($script:LastAdminList).Count -eq 0) { return }
    $dlg = New-Object System.Windows.Forms.SaveFileDialog
    $dlg.Filter = 'CSV files (*.csv)|*.csv'
    $dlg.FileName = "AdminAccounts_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    if ($dlg.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        try {
            $script:LastAdminList | Select-Object DisplayName, UserPrincipalName, AccountEnabled, IsGlobalAdmin, Mfa, MfaMethods, Licenses, HasUserLicense, Roles, Assignment | Export-Csv -Path $dlg.FileName -NoTypeInformation
            $txtLog.Text = "Exported $(@($script:LastAdminList).Count) row(s) to $($dlg.FileName)."
        }
        catch {
            [System.Windows.Forms.MessageBox]::Show("Export failed: $($_.Exception.Message)", 'Error', 'OK', 'Error') | Out-Null
        }
    }
})

# --- Full user MFA report ---
function Update-MfaReportList {
    $rows = @()
    if ($script:LastMfaReport) { $rows = @($script:LastMfaReport.Rows) }
    if ($chkMfaGapsOnly.Checked) { $rows = @($rows | Where-Object { $_.Status -ne 'Protected' }) }
    $attention = @('Registered, not enforced', 'Enforced, not registered', 'Registered (enforcement unknown)')
    $lvMfaReport.BeginUpdate()
    $lvMfaReport.Items.Clear()
    foreach ($row in $rows) {
        $item = New-Object System.Windows.Forms.ListViewItem([string]$row.DisplayName)
        [void]$item.SubItems.Add([string]$row.UserPrincipalName)
        [void]$item.SubItems.Add([string]$row.Status)
        [void]$item.SubItems.Add([string]$row.Methods)
        [void]$item.SubItems.Add([string]$row.EnforcedBy)
        [void]$item.SubItems.Add([string]$row.PerUserMfaState)
        $enabledText = 'No'
        if ($row.AccountEnabled) { $enabledText = 'Yes' }
        [void]$item.SubItems.Add($enabledText)
        [void]$item.SubItems.Add([string]$row.UserType)
        if ($row.Status -eq 'UNPROTECTED' -or $row.Status -eq 'No MFA (enforcement unknown)') { $item.ForeColor = [System.Drawing.Color]::Firebrick }
        elseif ($attention -contains $row.Status) { $item.ForeColor = [System.Drawing.Color]::DarkOrange }
        elseif ($row.Status -eq 'Unknown') { $item.ForeColor = [System.Drawing.Color]::Gray }
        # a disabled account isn't a live risk, so it never shouts
        if (-not $row.AccountEnabled) { $item.ForeColor = [System.Drawing.Color]::Gray }
        [void]$lvMfaReport.Items.Add($item)
    }
    Invoke-ListViewSort $lvMfaReport
    $lvMfaReport.EndUpdate()
}

function Show-MfaReport($r) {
    if (-not $r.Success) { Show-ReadFailure $secMfaReport $r; return }
    $script:LastMfaReport = $r
    Update-MfaReportList
    $s = $r.Summary
    $secMfaReport.Buttons['Export CSV...'].Enabled = ($s.Total -gt 0)

    $text = "$($s.Total) user(s): $($s.Protected) protected, $($s.RegisteredNotEnforced) registered but not enforced, $($s.EnforcedNotRegistered) enforced but not registered, $($s.Unprotected) UNPROTECTED"
    if ($s.Unknown -gt 0) { $text += ", $($s.Unknown) unknown" }
    $color = $script:TenantColors.Neutral
    if ($s.Total -gt 0) { $color = $script:TenantColors.Good }
    if (($s.RegisteredNotEnforced + $s.EnforcedNotRegistered + $s.Unknown) -gt 0) { $color = $script:TenantColors.Warn }
    if ($s.Unprotected -gt 0) { $color = $script:TenantColors.Bad }
    Set-TenantSection $secMfaReport $text $color
    $gaps = @($r.Rows | Where-Object { $_.Status -ne 'Protected' })
    Add-FindingLines $secMfaReport @("$($s.Protected) protected user(s) are not listed; the $($gaps.Count) below are not Protected.")
    Add-FindingLines $secMfaReport (Format-FindingLines $gaps {
        param($x) "[$($x.Status)] $($x.DisplayName) <$($x.UserPrincipalName)>$(if (-not $x.AccountEnabled) { ' (disabled)' }) methods: $(if ($x.Methods) { $x.Methods } else { 'none' }); enforced by: $(if ($x.EnforcedBy) { $x.EnforcedBy } else { 'nothing' })"
    })

    $sd = 'could not be read'
    if ($r.SecurityDefaults -eq $true) { $sd = 'ON' } elseif ($r.SecurityDefaults -eq $false) { $sd = 'off' }
    $lines = @("MFA report: $($s.Total) user(s) of $($r.UsersListed) in the tenant (disabled accounts $(if ($chkMfaDisabled.Checked) { 'included' } else { 'left out' }), guests $(if ($chkMfaGuests.Checked) { 'included' } else { 'left out' })). Security Defaults: $sd.")
    $lines += 'Protected = an MFA method is registered AND something enforces it (Security Defaults or per-user MFA). Registered, not enforced = has a method but nothing requires it. Enforced, not registered = will be prompted to register at next sign-in. UNPROTECTED = neither.'
    $lines += 'Conditional Access (Entra ID P1) is not evaluated, so on a tenant that uses it, "not enforced" may be covered by a policy.'
    if ($s.Unknown -gt 0) { $lines += "$($s.Unknown) user(s) are Unknown / enforcement unknown: their methods or per-user state could not be read (missing permission or throttling)." }
    $txtLog.Text = $lines -join "`r`n"
}

$secMfaReport.Buttons['Run MFA Report'].add_Click({
    $progress = [hashtable]::Synchronized(@{ Text = '' })
    Invoke-TenantAction -Status 'Building MFA report' -Cancellable -Progress $progress `
        -WorkerArgs @([bool]$chkMfaDisabled.Checked, [bool]$chkMfaGuests.Checked, $progress) `
        -Worker { param($includeDisabled, $includeGuests, $p) Get-TenantMfaReport -IncludeDisabled $includeDisabled -IncludeGuests $includeGuests -Progress $p } `
        -Render { param($r) Show-MfaReport $r }
})
$chkMfaGapsOnly.add_CheckedChanged({ if ($script:LastMfaReport) { Update-MfaReportList } })
$secMfaReport.Buttons['Export CSV...'].add_Click({
    if (-not $script:LastMfaReport -or @($script:LastMfaReport.Rows).Count -eq 0) { return }
    $dlg = New-Object System.Windows.Forms.SaveFileDialog
    $dlg.Filter = 'CSV files (*.csv)|*.csv'
    $dlg.FileName = "MfaReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    if ($dlg.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        try {
            $script:LastMfaReport.Rows | Select-Object DisplayName, UserPrincipalName, UserType, AccountEnabled, Status, Mfa, Methods, EnforcedBy, PerUserMfaState | Export-Csv -Path $dlg.FileName -NoTypeInformation
            $txtLog.Text = "Exported the full report ($(@($script:LastMfaReport.Rows).Count) row(s), ignoring the 'only show' filter) to $($dlg.FileName)."
        }
        catch {
            [System.Windows.Forms.MessageBox]::Show("Export failed: $($_.Exception.Message)", 'Error', 'OK', 'Error') | Out-Null
        }
    }
})

# --- Exchange mail flow connectors ---
function Show-Connectors($r) {
    if (-not $r.Success) { Show-ReadFailure $secConnectors $r; return }
    $script:LastConnectors = @($r.Connectors)
    $lvConnectors.BeginUpdate()
    $lvConnectors.Items.Clear()
    foreach ($c in $script:LastConnectors) {
        $item = New-Object System.Windows.Forms.ListViewItem([string]$c.Direction)
        [void]$item.SubItems.Add([string]$c.Name)
        $enabledText = 'No'
        if ($c.Enabled) { $enabledText = 'Yes' }
        [void]$item.SubItems.Add($enabledText)
        [void]$item.SubItems.Add([string]$c.Type)
        [void]$item.SubItems.Add([string]$c.Scope)
        [void]$item.SubItems.Add([string]$c.Endpoints)
        [void]$item.SubItems.Add([string]$c.Tls)
        [void]$item.SubItems.Add([string]$c.Created)
        [void]$item.SubItems.Add([string]$c.Flags)
        if ($c.Severity -eq 'High') { $item.ForeColor = [System.Drawing.Color]::Firebrick }
        elseif ($c.Severity -eq 'Review') { $item.ForeColor = [System.Drawing.Color]::DarkOrange }
        if (-not $c.Enabled) { $item.ForeColor = [System.Drawing.Color]::Gray }
        [void]$lvConnectors.Items.Add($item)
    }
    Invoke-ListViewSort $lvConnectors
    $lvConnectors.EndUpdate()

    $s = $r.Summary
    $secConnectors.Buttons['Export CSV...'].Enabled = ($s.Total -gt 0)
    if ($s.Total -eq 0) {
        Set-TenantSection $secConnectors 'No mail flow connectors are configured' $script:TenantColors.Good
        $txtLog.Text = 'No inbound or outbound connectors exist in this tenant, so all mail uses the default routing.'
        return
    }
    $text = "$($s.Total) connector(s): $($s.Inbound) inbound, $($s.Outbound) outbound; $($s.High) high-risk, $($s.Review) to review"
    $color = $script:TenantColors.Good
    if ($s.Review -gt 0) { $color = $script:TenantColors.Warn }
    if ($s.High -gt 0) { $color = $script:TenantColors.Bad }
    Set-TenantSection $secConnectors $text $color
    Add-FindingLines $secConnectors (Format-FindingLines $script:LastConnectors {
        param($x) "[$(if ($x.Severity) { $x.Severity } else { 'ok' })] $($x.Direction) connector '$($x.Name)' ($($x.Type)), enabled: $(Get-YesNo $x.Enabled), scope: $($x.Scope), endpoints: $($x.Endpoints), TLS: $($x.Tls), created: $($x.Created)$(if ($x.Flags) { ' - ' + $x.Flags })"
    })

    $lines = @("$($s.Total) mail flow connector(s) ($($s.Enabled) enabled): $($s.High) high-risk, $($s.Review) to review, $($s.Recent) created in the last 30 days.")
    $lines += 'Connectors decide who may deliver mail into the tenant and where outgoing mail is sent; an intruder who adds one can spoof your domain or divert mail, so confirm each one below is one you created.'
    $lines += 'Red = unsafe as configured (treats its mail as internal, accepts any sender domain, or accepts a partner domain with no IP or certificate restriction). Orange = unusual or worth confirming (new in the last 30 days, TLS not required, all outbound mail through a smart host, used by a mail flow rule). Grey = disabled.'
    $lines += 'This check is read-only: change or remove connectors in the Exchange admin center under Mail flow > Connectors.'
    $txtLog.Text = $lines -join "`r`n"
}

$secConnectors.Buttons['List Connectors'].add_Click({
    Invoke-TenantAction -Status 'Listing mail flow connectors' -Cancellable -Worker { Get-TenantMailConnectors } -Render { param($r) Show-Connectors $r }
})
$secConnectors.Buttons['Export CSV...'].add_Click({
    if (@($script:LastConnectors).Count -eq 0) { return }
    $dlg = New-Object System.Windows.Forms.SaveFileDialog
    $dlg.Filter = 'CSV files (*.csv)|*.csv'
    $dlg.FileName = "MailConnectors_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    if ($dlg.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        try {
            $script:LastConnectors | Select-Object Direction, Name, Enabled, Type, Scope, Endpoints, Tls, Created, Severity, Flags | Export-Csv -Path $dlg.FileName -NoTypeInformation
            $txtLog.Text = "Exported $(@($script:LastConnectors).Count) connector(s) to $($dlg.FileName)."
        }
        catch {
            [System.Windows.Forms.MessageBox]::Show("Export failed: $($_.Exception.Message)", 'Error', 'OK', 'Error') | Out-Null
        }
    }
})

# ---------------------------------------------------------------------------
# Findings report: what each check found, and every change made this session
# ---------------------------------------------------------------------------
# Set-TenantSection records each check's result here (keyed by section title), and the list sections add
# their rows as extra lines. The change journal collects every change the tool makes, on any tab.
function Register-Finding($Section, [string]$State, $Color, $Detail) {
    $title = $Section.Title
    if ($State -eq 'Not checked yet.') { $script:TenantReport.Remove($title); return }
    $severity = 'INFO'
    if ($Color -eq $script:TenantColors.Good) { $severity = 'OK' }
    elseif ($Color -eq $script:TenantColors.Bad) { $severity = 'PROBLEM' }
    elseif ($Color -eq $script:TenantColors.Warn) {
        if ($State -eq 'Could not be read') { $severity = 'UNREADABLE' } else { $severity = 'REVIEW' }
    }
    $lines = @()
    if ($Detail) { $lines = @(([string]$Detail) -split "`r?`n" | Where-Object { $_ -ne '' }) }
    $script:TenantReport[$title] = [pscustomobject]@{ Title = $title; State = $State; Severity = $severity; Time = (Get-Date); Lines = $lines }
}

function Add-FindingLines($Section, [string[]]$Lines) {
    $entry = $script:TenantReport[$Section.Title]
    if ($entry) { $entry.Lines = @($entry.Lines) + @($Lines | Where-Object { $_ }) }
}

function Format-FindingLines {
    param($Rows, [scriptblock]$Format, [int]$Max = 500)
    $all = @($Rows)
    $out = @($all | Select-Object -First $Max | ForEach-Object { & $Format $_ })
    if ($all.Count -gt $Max) { $out += "... and $($all.Count - $Max) more (use Export CSV for the full list)" }
    $out
}

function Add-ChangeRecord {
    param([string]$Area, [string]$Title, [bool]$Success, [string[]]$Lines = @(), [string]$ErrorText)
    [void]$script:ChangeJournal.Add([pscustomobject]@{
        Time    = (Get-Date)
        Area    = $Area
        Title   = $Title
        Success = $Success
        Lines   = @($Lines | Where-Object { $_ })
        Error   = $ErrorText
    })
}

function New-FindingsReport {
    $out = New-Object System.Collections.Generic.List[string]
    $out.Add("$($script:AppName) - findings report")
    $out.Add("Generated:    $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
    $out.Add("Signed in as: $($script:ConnectedAccount)")
    $out.Add("Tenant ID:    $($script:ConnectedTenantId)")
    $out.Add('')

    $entries = @()
    $notRun = @()
    foreach ($s in $script:TenantSectionList) {
        $e = $script:TenantReport[$s.Title]
        if ($e) { $entries += $e } else { $notRun += $s.Title }
    }
    $count = { param($sev) @($entries | Where-Object { $_.Severity -eq $sev }).Count }

    $out.Add('SUMMARY')
    $out.Add("  Checks run: $($entries.Count) of $($script:TenantSectionList.Count)    Problems: $(& $count 'PROBLEM')    To review: $(& $count 'REVIEW')    OK: $(& $count 'OK')    Could not be read: $(& $count 'UNREADABLE')    Not run: $($notRun.Count)")
    $out.Add("  Changes made this session: $($script:ChangeJournal.Count)")
    $out.Add('  Findings cover only the checks run in this session. The change list covers every change this tool made since it was started, on every tab.')
    $out.Add('')

    $out.Add('RESULTS')
    foreach ($e in $entries) { $out.Add(('  [{0}] {1}: {2}' -f $e.Severity.PadRight(10), $e.Title, $e.State)) }
    foreach ($t in $notRun) { $out.Add(('  [{0}] {1}' -f 'NOT RUN'.PadRight(10), $t)) }
    $out.Add('')

    $out.Add('DETAILS')
    foreach ($e in $entries) {
        $out.Add(('-' * 78))
        $out.Add($e.Title)
        $out.Add("  Result:  $($e.State)  [$($e.Severity)]")
        $out.Add("  Checked: $($e.Time.ToString('yyyy-MM-dd HH:mm:ss'))")
        foreach ($l in $e.Lines) { $out.Add("  $l") }
    }
    if ($entries.Count -eq 0) { $out.Add('  (no checks have been run)') }
    $out.Add('')

    $out.Add('CHANGES MADE THIS SESSION')
    if ($script:ChangeJournal.Count -eq 0) { $out.Add('  (none - this tool has not changed anything since it was started)') }
    foreach ($c in $script:ChangeJournal) {
        $outcome = 'succeeded'
        if (-not $c.Success) { $outcome = 'FAILED' }
        $out.Add(('  {0}  [{1}] {2} - {3}' -f $c.Time.ToString('yyyy-MM-dd HH:mm:ss'), $c.Area, $c.Title, $outcome))
        foreach ($l in $c.Lines) { $out.Add("      $l") }
        if ($c.Error) { $out.Add("      Problem: $($c.Error)") }
    }
    $out.Add('')
    $out -join "`r`n"
}

# ---------------------------------------------------------------------------
# Mail security sections: forwarding in use, inbox rule scan, attachment filter, DKIM, SPF / DMARC
# ---------------------------------------------------------------------------
function Export-TenantCsv {
    param($Rows, [string[]]$Columns, [string]$NamePrefix)
    if (@($Rows).Count -eq 0) { return }
    $dlg = New-Object System.Windows.Forms.SaveFileDialog
    $dlg.Filter = 'CSV files (*.csv)|*.csv'
    $dlg.FileName = "${NamePrefix}_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    if ($dlg.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        try {
            @($Rows) | Select-Object $Columns | Export-Csv -Path $dlg.FileName -NoTypeInformation
            $txtLog.Text = "Exported $(@($Rows).Count) row(s) to $($dlg.FileName)."
        }
        catch {
            [System.Windows.Forms.MessageBox]::Show("Export failed: $($_.Exception.Message)", 'Error', 'OK', 'Error') | Out-Null
        }
    }
}

function Get-YesNo($Value) { if ($Value) { 'Yes' } else { 'No' } }

function Show-ForwardingUse($r) {
    if (-not $r.Success) { Show-ReadFailure $secFwdUse $r; return }
    $script:LastFwdUse = @($r.Rows)
    $lvFwdUse.BeginUpdate()
    $lvFwdUse.Items.Clear()
    foreach ($row in $script:LastFwdUse) {
        $item = New-Object System.Windows.Forms.ListViewItem([string]$row.Source)
        [void]$item.SubItems.Add([string]$row.Name)
        [void]$item.SubItems.Add([string]$row.Target)
        [void]$item.SubItems.Add((Get-YesNo $row.External))
        [void]$item.SubItems.Add((Get-YesNo $row.KeepsCopy))
        [void]$item.SubItems.Add((Get-YesNo $row.Enabled))
        [void]$item.SubItems.Add([string]$row.Detail)
        if ($row.Severity -eq 'High') { $item.ForeColor = [System.Drawing.Color]::Firebrick }
        elseif ($row.Severity -eq 'Review') { $item.ForeColor = [System.Drawing.Color]::DarkOrange }
        if (-not $row.Enabled) { $item.ForeColor = [System.Drawing.Color]::Gray }
        [void]$lvFwdUse.Items.Add($item)
    }
    Invoke-ListViewSort $lvFwdUse
    $lvFwdUse.EndUpdate()

    $s = $r.Summary
    $secFwdUse.Buttons['Export CSV...'].Enabled = ($s.Total -gt 0)
    $external = $s.ExternalMailbox + $s.ExternalRules
    if ($s.Total -eq 0) { Set-TenantSection $secFwdUse 'No forwarding found in mailbox settings or mail flow rules' $script:TenantColors.Good }
    elseif ($external -gt 0) {
        Set-TenantSection $secFwdUse "$external send mail outside the tenant: $($s.ExternalMailbox) mailbox(es), $($s.ExternalRules) mail flow rule(s)" $script:TenantColors.Bad
    }
    else { Set-TenantSection $secFwdUse "$($s.Total) forwarding setting(s), all to internal recipients" $script:TenantColors.Good }
    Add-FindingLines $secFwdUse (Format-FindingLines $script:LastFwdUse {
        param($x) "[$(if ($x.Severity) { $x.Severity } else { 'ok' })] $($x.Source) '$($x.Name)' -> $($x.Target) (external: $(Get-YesNo $x.External), keeps copy: $(Get-YesNo $x.KeepsCopy), enabled: $(Get-YesNo $x.Enabled))"
    })
    $txtLog.Text = "Forwarding set on mailboxes and in mail flow rules: $($s.Total) found, $external going outside the tenant.`r`nRed = external destination (a disabled mail flow rule is orange). This does not open every mailbox, so forwarding done by inbox rules is covered by the 'Suspicious inbox rules' scan, and the 'Forwarding to external domains' section above shows whether the tenant blocks external auto-forwarding at all."
}

function Show-InboxScan($r) {
    if (-not $r.Success) { Show-ReadFailure $secInboxScan $r; return }
    $script:LastInboxScan = @($r.Rows)
    $lvInboxScan.BeginUpdate()
    $lvInboxScan.Items.Clear()
    foreach ($row in $script:LastInboxScan) {
        $item = New-Object System.Windows.Forms.ListViewItem([string]$row.Mailbox)
        [void]$item.SubItems.Add([string]$row.Rule)
        [void]$item.SubItems.Add([string]$row.Severity)
        [void]$item.SubItems.Add([string]$row.Findings)
        [void]$item.SubItems.Add((Get-YesNo $row.Hidden))
        [void]$item.SubItems.Add((Get-YesNo $row.Enabled))
        if ($row.Severity -eq 'High') { $item.ForeColor = [System.Drawing.Color]::Firebrick } else { $item.ForeColor = [System.Drawing.Color]::DarkOrange }
        if (-not $row.Enabled) { $item.ForeColor = [System.Drawing.Color]::Gray }
        [void]$lvInboxScan.Items.Add($item)
    }
    Invoke-ListViewSort $lvInboxScan
    $lvInboxScan.EndUpdate()

    $s = $r.Summary
    $secInboxScan.Buttons['Export CSV...'].Enabled = ($s.Flagged -gt 0)
    $mailboxCount = @($script:LastInboxScan | Select-Object -ExpandProperty Mailbox -Unique).Count
    $text = "$($s.Flagged) flagged rule(s) in $mailboxCount of $($s.Mailboxes) mailbox(es): $($s.High) high, $($s.Review) to review ($($s.ExternalForward) forward outside, $($s.Hidden) hidden)"
    $color = $script:TenantColors.Good
    if ($s.Review -gt 0 -or $s.Failed -gt 0) { $color = $script:TenantColors.Warn }
    if ($s.High -gt 0) { $color = $script:TenantColors.Bad }
    if ($s.Flagged -eq 0 -and $s.Failed -eq 0) { $text = "No suspicious inbox rules in $($s.Mailboxes) mailbox(es)" }
    elseif ($s.Failed -gt 0) { $text += "; $($s.Failed) mailbox(es) could not be read" }
    Set-TenantSection $secInboxScan $text $color
    Add-FindingLines $secInboxScan (Format-FindingLines $script:LastInboxScan {
        param($x) "[$($x.Severity)] $($x.Mailbox) - rule '$($x.Rule)'$(if ($x.Hidden) { ' (HIDDEN)' }): $($x.Findings)"
    })
    if ($s.Failed -gt 0) { Add-FindingLines $secInboxScan (@("Mailboxes that could not be read ($($s.Failed)):") + @($s.FailedDetail | Select-Object -First 50 | ForEach-Object { "  $_" })) }

    $lines = @("Scanned $($s.Mailboxes) mailbox(es): $($s.Flagged) flagged inbox rule(s), $($s.High) high, $($s.Review) to review.")
    $lines += 'Red = very likely malicious or unsafe: forwards outside the tenant, deletes or hides mail about security or money, deletes everything, or is hidden from Outlook and OWA. Orange = unusual and worth a look (internal forwards, odd names, moving mail to RSS/Junk/Archive). The built-in hidden Junk E-mail Rule is ignored.'
    if ($s.Failed -gt 0) { $lines += "$($s.Failed) mailbox(es) could not be read (first: $($s.FailedDetail[0])). Reading rules needs rights such as Organization Management; Global Reader is not enough." }
    $txtLog.Text = $lines -join "`r`n"
}

function Show-Attachment($r) {
    if (-not $r.Success) { Show-ReadFailure $secAttach $r; return }
    $policies = @($r.Policies)
    $lines = @()
    foreach ($p in $policies) {
        $missing = 'none'
        if ($p.MissingHighRisk.Count -gt 0) { $missing = $p.MissingHighRisk -join ', ' }
        $filter = 'OFF'
        if ($p.EnableFileFilter) { $filter = 'ON' }
        $zap = 'off'
        if ($p.ZapEnabled) { $zap = 'on' }
        $tag = ''
        if ($p.IsDefault) { $tag = ' (default)' }
        $lines += "$($p.Name)${tag}: file filter $filter, action $($p.FileTypeAction), $($p.FileTypeCount) file types, common risky types missing: $missing, zero-hour auto purge $zap"
    }
    $detail = $lines -join "`r`n"
    $default = $policies | Where-Object { $_.IsDefault } | Select-Object -First 1
    $offCustom = @($policies | Where-Object { -not $_.IsDefault -and -not $_.EnableFileFilter })
    if ($policies.Count -eq 0) { Set-TenantSection $secAttach 'No anti-malware policies were returned' $script:TenantColors.Warn $detail }
    elseif (-not $default) { Set-TenantSection $secAttach 'No default anti-malware policy found' $script:TenantColors.Warn $detail }
    elseif (-not $default.EnableFileFilter) {
        Set-TenantSection $secAttach 'OFF on the default policy - risky attachment types are not blocked' $script:TenantColors.Bad $detail
    }
    elseif ($offCustom.Count -gt 0) {
        Set-TenantSection $secAttach "ON by default, but OFF in $($offCustom.Count) custom policy(ies)" $script:TenantColors.Warn $detail
    }
    elseif ($default.MissingHighRisk.Count -gt 0) {
        Set-TenantSection $secAttach 'ON, but the default file-type list is missing common risky types' $script:TenantColors.Warn $detail
    }
    else { Set-TenantSection $secAttach "ON in all $($policies.Count) polic(ies); the list covers the common risky types" $script:TenantColors.Good $detail }
}

function Show-Dkim($r) {
    if (-not $r.Success) { Show-ReadFailure $secDkim $r; return }
    $rows = @($r.Rows)
    $lines = @()
    foreach ($row in $rows) {
        if ($row.Enabled -eq $true) { $lines += "$($row.Domain): DKIM ON ($($row.Status))" }
        else {
            $extra = ''
            if ($row.Dns) { $extra = " - $($row.Dns)" }
            $lines += "$($row.Domain): DKIM OFF ($($row.Status))$extra"
        }
    }
    $detail = $lines -join "`r`n"
    $s = $r.Summary
    if ($s.Domains -eq 0) { Set-TenantSection $secDkim 'No domains found' $script:TenantColors.Warn $detail }
    elseif ($s.Missing -gt 0) { Set-TenantSection $secDkim "DKIM is off on $($s.Missing) of $($s.Domains) domain(s)" $script:TenantColors.Bad $detail }
    elseif ($s.Enabled -lt $s.Domains) { Set-TenantSection $secDkim 'DKIM is on for every custom domain (a Microsoft-managed domain is not signing)' $script:TenantColors.Warn $detail }
    else { Set-TenantSection $secDkim "DKIM signing is enabled on all $($s.Domains) domain(s)" $script:TenantColors.Good $detail }
}

function Show-MailAuth($r) {
    if (-not $r.Success) { Show-ReadFailure $secMailAuth $r; return }
    $script:LastMailAuth = @($r.Rows)
    $lvMailAuth.BeginUpdate()
    $lvMailAuth.Items.Clear()
    foreach ($row in $script:LastMailAuth) {
        $item = New-Object System.Windows.Forms.ListViewItem([string]$row.Domain)
        [void]$item.SubItems.Add([string]$row.Spf)
        [void]$item.SubItems.Add([string]$row.SpfLookups)
        [void]$item.SubItems.Add([string]$row.Dmarc)
        [void]$item.SubItems.Add([string]$row.DmarcReports)
        [void]$item.SubItems.Add([string]$row.Findings)
        if ($row.Severity -eq 'High') { $item.ForeColor = [System.Drawing.Color]::Firebrick }
        elseif ($row.Severity -eq 'Review') { $item.ForeColor = [System.Drawing.Color]::DarkOrange }
        elseif ($row.Skipped) { $item.ForeColor = [System.Drawing.Color]::Gray }
        [void]$lvMailAuth.Items.Add($item)
    }
    Invoke-ListViewSort $lvMailAuth
    $lvMailAuth.EndUpdate()

    $s = $r.Summary
    $secMailAuth.Buttons['Export CSV...'].Enabled = (@($script:LastMailAuth).Count -gt 0)
    if ($s.Domains -eq 0) { Set-TenantSection $secMailAuth 'No domains to check' $script:TenantColors.Warn }
    else {
        $text = "$($s.Domains) domain(s): $($s.High) with serious gaps, $($s.Review) to review; DMARC enforcing on $($s.DmarcEnforced); no SPF on $($s.NoSpf), no DMARC on $($s.NoDmarc)"
        $color = $script:TenantColors.Good
        if ($s.Review -gt 0) { $color = $script:TenantColors.Warn }
        if ($s.High -gt 0) { $color = $script:TenantColors.Bad }
        Set-TenantSection $secMailAuth $text $color
    }
    Add-FindingLines $secMailAuth (Format-FindingLines $script:LastMailAuth {
        param($x)
        $head = "[$(if ($x.Severity) { $x.Severity } else { 'ok' })] $($x.Domain): SPF $($x.Spf)"
        if ($null -ne $x.SpfLookups) { $head += " ($($x.SpfLookups) lookups)" }
        $head += "; DMARC $($x.Dmarc)"
        if ($x.Findings) { $head += " - $($x.Findings)" }
        $head
    })
    $txtLog.Text = (@(
        "SPF and DMARC read from public DNS for $($s.Domains) domain(s) (a public resolver is asked first so an internal DNS zone cannot hide or fake the records).",
        'Red = serious gap: no SPF or DMARC record, more than one record, SPF ending in +all or needing more than 10 DNS lookups. Orange = worth tightening: DMARC p=none (monitoring only), pct below 100, no aggregate reports (rua), SPF close to the lookup limit or not authorizing Microsoft 365.',
        'SPF -all (hard fail) or ~all (soft fail) and DMARC p=quarantine or p=reject together are what actually stop someone sending as your domain. Subdomains inherit the parent domain''s DMARC record when they have none of their own.'
    ) -join "`r`n")
}

$secFwdUse.Buttons['Scan for External Forwarding'].add_Click({
    $progress = [hashtable]::Synchronized(@{ Text = '' })
    Invoke-TenantAction -Status 'Scanning for external forwarding' -Cancellable -Progress $progress -WorkerArgs @($progress) `
        -Worker { param($p) Get-TenantExternalForwardingUse -Progress $p } -Render { param($r) Show-ForwardingUse $r }
})
$secFwdUse.Buttons['Export CSV...'].add_Click({
    Export-TenantCsv $script:LastFwdUse @('Source', 'Name', 'Target', 'External', 'KeepsCopy', 'Enabled', 'Severity', 'Detail') 'ExternalForwarding'
})

$secInboxScan.Buttons['Scan All Mailboxes'].add_Click({
    $progress = [hashtable]::Synchronized(@{ Text = '' })
    Invoke-TenantAction -Status 'Scanning mailboxes for suspicious inbox rules' -Cancellable -Progress $progress `
        -WorkerArgs @($progress, [bool]$chkScanShared.Checked) `
        -Worker { param($p, $shared) Get-TenantSuspiciousInboxRules -Progress $p -IncludeSharedMailboxes $shared } -Render { param($r) Show-InboxScan $r }
})
$secInboxScan.Buttons['Export CSV...'].add_Click({
    Export-TenantCsv $script:LastInboxScan @('Mailbox', 'DisplayName', 'Rule', 'Enabled', 'Priority', 'Severity', 'Hidden', 'ExternalTargets', 'Findings', 'Detail') 'SuspiciousInboxRules'
})

$secAttach.Buttons['Check'].add_Click({
    Invoke-TenantAction -Status 'Checking the common attachment filter' -Cancellable -Worker { Get-TenantAttachmentFilterStatus } -Render { param($r) Show-Attachment $r }
})

$secDkim.Buttons['Check'].add_Click({
    $progress = [hashtable]::Synchronized(@{ Text = '' })
    Invoke-TenantAction -Status 'Checking DKIM' -Cancellable -Progress $progress -WorkerArgs @($progress) `
        -Worker { param($p) Get-TenantDkimStatus -Progress $p } -Render { param($r) Show-Dkim $r }
})

$secMailAuth.Buttons['Check'].add_Click({
    $progress = [hashtable]::Synchronized(@{ Text = '' })
    Invoke-TenantAction -Status 'Checking SPF and DMARC' -Cancellable -Progress $progress -WorkerArgs @($progress) `
        -Worker { param($p) Get-TenantMailAuthStatus -Progress $p } -Render { param($r) Show-MailAuth $r }
})
$secMailAuth.Buttons['Export CSV...'].add_Click({
    Export-TenantCsv $script:LastMailAuth @('Domain', 'Spf', 'SpfAll', 'SpfLookups', 'SpfRecord', 'Dmarc', 'DmarcPolicy', 'DmarcSubdomainPolicy', 'DmarcPct', 'DmarcReports', 'DmarcSource', 'Severity', 'Findings') 'SpfDmarc'
})

# --- Run all checks / export the findings report ---
$btnRunAll.add_Click({
    if (-not $script:Connected) {
        [System.Windows.Forms.MessageBox]::Show('Connect to the tenant first.', 'Not Connected', 'OK', 'Warning') | Out-Null
        return
    }
    $checks = @($script:TenantCheckList | Where-Object { $chkRunAllSlow.Checked -or -not $_.Slow })
    $onClick = [System.Windows.Forms.Control].GetMethod('OnClick', [System.Reflection.BindingFlags]'NonPublic,Instance')
    $started = Get-Date
    $script:QuietChecks = $true      # a failed check marks its own section instead of raising a dialog
    $script:RunAllCancelled = $false
    $done = 0
    try {
        foreach ($c in $checks) {
            $txtLog.Text = "Running check $($done + 1) of $($checks.Count): $($c.Section.Title)"
            try { [void]$onClick.Invoke($c.Button, @([System.EventArgs]::Empty)) } catch { }
            if ($script:RunAllCancelled) { break }
            $done++
        }
    }
    finally { $script:QuietChecks = $false }

    $titles = @($checks | Select-Object -First $done | ForEach-Object { $_.Section.Title })
    $entries = @($titles | ForEach-Object { $script:TenantReport[$_] } | Where-Object { $_ })
    $problem = @($entries | Where-Object { $_.Severity -eq 'PROBLEM' })
    $review = @($entries | Where-Object { $_.Severity -eq 'REVIEW' })
    $unreadable = @($entries | Where-Object { $_.Severity -eq 'UNREADABLE' })
    $ok = @($entries | Where-Object { $_.Severity -eq 'OK' })
    $seconds = [int]((Get-Date) - $started).TotalSeconds
    $lines = @("Ran $done of $($checks.Count) checks in ${seconds}s: $($problem.Count) problem(s), $($review.Count) to review, $($unreadable.Count) could not be read, $($ok.Count) OK.")
    if ($script:RunAllCancelled) { $lines += 'Stopped early because you cancelled.' }
    if ($problem.Count -gt 0) { $lines += 'PROBLEMS:'; $lines += @($problem | ForEach-Object { "  - $($_.Title): $($_.State)" }) }
    if ($review.Count -gt 0) { $lines += 'TO REVIEW:'; $lines += @($review | ForEach-Object { "  - $($_.Title): $($_.State)" }) }
    if ($unreadable.Count -gt 0) { $lines += 'COULD NOT BE READ:'; $lines += @($unreadable | ForEach-Object { "  - $($_.Title)" }) }
    $lines += "Use 'Export Findings Report...' to save these results."
    $txtLog.Text = $lines -join "`r`n"
})

$btnExportReport.add_Click({
    if ($script:TenantReport.Count -eq 0 -and $script:ChangeJournal.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show('Nothing to report yet: run some checks first (Run All Checks), then export.', 'Nothing To Report', 'OK', 'Information') | Out-Null
        return
    }
    $dlg = New-Object System.Windows.Forms.SaveFileDialog
    $dlg.Filter = 'Text files (*.txt)|*.txt'
    $dlg.FileName = "FindingsReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
    if ($dlg.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        try {
            [System.IO.File]::WriteAllText($dlg.FileName, (New-FindingsReport), (New-Object System.Text.UTF8Encoding($true)))
            $txtLog.Text = "Findings report saved to $($dlg.FileName) ($($script:TenantReport.Count) check result(s), $($script:ChangeJournal.Count) change(s))."
        }
        catch {
            [System.Windows.Forms.MessageBox]::Show("Could not save the report: $($_.Exception.Message)", 'Error', 'OK', 'Error') | Out-Null
        }
    }
})

$form.add_FormClosing({
    param($sender, $e)
    if ($script:WorkerBusy) {
        $e.Cancel = $true
        if ($btnCancel.Visible) {
            $script:CancelRequested = $true
            $btnCancel.Enabled = $false
            $lblStatus.Text = 'Cancelling...'
        }
        else {
            $lblStatus.Text = 'Please wait for the current operation to finish before closing.'
        }
    }
})
$form.add_FormClosed({ Close-Worker })

# PowerShell ISE (and some console hosts) hold foreground focus, and Windows' foreground-lock
# then prevents the newly-shown form from stealing it, so it opens behind the host window.
# Forcing TopMost only at Shown-time, then dropping it, forces the activation without leaving
# the form permanently pinned above other windows.
$form.TopMost = $true
$form.Add_Shown({
    $form.Activate()
    $form.TopMost = $false
})

[System.Windows.Forms.Application]::Run($form)
