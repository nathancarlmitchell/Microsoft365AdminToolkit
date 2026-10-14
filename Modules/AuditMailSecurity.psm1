<#
    Backend for the mail-security checks: external forwarding (per user and tenant-wide), suspicious
    inbox rules across every mailbox, the common attachment filter, DKIM, and SPF / DMARC. Every
    function returns a result object (Success / Error plus data) instead of throwing. All of it is
    read-only; nothing here changes the tenant.
#>
Import-Module (Join-Path $PSScriptRoot 'GraphHelpers.psm1')

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------
function Set-ScanProgress {
    param($Progress, [string] $Text)
    if ($Progress) { $Progress['Text'] = $Text }
}

function Get-AcceptedDomainNames {
    @(Get-AcceptedDomain | ForEach-Object { ([string]$_.DomainName).ToLowerInvariant() })
}

function Get-SmtpAddressFromTarget {
    <#
    .SYNOPSIS
        The SMTP address inside a rule/forwarding target, which Exchange renders in several shapes:
        "Name" [SMTP:user@x.com], smtp:user@x.com, user@x.com. Internal Exchange identities (EX:/o=...)
        have no SMTP address and return $null.
    #>
    param([string] $Target)
    if (-not $Target) { return $null }
    if ($Target -match 'SMTP:([^\]\s>"]+)') { return $Matches[1].ToLowerInvariant() }
    if ($Target -match '([A-Za-z0-9._%+''-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})') { return $Matches[1].ToLowerInvariant() }
    $null
}

function Test-ExternalDomain {
    param([string] $Domain, [string[]] $AcceptedDomains)
    $d = $Domain.ToLowerInvariant()
    foreach ($a in $AcceptedDomains) {
        if ($a -eq $d) { return $false }
        if ($a.StartsWith('*.') -and $d.EndsWith($a.Substring(1))) { return $false }
    }
    $true
}

function Get-ExternalTargets {
    <#
    .SYNOPSIS
        Splits forward/redirect/copy targets into SMTP addresses, the subset outside the tenant's
        accepted domains, and targets that are internal Exchange identities with no SMTP address.
    #>
    param($Targets, [string[]] $AcceptedDomains)
    $all = @(); $external = @(); $unresolved = @()
    foreach ($t in @($Targets | Where-Object { $_ })) {
        $address = Get-SmtpAddressFromTarget ([string]$t)
        if (-not $address) { $unresolved += [string]$t; continue }
        $all += $address
        $domain = $address.Substring($address.IndexOf('@') + 1)
        if (Test-ExternalDomain $domain $AcceptedDomains) { $external += $address }
    }
    [pscustomobject]@{ All = $all; External = $external; Unresolved = $unresolved }
}

function Resolve-ForwardingRecipient {
    <#
    .SYNOPSIS
        Turns a mailbox's ForwardingAddress (an internal recipient name) into the SMTP address mail
        really goes to. A mail contact's address is external, so the recipient has to be looked up.
    #>
    param([string] $Identity, [hashtable] $Cache)
    if ($Cache.ContainsKey($Identity)) { return $Cache[$Identity] }
    $resolved = $null
    try {
        $r = Get-Recipient -Identity $Identity -ErrorAction Stop
        if ($r.ExternalEmailAddress) { $resolved = Get-SmtpAddressFromTarget ([string]$r.ExternalEmailAddress) }
        if (-not $resolved) { $resolved = ([string]$r.PrimarySmtpAddress).ToLowerInvariant() }
    }
    catch { $resolved = $null }
    $Cache[$Identity] = $resolved
    $resolved
}

# ---------------------------------------------------------------------------
# Inbox rule classification
# ---------------------------------------------------------------------------
# Words that show up in the conditions of attacker rules: they hide security alerts and replies about
# money, or divert them.
$script:RuleKeywordPattern = 'invoice|payment|wire|bank|remit|password|security|verify|account|transfer|purchase order|paypal|docusign|helpdesk|alert|phish|spam|unauthori[sz]ed|suspicious|mfa|2fa|sign.?in|login|hack|fraud'
$script:HideFolderPattern = 'RSS|Conversation History|Deleted Items|Junk|Archive'
$script:RuleConditionProperties = @('SubjectContainsWords', 'BodyContainsWords', 'SubjectOrBodyContainsWords', 'FromAddressContainsWords', 'From',
    'SentTo', 'HeaderContainsWords', 'RecipientAddressContainsWords', 'HasAttachment', 'FlaggedForAction', 'WithImportance', 'WithSensitivity',
    'MyNameInToBox', 'MyNameInCcBox', 'MyNameInToOrCcBox', 'MyNameNotInToBox', 'SentOnlyToMe', 'FromSubscription', 'MessageTypeMatches')

function Get-RuleProperty {
    param($Rule, [string] $Name)
    if ($Rule.PSObject.Properties.Name -contains $Name) { return $Rule.$Name }
    $null
}

function Get-RuleConditionText {
    param($Rule)
    $parts = @()
    foreach ($n in 'SubjectContainsWords', 'BodyContainsWords', 'SubjectOrBodyContainsWords', 'FromAddressContainsWords', 'From', 'HeaderContainsWords', 'RecipientAddressContainsWords') {
        $parts += @(Get-RuleProperty $Rule $n | Where-Object { $_ } | ForEach-Object { [string]$_ })
    }
    $parts -join ' '
}

function Test-RuleHasConditions {
    param($Rule)
    foreach ($n in $script:RuleConditionProperties) {
        $v = Get-RuleProperty $Rule $n
        if ($v -is [bool]) { if ($v) { return $true }; continue }
        if (@($v | Where-Object { $_ }).Count -gt 0) { return $true }
    }
    $false
}

function Test-InboxRuleSuspicion {
    <#
    .SYNOPSIS
        What looks wrong with one inbox rule. High = very likely malicious or unsafe (forwards outside
        the tenant, hides mail about security or money, deletes everything). Review = unusual.
    #>
    param($Rule, [string[]] $AcceptedDomains)
    $high = @(); $review = @(); $external = @()

    $targets = @(@(Get-RuleProperty $Rule 'ForwardTo') + @(Get-RuleProperty $Rule 'ForwardAsAttachmentTo') + @(Get-RuleProperty $Rule 'RedirectTo') | Where-Object { $_ })
    if ($targets.Count -gt 0) {
        $t = Get-ExternalTargets $targets $AcceptedDomains
        if ($t.External.Count -gt 0) {
            $external = $t.External
            $high += "forwards or redirects to external address: $($t.External -join ', ')"
        }
        else { $review += 'forwards or redirects mail to another recipient' }
    }

    $conditionText = Get-RuleConditionText $Rule
    $keywords = @([regex]::Matches($conditionText, $script:RuleKeywordPattern, 'IgnoreCase') | ForEach-Object { $_.Value.ToLowerInvariant() } | Select-Object -Unique)
    $hasConditions = Test-RuleHasConditions $Rule
    $delete = [bool](Get-RuleProperty $Rule 'DeleteMessage')
    $folder = [string](Get-RuleProperty $Rule 'MoveToFolder')

    if ($delete) {
        if ($keywords.Count -gt 0) { $high += "deletes mail matching: $($keywords -join ', ')" }
        elseif (-not $hasConditions) { $high += 'deletes ALL incoming mail' }
        else { $review += 'deletes matching mail' }
    }
    if ($folder -and ($folder -match $script:HideFolderPattern)) {
        if ($keywords.Count -gt 0) { $high += "moves mail matching '$($keywords -join ', ')' to $folder" }
        else { $review += "moves mail to $folder" }
    }
    if ([bool](Get-RuleProperty $Rule 'MarkAsRead') -and ($delete -or $folder)) { $review += 'marks mail as read so it is not noticed' }

    $name = ([string]$Rule.Name).Trim()
    if ($name.Length -le 2 -or $name -match '^[\W_]+$') { $review += 'unusual rule name' }

    [pscustomobject]@{ High = $high; Review = $review; External = $external; Keywords = $keywords }
}

function Get-RuleKey {
    param($Rule)
    $id = Get-RuleProperty $Rule 'RuleIdentity'
    if ($null -eq $id) { $id = Get-RuleProperty $Rule 'Identity' }
    [string]$id
}

function Get-VisibleRuleKeys {
    param([string] $Mailbox)
    @(Get-InboxRule -Mailbox $Mailbox -ErrorAction Stop | ForEach-Object { Get-RuleKey $_ })
}

function Get-RuleSummaryText {
    param($Rule)
    (([string](Get-RuleProperty $Rule 'Description')) -replace '\s+', ' ').Trim()
}

# ---------------------------------------------------------------------------
# One user: external forwarding
# ---------------------------------------------------------------------------
function Get-UserExternalForwarding {
    <#
    .SYNOPSIS
        Every way mail for one mailbox is forwarded: mailbox-level forwarding and forwarding / redirect
        inbox rules (including rules hidden from Outlook and OWA), each marked external or not.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string] $UserPrincipalName)

    try {
        $domains = Get-AcceptedDomainNames
        $cache = @{}
        $rows = @()
        $mbx = Get-Mailbox -Identity $UserPrincipalName -ErrorAction Stop

        $keepsCopy = [bool]$mbx.DeliverToMailboxAndForward
        if ($mbx.ForwardingSmtpAddress) {
            $address = Get-SmtpAddressFromTarget ([string]$mbx.ForwardingSmtpAddress)
            $external = ($address -and (Test-ExternalDomain $address.Substring($address.IndexOf('@') + 1) $domains))
            $rows += [pscustomobject]@{ Type = 'Mailbox forwarding'; Name = 'ForwardingSmtpAddress'; Target = $address; External = $external
                KeepsCopy = $keepsCopy; Hidden = $false; Enabled = $true; Severity = $(if ($external) { 'High' } else { 'Review' })
                Detail = 'Set on the mailbox itself, not an inbox rule; not visible in Outlook.' }
        }
        if ($mbx.ForwardingAddress) {
            $address = Resolve-ForwardingRecipient ([string]$mbx.ForwardingAddress) $cache
            $external = ($address -and (Test-ExternalDomain $address.Substring($address.IndexOf('@') + 1) $domains))
            $targetText = $address
            if (-not $address) { $targetText = [string]$mbx.ForwardingAddress }
            $rows += [pscustomobject]@{ Type = 'Mailbox forwarding'; Name = 'ForwardingAddress'; Target = $targetText; External = [bool]$external
                KeepsCopy = $keepsCopy; Hidden = $false; Enabled = $true; Severity = $(if ($external) { 'High' } else { 'Review' })
                Detail = 'Set on the mailbox itself, not an inbox rule; not visible in Outlook.' }
        }

        $all = @(Get-InboxRule -Mailbox $UserPrincipalName -IncludeHidden -ErrorAction Stop)
        $visible = @()
        $visibleLoaded = $false
        foreach ($rule in $all) {
            $targets = @(@(Get-RuleProperty $rule 'ForwardTo') + @(Get-RuleProperty $rule 'ForwardAsAttachmentTo') + @(Get-RuleProperty $rule 'RedirectTo') | Where-Object { $_ })
            if ($targets.Count -eq 0) { continue }
            $t = Get-ExternalTargets $targets $domains
            if (-not $visibleLoaded) { $visible = @(Get-VisibleRuleKeys $UserPrincipalName); $visibleLoaded = $true }
            $hidden = (($visible -notcontains (Get-RuleKey $rule)) -and ([string]$rule.Name -ne 'Junk E-mail Rule'))
            $redirect = @(Get-RuleProperty $rule 'RedirectTo' | Where-Object { $_ }).Count -gt 0
            $copy = (-not $redirect) -and (-not [bool](Get-RuleProperty $rule 'DeleteMessage'))
            $isExternal = ($t.External.Count -gt 0)
            $targetText = (@($t.All) + @($t.Unresolved)) -join ', '
            $sev = 'Review'
            if ($isExternal -or $hidden) { $sev = 'High' }
            $rows += [pscustomobject]@{ Type = 'Inbox rule'; Name = [string]$rule.Name; Target = $targetText; External = $isExternal
                KeepsCopy = $copy; Hidden = $hidden; Enabled = [bool]$rule.Enabled; Severity = $sev; Detail = (Get-RuleSummaryText $rule) }
        }

        $rows = @($rows | Sort-Object -Property @{ Expression = { if ($_.External) { 0 } else { 1 } } }, Type, Name)
        $summary = [pscustomobject]@{
            Total    = $rows.Count
            External = @($rows | Where-Object { $_.External }).Count
            Hidden   = @($rows | Where-Object { $_.Hidden }).Count
        }
        [pscustomobject]@{ Success = $true; Error = $null; Rows = $rows; Summary = $summary }
    }
    catch {
        [pscustomobject]@{ Success = $false; Error = (Get-GraphErrorText $_); Rows = @(); Summary = $null }
    }
}

# ---------------------------------------------------------------------------
# Tenant: external forwarding in use (mailbox-level + mail flow rules)
# ---------------------------------------------------------------------------
function Get-TenantExternalForwardingUse {
    <#
    .SYNOPSIS
        Mailboxes that forward to an outside address and mail flow (transport) rules that redirect or
        copy mail to one. Forwarding done by inbox rules is covered by Get-TenantSuspiciousInboxRules,
        which has to open every mailbox.
    #>
    [CmdletBinding()]
    param([hashtable] $Progress)

    try {
        $domains = Get-AcceptedDomainNames
        $cache = @{}
        $rows = @()

        Set-ScanProgress $Progress 'reading mailbox forwarding settings'
        $mailboxes = @(Get-EXOMailbox -ResultSize Unlimited -Properties ForwardingSmtpAddress, ForwardingAddress, DeliverToMailboxAndForward |
            Where-Object { $_.ForwardingSmtpAddress -or $_.ForwardingAddress })
        foreach ($m in $mailboxes) {
            $address = $null
            if ($m.ForwardingSmtpAddress) { $address = Get-SmtpAddressFromTarget ([string]$m.ForwardingSmtpAddress) }
            elseif ($m.ForwardingAddress) { $address = Resolve-ForwardingRecipient ([string]$m.ForwardingAddress) $cache }
            $external = ($address -and (Test-ExternalDomain $address.Substring($address.IndexOf('@') + 1) $domains))
            $targetText = $address
            if (-not $address) { $targetText = [string]$m.ForwardingAddress }
            $upn = [string]$m.UserPrincipalName
            if (-not $upn) { $upn = [string]$m.PrimarySmtpAddress }
            $rows += [pscustomobject]@{ Source = 'Mailbox'; Name = $upn; Target = $targetText; External = [bool]$external
                KeepsCopy = [bool]$m.DeliverToMailboxAndForward; Enabled = $true
                Severity = $(if ($external) { 'High' } else { '' }); Detail = 'Forwarding set on the mailbox' }
        }

        Set-ScanProgress $Progress 'reading mail flow rules'
        foreach ($r in @(Get-TransportRule -ResultSize Unlimited)) {
            $redirect = @($r.RedirectMessageTo | Where-Object { $_ })
            $copies = @(@($r.BlindCopyTo) + @($r.CopyTo) | Where-Object { $_ })
            if (($redirect.Count + $copies.Count) -eq 0) { continue }
            $t = Get-ExternalTargets (@($redirect) + @($copies)) $domains
            $enabled = ([string]$r.State -eq 'Enabled')
            $isExternal = ($t.External.Count -gt 0)
            $sev = ''
            if ($isExternal -and $enabled) { $sev = 'High' } elseif ($isExternal) { $sev = 'Review' }
            $rows += [pscustomobject]@{ Source = 'Mail flow rule'; Name = [string]$r.Name; Target = ((@($t.All) + @($t.Unresolved)) -join ', '); External = $isExternal
                KeepsCopy = ($redirect.Count -eq 0); Enabled = $enabled; Severity = $sev
                Detail = "Priority $($r.Priority), $(if ($redirect.Count) { 'redirects' } else { 'copies' }) matching mail" }
        }

        $rows = @($rows | Sort-Object -Property @{ Expression = { if ($_.Severity -eq 'High') { 0 } elseif ($_.Severity -eq 'Review') { 1 } else { 2 } } }, Source, Name)
        $summary = [pscustomobject]@{
            Total            = $rows.Count
            ExternalMailbox  = @($rows | Where-Object { $_.Source -eq 'Mailbox' -and $_.External }).Count
            ExternalRules    = @($rows | Where-Object { $_.Source -eq 'Mail flow rule' -and $_.External }).Count
            InternalOnly     = @($rows | Where-Object { -not $_.External }).Count
        }
        Set-ScanProgress $Progress 'done'
        [pscustomobject]@{ Success = $true; Error = $null; Rows = $rows; Summary = $summary }
    }
    catch {
        [pscustomobject]@{ Success = $false; Error = (Get-GraphErrorText $_); Rows = @(); Summary = $null }
    }
}

# ---------------------------------------------------------------------------
# Tenant: suspicious inbox rules in every mailbox
# ---------------------------------------------------------------------------
function Get-TenantSuspiciousInboxRules {
    <#
    .SYNOPSIS
        Opens every user mailbox and flags inbox rules that look like business-email-compromise
        persistence: external forwards, rules that delete or hide mail about security or money, rules
        that delete everything, odd rule names, and rules hidden from Outlook and OWA. Slow on a large
        tenant (one call per mailbox), so it reports progress and can be cancelled.
    #>
    [CmdletBinding()]
    param([hashtable] $Progress, [bool] $IncludeSharedMailboxes = $false)

    try {
        $domains = Get-AcceptedDomainNames
        $types = 'UserMailbox'
        if ($IncludeSharedMailboxes) { $types = 'UserMailbox', 'SharedMailbox' }
        Set-ScanProgress $Progress 'listing mailboxes'
        $mailboxes = @(Get-EXOMailbox -ResultSize Unlimited -RecipientTypeDetails $types -Properties PrimarySmtpAddress, DisplayName)

        $rows = @()
        $failed = @()
        $n = 0
        foreach ($m in $mailboxes) {
            $n++
            $address = [string]$m.PrimarySmtpAddress
            Set-ScanProgress $Progress "scanning mailbox $n of $($mailboxes.Count)"
            try {
                $rules = @(Get-InboxRule -Mailbox $address -IncludeHidden -ErrorAction Stop)
                $flagged = @()
                foreach ($rule in $rules) {
                    $s = Test-InboxRuleSuspicion $rule $domains
                    if ($s.High.Count -gt 0 -or $s.Review.Count -gt 0) { $flagged += [pscustomobject]@{ Rule = $rule; Result = $s } }
                }
                if ($flagged.Count -eq 0) { continue }

                # Only for mailboxes that already have a flagged rule: which of those are hidden from Outlook / OWA?
                $visible = @(Get-VisibleRuleKeys $address)
                foreach ($f in $flagged) {
                    $hidden = (($visible -notcontains (Get-RuleKey $f.Rule)) -and ([string]$f.Rule.Name -ne 'Junk E-mail Rule'))
                    $high = @($f.Result.High); $review = @($f.Result.Review)
                    if ($hidden) { $high += 'hidden from Outlook and OWA' }
                    $sev = 'Review'
                    if ($high.Count -gt 0) { $sev = 'High' }
                    $rows += [pscustomobject]@{
                        Mailbox         = $address
                        DisplayName     = [string]$m.DisplayName
                        Rule            = [string]$f.Rule.Name
                        Enabled         = [bool]$f.Rule.Enabled
                        Priority        = $f.Rule.Priority
                        Severity        = $sev
                        Hidden          = $hidden
                        ExternalTargets = ($f.Result.External -join ', ')
                        Findings        = ((@($high) + @($review)) -join '; ')
                        Detail          = (Get-RuleSummaryText $f.Rule)
                    }
                }
            }
            catch {
                $failed += "${address}: $(Get-GraphErrorText $_)"
            }
        }

        $rows = @($rows | Sort-Object -Property @{ Expression = { if ($_.Severity -eq 'High') { 0 } else { 1 } } }, Mailbox, Rule)
        $summary = [pscustomobject]@{
            Mailboxes       = $mailboxes.Count
            Failed          = $failed.Count
            FailedDetail    = $failed
            Flagged         = $rows.Count
            High            = @($rows | Where-Object { $_.Severity -eq 'High' }).Count
            Review          = @($rows | Where-Object { $_.Severity -eq 'Review' }).Count
            ExternalForward = @($rows | Where-Object { $_.ExternalTargets }).Count
            Hidden          = @($rows | Where-Object { $_.Hidden }).Count
        }
        Set-ScanProgress $Progress 'done'
        [pscustomobject]@{ Success = $true; Error = $null; Rows = $rows; Summary = $summary }
    }
    catch {
        [pscustomobject]@{ Success = $false; Error = (Get-GraphErrorText $_); Rows = @(); Summary = $null }
    }
}

# ---------------------------------------------------------------------------
# Tenant: common attachment filter (anti-malware policies)
# ---------------------------------------------------------------------------
$script:HighRiskFileTypes = @('exe', 'bat', 'cmd', 'com', 'scr', 'vbs', 'vbe', 'js', 'jse', 'jar', 'msi', 'wsf', 'hta', 'lnk')

function Get-TenantAttachmentFilterStatus {
    [CmdletBinding()]
    param()
    try {
        $policies = @(Get-MalwareFilterPolicy | ForEach-Object {
            $types = @($_.FileTypes | ForEach-Object { ([string]$_).ToLowerInvariant().TrimStart('.') } | Where-Object { $_ })
            $isDefault = ([string]$_.Name -eq 'Default')
            if ($_.PSObject.Properties.Name -contains 'IsDefault' -and $_.IsDefault) { $isDefault = $true }
            [pscustomobject]@{
                Name             = [string]$_.Name
                IsDefault        = $isDefault
                EnableFileFilter = [bool]$_.EnableFileFilter
                FileTypeAction   = [string]$_.FileTypeAction
                FileTypeCount    = $types.Count
                MissingHighRisk  = @($script:HighRiskFileTypes | Where-Object { $types -notcontains $_ })
                ZapEnabled       = [bool]$_.ZapEnabled
            }
        })
        [pscustomobject]@{ Success = $true; Error = $null; Policies = $policies }
    }
    catch {
        [pscustomobject]@{ Success = $false; Error = (Get-GraphErrorText $_); Policies = @() }
    }
}

# ---------------------------------------------------------------------------
# DNS helper, then DKIM and SPF / DMARC
# ---------------------------------------------------------------------------
function Resolve-DnsRecord {
    <#
    .SYNOPSIS
        TXT or CNAME records for a name. Asks a public resolver first, so an internal (split-horizon)
        DNS zone can't hide or fake the public records, then falls back to the system resolver if the
        public one is unreachable. An authoritative "no such name" is an answer (Ok, no records);
        only a network failure on every resolver is Ok = $false.
    #>
    param([Parameter(Mandatory)] [string] $Name, [ValidateSet('TXT', 'CNAME')] [string] $Type = 'TXT')

    foreach ($server in @('1.1.1.1', '')) {
        try {
            $query = @{ Name = $Name; Type = $Type; DnsOnly = $true; ErrorAction = 'Stop' }
            if ($server) { $query['Server'] = $server }
            $answers = @(Resolve-DnsName @query | Where-Object { $_.Type -eq $Type })
            if ($Type -eq 'TXT') { $records = @($answers | ForEach-Object { (@($_.Strings) -join '') }) }
            else { $records = @($answers | ForEach-Object { [string]$_.NameHost }) }
            $resolver = 'system resolver'
            if ($server) { $resolver = $server }
            return [pscustomobject]@{ Ok = $true; Records = $records; Resolver = $resolver }
        }
        catch {
            $text = "$($_.FullyQualifiedErrorId) $($_.Exception.Message)"
            if ($text -match 'RCODE_NAME_ERROR|does not exist|NXDOMAIN|No such host') {
                $resolver = 'system resolver'
                if ($server) { $resolver = $server }
                return [pscustomobject]@{ Ok = $true; Records = @(); Resolver = $resolver }
            }
        }
    }
    [pscustomobject]@{ Ok = $false; Records = @(); Resolver = '' }
}

function Get-TenantDkimStatus {
    [CmdletBinding()]
    param([hashtable] $Progress)
    try {
        $domains = @(Get-AcceptedDomainNames)
        $configs = @(Get-DkimSigningConfig)
        $rows = @()
        $n = 0
        foreach ($d in ($domains | Sort-Object)) {
            $n++
            Set-ScanProgress $Progress "checking DKIM for $d ($n/$($domains.Count))"
            $isMicrosoft = $d.EndsWith('.onmicrosoft.com')
            $c = $configs | Where-Object { (([string]$_.Domain).ToLowerInvariant() -eq $d) -or (([string]$_.Name).ToLowerInvariant() -eq $d) } | Select-Object -First 1

            $enabled = $null
            $status = 'No DKIM configuration'
            if ($c) { $enabled = [bool]$c.Enabled; $status = [string]$c.Status }

            $dns = ''
            if ($enabled -ne $true -and -not $isMicrosoft) {
                $s1 = Resolve-DnsRecord -Name "selector1._domainkey.$d" -Type CNAME
                $s2 = Resolve-DnsRecord -Name "selector2._domainkey.$d" -Type CNAME
                if (-not $s1.Ok -or -not $s2.Ok) { $dns = 'selector CNAMEs could not be looked up' }
                elseif ($s1.Records.Count -gt 0 -and $s2.Records.Count -gt 0) { $dns = 'both selector CNAMEs are published - ready to enable' }
                elseif ($s1.Records.Count -gt 0 -or $s2.Records.Count -gt 0) { $dns = 'only one selector CNAME is published' }
                else { $dns = 'selector CNAMEs are not published yet' }
            }

            $sev = ''
            if ($enabled -ne $true) { if ($isMicrosoft) { $sev = 'Review' } else { $sev = 'High' } }
            $rows += [pscustomobject]@{ Domain = $d; Enabled = $enabled; Status = $status; Dns = $dns; MicrosoftDomain = $isMicrosoft; Severity = $sev }
        }
        $summary = [pscustomobject]@{
            Domains  = $rows.Count
            Enabled  = @($rows | Where-Object { $_.Enabled -eq $true }).Count
            Missing  = @($rows | Where-Object { $_.Severity -eq 'High' }).Count
        }
        Set-ScanProgress $Progress 'done'
        [pscustomobject]@{ Success = $true; Error = $null; Rows = $rows; Summary = $summary }
    }
    catch {
        [pscustomobject]@{ Success = $false; Error = (Get-GraphErrorText $_); Rows = @(); Summary = $null }
    }
}

function Measure-SpfRecord {
    <#
    .SYNOPSIS
        Counts the DNS-lookup terms (include, a, mx, ptr, exists, redirect) in an SPF record, following
        include / redirect into the records they point at. More than 10 breaks SPF evaluation.
    #>
    param([string] $Record, $State, [int] $Depth = 0)
    foreach ($token in @($Record -split '\s+' | Where-Object { $_ })) {
        $t = $token.ToLowerInvariant().TrimStart('+', '-', '~', '?')
        if ($t -match '^include:(.+)$' -or $t -match '^redirect=(.+)$') {
            $target = $Matches[1]
            $State.Lookups++
            $State.Includes += $target
            if ($Depth -lt 5 -and $State.Queries -lt 20) {
                $State.Queries++
                $inc = Resolve-DnsRecord -Name $target -Type TXT
                $spf = @($inc.Records | Where-Object { $_ -match '^\s*v=spf1' })
                if ($spf.Count -gt 0) { Measure-SpfRecord $spf[0] $State ($Depth + 1) }
            }
        }
        elseif ($t -match '^(a|mx)([:/]|$)' -or $t -match '^ptr' -or $t -match '^exists:') { $State.Lookups++ }
    }
}

function Get-DmarcRecord {
    param([string] $Domain)
    $labels = $Domain.Split('.')
    for ($i = 0; $i -le ($labels.Count - 2); $i++) {
        $candidate = ($labels[$i..($labels.Count - 1)] -join '.')
        $res = Resolve-DnsRecord -Name "_dmarc.$candidate" -Type TXT
        if (-not $res.Ok) { return [pscustomobject]@{ Ok = $false; Records = @(); Source = '' } }
        $recs = @($res.Records | Where-Object { $_ -match '^\s*v=DMARC1' })
        if ($recs.Count -gt 0) { return [pscustomobject]@{ Ok = $true; Records = $recs; Source = $candidate } }
    }
    [pscustomobject]@{ Ok = $true; Records = @(); Source = '' }
}

function Get-TenantMailAuthStatus {
    <#
    .SYNOPSIS
        SPF and DMARC for every accepted domain, read from public DNS: is there a record, is it valid
        (one record, under 10 lookups), how strict is it (-all / ~all, p=none / quarantine / reject),
        and is it reporting. Microsoft's own *.onmicrosoft.com domains are skipped.
    #>
    [CmdletBinding()]
    param([hashtable] $Progress)
    try {
        $domains = @(Get-AcceptedDomainNames | Sort-Object)
        $rows = @()
        $n = 0
        foreach ($d in $domains) {
            $n++
            Set-ScanProgress $Progress "checking SPF and DMARC for $d ($n/$($domains.Count))"
            if ($d.EndsWith('.onmicrosoft.com')) {
                $rows += [pscustomobject]@{ Domain = $d; Spf = 'Microsoft-managed'; SpfAll = ''; SpfLookups = $null; SpfRecord = ''
                    Dmarc = 'n/a'; DmarcPolicy = ''; DmarcSubdomainPolicy = ''; DmarcPct = ''; DmarcReports = ''; DmarcSource = ''
                    Findings = ''; Severity = ''; Skipped = $true }
                continue
            }

            $high = @(); $review = @()

            # ---- SPF ----
            $spfText = 'None'; $allQualifier = ''; $lookups = $null; $spfRecord = ''
            $txt = Resolve-DnsRecord -Name $d -Type TXT
            if (-not $txt.Ok) { $spfText = 'DNS lookup failed'; $review += 'SPF could not be looked up (DNS unreachable)' }
            else {
                $spf = @($txt.Records | Where-Object { $_ -match '^\s*v=spf1' })
                if ($spf.Count -eq 0) { $high += 'no SPF record'; $spfText = 'None' }
                else {
                    if ($spf.Count -gt 1) { $high += "$($spf.Count) SPF records published - only one is allowed, so SPF fails" }
                    $spfRecord = $spf[0]
                    $state = @{ Queries = 0; Lookups = 0; Includes = @() }
                    Measure-SpfRecord $spfRecord $state
                    $lookups = $state.Lookups
                    $allToken = @($spfRecord -split '\s+' | Where-Object { $_ -match '^[+\-~?]?all$' } | Select-Object -First 1)
                    if ($allToken.Count -gt 0) {
                        $q = $allToken[0].Substring(0, $allToken[0].Length - 3)
                        if (-not $q) { $q = '+' }
                        $allQualifier = "${q}all"
                    }
                    elseif ($spfRecord -notmatch 'redirect=') { $allQualifier = '(none)' }

                    switch ($allQualifier) {
                        '-all' { $spfText = 'Hard fail (-all)' }
                        '~all' { $spfText = 'Soft fail (~all)' }
                        '?all' { $spfText = 'Neutral (?all)'; $review += 'SPF ends in ?all, which says nothing about unauthorized senders' }
                        '+all' { $spfText = 'Allows everyone (+all)'; $high += 'SPF ends in +all, which authorizes any server to send as this domain' }
                        '(none)' { $spfText = 'No all mechanism'; $review += 'SPF has no all mechanism, so unlisted senders are not covered' }
                        default { $spfText = 'Redirect' }
                    }
                    if ($lookups -gt 10) { $high += "SPF needs $lookups DNS lookups (limit 10), so receivers return a permanent error" }
                    elseif ($lookups -ge 8) { $review += "SPF uses $lookups of the 10 allowed DNS lookups" }
                    $allText = $spfRecord + ' ' + (@($state.Includes) -join ' ')
                    if ($allText -notmatch 'spf\.protection\.outlook\.com') { $review += 'SPF does not authorize Microsoft 365 (include:spf.protection.outlook.com)' }
                }
            }

            # ---- DMARC ----
            $dmarcText = 'None'; $policy = ''; $subPolicy = ''; $pct = ''; $reports = ''; $source = ''
            $dm = Get-DmarcRecord $d
            if (-not $dm.Ok) { $dmarcText = 'DNS lookup failed'; $review += 'DMARC could not be looked up (DNS unreachable)' }
            elseif ($dm.Records.Count -eq 0) { $high += 'no DMARC record'; $dmarcText = 'None' }
            else {
                if ($dm.Records.Count -gt 1) { $high += "$($dm.Records.Count) DMARC records published - only one is allowed, so DMARC is ignored" }
                $source = $dm.Source
                $tags = @{}
                foreach ($part in ($dm.Records[0] -split ';')) {
                    $kv = $part.Split('=', 2)
                    if ($kv.Count -eq 2) { $tags[$kv[0].Trim().ToLowerInvariant()] = $kv[1].Trim() }
                }
                $policy = [string]$tags['p']
                $subPolicy = [string]$tags['sp']
                $pct = '100'
                if ($tags.ContainsKey('pct') -and $tags['pct']) { $pct = [string]$tags['pct'] }
                if ($tags.ContainsKey('rua') -and $tags['rua']) { $reports = 'Yes' } else { $reports = 'No' }
                $dmarcText = "p=$policy"
                switch ($policy.ToLowerInvariant()) {
                    'reject'     { }
                    'quarantine' { }
                    'none'       { $review += 'DMARC is p=none: monitoring only, spoofed mail is still delivered' }
                    default      { $high += "DMARC policy is missing or invalid (p=$policy)" }
                }
                $pctValue = 100
                [void][int]::TryParse($pct, [ref]$pctValue)
                if ($pctValue -lt 100 -and $policy -in @('quarantine', 'reject')) { $review += "DMARC applies to only $pctValue% of mail (pct=$pctValue)" }
                if ($reports -eq 'No') { $review += 'DMARC has no aggregate report address (rua), so you will not see who is spoofing you' }
                if ($subPolicy -and $subPolicy.ToLowerInvariant() -eq 'none' -and $policy -in @('quarantine', 'reject')) { $review += 'DMARC subdomain policy (sp=none) is weaker than the main policy' }
                if ($source -and $source -ne $d) { $dmarcText += " (inherited from $source)" }
            }

            $sev = ''
            if ($high.Count -gt 0) { $sev = 'High' } elseif ($review.Count -gt 0) { $sev = 'Review' }
            $rows += [pscustomobject]@{ Domain = $d; Spf = $spfText; SpfAll = $allQualifier; SpfLookups = $lookups; SpfRecord = $spfRecord
                Dmarc = $dmarcText; DmarcPolicy = $policy; DmarcSubdomainPolicy = $subPolicy; DmarcPct = $pct; DmarcReports = $reports; DmarcSource = $source
                Findings = ((@($high) + @($review)) -join '; '); Severity = $sev; Skipped = $false }
        }

        $checked = @($rows | Where-Object { -not $_.Skipped })
        $summary = [pscustomobject]@{
            Domains       = $checked.Count
            High          = @($rows | Where-Object { $_.Severity -eq 'High' }).Count
            Review        = @($rows | Where-Object { $_.Severity -eq 'Review' }).Count
            NoSpf         = @($checked | Where-Object { $_.Spf -eq 'None' }).Count
            NoDmarc       = @($checked | Where-Object { $_.Dmarc -eq 'None' }).Count
            DmarcEnforced = @($checked | Where-Object { $_.DmarcPolicy -in @('quarantine', 'reject') }).Count
        }
        Set-ScanProgress $Progress 'done'
        [pscustomobject]@{ Success = $true; Error = $null; Rows = @($rows | Sort-Object -Property @{ Expression = { if ($_.Severity -eq 'High') { 0 } elseif ($_.Severity -eq 'Review') { 1 } else { 2 } } }, Domain); Summary = $summary }
    }
    catch {
        [pscustomobject]@{ Success = $false; Error = (Get-GraphErrorText $_); Rows = @(); Summary = $null }
    }
}

Export-ModuleMember -Function Get-UserExternalForwarding, Get-TenantExternalForwardingUse, Get-TenantSuspiciousInboxRules, `
    Get-TenantAttachmentFilterStatus, Get-TenantDkimStatus, Get-TenantMailAuthStatus
