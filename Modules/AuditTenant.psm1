<#
    Backend for the "Audit Tenant" tab - tenant-wide security posture checks and the matching
    hardening actions. Every function returns a result object (Success / Error plus data) instead of
    throwing, so the UI can show exactly what happened. Action functions also return Lines (what was
    done) and Status (the setting read back afterwards, in the same shape as the matching Get-
    function). Exchange settings need the Exchange Online session; the rest use Microsoft Graph.
#>

Import-Module (Join-Path $PSScriptRoot 'GraphHelpers.psm1')

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------
function Invoke-GraphPaged {
    param([Parameter(Mandatory)] [string] $Uri)
    $items = @()
    while ($Uri) {
        $page = Invoke-MgGraphRequest -Method GET -Uri $Uri
        if ($page['value']) { $items += @($page['value']) }
        $Uri = $page['@odata.nextLink']
    }
    $items
}

function Add-AdminEntry {
    param($Users, $Id, $DisplayName, $Upn, $Enabled, $RoleLabel, $Via, $IsGlobalAdmin)
    if (-not $Users.ContainsKey($Id)) {
        $Users[$Id] = [pscustomobject]@{
            Id                = $Id
            DisplayName       = $DisplayName
            UserPrincipalName = $Upn
            AccountEnabled    = $Enabled
            IsGlobalAdmin     = $false
            RoleSet           = (New-Object System.Collections.Generic.List[string])
            ViaSet            = (New-Object System.Collections.Generic.List[string])
        }
    }
    $u = $Users[$Id]
    if ($u.RoleSet -notcontains $RoleLabel) { $u.RoleSet.Add($RoleLabel) }
    if ($u.ViaSet -notcontains $Via) { $u.ViaSet.Add($Via) }
    if ($IsGlobalAdmin) { $u.IsGlobalAdmin = $true }
}

# Authentication method types that can satisfy MFA, with the short names shown in the UI.
# Password, email and Temporary Access Pass are deliberately absent: they don't count as MFA.
$script:MfaCapableMethodTypes = @{
    '#microsoft.graph.phoneAuthenticationMethod'                   = 'Phone'
    '#microsoft.graph.microsoftAuthenticatorAuthenticationMethod'  = 'Authenticator'
    '#microsoft.graph.softwareOathAuthenticationMethod'            = 'OATH token'
    '#microsoft.graph.hardwareOathAuthenticationMethod'            = 'Hardware token'
    '#microsoft.graph.fido2AuthenticationMethod'                   = 'Passkey (FIDO2)'
    '#microsoft.graph.windowsHelloForBusinessAuthenticationMethod' = 'Windows Hello'
    '#microsoft.graph.platformCredentialAuthenticationMethod'      = 'Platform credential'
}

function Get-UserMfaSummary {
    <#
    .SYNOPSIS
        Which MFA-capable methods a user has registered. Works on any tenant (it reads the user's
        authentication methods rather than the Premium-only registration report). A failed read gives
        Known = $false so the UI can show "Unknown" instead of wrongly claiming "no MFA".
    #>
    param([Parameter(Mandatory)] [string] $UserId)
    try {
        $methods = Invoke-GraphPaged "https://graph.microsoft.com/v1.0/users/$UserId/authentication/methods"
        $names = @($methods | ForEach-Object { $script:MfaCapableMethodTypes[[string]$_['@odata.type']] } | Where-Object { $_ } | Select-Object -Unique)
        [pscustomobject]@{ Known = $true; HasMfa = ($names.Count -gt 0); Methods = ($names -join ', ') }
    }
    catch {
        [pscustomobject]@{ Known = $false; HasMfa = $null; Methods = '' }
    }
}

# Service plans that make a license a "user license": a mailbox, the Office apps, Teams or SharePoint.
# Admin accounts should not hold one. Licenses without any of these (for example Entra ID P1/P2, which
# admins can legitimately need for Conditional Access or PIM) are shown but not flagged.
$script:ProductivityPlanPattern = '^(EXCHANGE_S_(STANDARD|ENTERPRISE|FOUNDATION|DESKLESS|ESSENTIALS)|OFFICESUBSCRIPTION|OFFICE_BUSINESS|O365_BUSINESS|SHAREPOINT(ENTERPRISE|STANDARD)|TEAMS1|MCOSTANDARD)$'

function Get-SkuCatalog {
    <#
    .SYNOPSIS
        skuId -> @{ Name; ProductivityPlanIds } for every SKU the tenant owns, so an assigned license
        can be named and judged (does it include a mailbox / Office / Teams / SharePoint plan?).
    #>
    $catalog = @{}
    foreach ($s in (Invoke-GraphPaged 'https://graph.microsoft.com/v1.0/subscribedSkus')) {
        $planIds = @(@($s['servicePlans']) |
            Where-Object { $_ -and ([string]$_['servicePlanName']) -match $script:ProductivityPlanPattern } |
            ForEach-Object { [string]$_['servicePlanId'] })
        $catalog[[string]$s['skuId']] = [pscustomobject]@{
            Name                = (Get-LicenseFriendlyName ([string]$s['skuPartNumber']))
            ProductivityPlanIds = $planIds
        }
    }
    $catalog
}

function Get-UserLicenseSummary {
    <#
    .SYNOPSIS
        Names of the licenses a user holds, and which of them are user licenses. A license counts only
        if at least one of its mailbox / Office / Teams / SharePoint plans is not switched off for that
        user (assignedLicenses.disabledPlans).
    #>
    param($AssignedLicenses, $Catalog)
    $names = @()
    $userNames = @()
    foreach ($l in @($AssignedLicenses | Where-Object { $_ })) {
        $skuId = [string]$l['skuId']
        $sku = $Catalog[$skuId]
        if ($sku) { $name = $sku.Name } else { $name = $skuId }
        $names += $name
        if ($sku) {
            $disabled = @(@($l['disabledPlans']) | ForEach-Object { [string]$_ })
            $active = @($sku.ProductivityPlanIds | Where-Object { $disabled -notcontains $_ })
            if ($active.Count -gt 0) { $userNames += $name }
        }
    }
    [pscustomobject]@{ Names = $names; UserLicenseNames = $userNames }
}

# ---------------------------------------------------------------------------
# Exchange Online: organization customization
# ---------------------------------------------------------------------------
function Get-TenantOrgCustomizationStatus {
    [CmdletBinding()]
    param()
    try {
        $c = Get-OrganizationConfig
        $dehydrated = [bool]$c.IsDehydrated
        [pscustomobject]@{ Success = $true; Error = $null; IsDehydrated = $dehydrated; CustomizationEnabled = (-not $dehydrated) }
    }
    catch {
        [pscustomobject]@{ Success = $false; Error = (Get-GraphErrorText $_); IsDehydrated = $null; CustomizationEnabled = $null }
    }
}

function Enable-TenantOrgCustomization {
    [CmdletBinding()]
    param()
    $before = Get-TenantOrgCustomizationStatus
    if (-not $before.Success) {
        return [pscustomobject]@{ Success = $false; Error = $before.Error; Lines = @(); Status = $before }
    }
    if ($before.CustomizationEnabled) {
        return [pscustomobject]@{ Success = $true; Error = $null; Lines = @('Already customized - nothing to do.'); Status = $before }
    }
    try {
        Enable-OrganizationCustomization
        $after = Get-TenantOrgCustomizationStatus
        $lines = @('Enable-OrganizationCustomization completed.')
        if ($after.Success -and -not $after.CustomizationEnabled) {
            $after | Add-Member -NotePropertyName Pending -NotePropertyValue $true -Force
            $lines += 'Exchange can take several minutes before the organization stops showing as dehydrated; check again shortly.'
        }
        [pscustomobject]@{ Success = $true; Error = $null; Lines = $lines; Status = $after }
    }
    catch {
        [pscustomobject]@{ Success = $false; Error = (Get-GraphErrorText $_); Lines = @(); Status = $before }
    }
}

# ---------------------------------------------------------------------------
# Exchange Online: unified audit log
# ---------------------------------------------------------------------------
function Get-TenantUnifiedAuditLogStatus {
    [CmdletBinding()]
    param()
    try {
        $c = Get-AdminAuditLogConfig
        [pscustomobject]@{
            Success        = $true
            Error          = $null
            IsEnabled      = [bool]$c.UnifiedAuditLogIngestionEnabled
            FirstOptInDate = $c.UnifiedAuditLogFirstOptInDate
        }
    }
    catch {
        [pscustomobject]@{ Success = $false; Error = (Get-GraphErrorText $_); IsEnabled = $null; FirstOptInDate = $null }
    }
}

function Enable-TenantUnifiedAuditLog {
    [CmdletBinding()]
    param()
    $before = Get-TenantUnifiedAuditLogStatus
    if (-not $before.Success) {
        return [pscustomobject]@{ Success = $false; Error = $before.Error; Lines = @(); Status = $before }
    }
    if ($before.IsEnabled) {
        return [pscustomobject]@{ Success = $true; Error = $null; Lines = @('Audit log search is already on - nothing to do.'); Status = $before }
    }
    try {
        Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $true
        $after = Get-TenantUnifiedAuditLogStatus
        [pscustomobject]@{
            Success = $true
            Error   = $null
            Lines   = @('Unified audit log ingestion switched on.', 'It can take up to 60 minutes before audit searches return data.')
            Status  = $after
        }
    }
    catch {
        [pscustomobject]@{ Success = $false; Error = (Get-GraphErrorText $_); Lines = @(); Status = $before }
    }
}

# ---------------------------------------------------------------------------
# Exchange Online: Direct Send
# ---------------------------------------------------------------------------
function Get-TenantDirectSendStatus {
    [CmdletBinding()]
    param()
    try {
        $c = Get-OrganizationConfig
        $available = ($c.PSObject.Properties.Name -contains 'RejectDirectSend')
        [pscustomobject]@{
            Success    = $true
            Error      = $null
            Available  = $available
            Rejected   = if ($available) { [bool]$c.RejectDirectSend } else { $null }
        }
    }
    catch {
        [pscustomobject]@{ Success = $false; Error = (Get-GraphErrorText $_); Available = $null; Rejected = $null }
    }
}

function Disable-TenantDirectSend {
    [CmdletBinding()]
    param()
    $before = Get-TenantDirectSendStatus
    if (-not $before.Success) {
        return [pscustomobject]@{ Success = $false; Error = $before.Error; Lines = @(); Status = $before }
    }
    if (-not $before.Available) {
        return [pscustomobject]@{ Success = $false; Error = 'This tenant does not expose the RejectDirectSend setting yet.'; Lines = @(); Status = $before }
    }
    if ($before.Rejected) {
        return [pscustomobject]@{ Success = $true; Error = $null; Lines = @('Direct Send is already rejected - nothing to do.'); Status = $before }
    }
    try {
        Set-OrganizationConfig -RejectDirectSend $true
        $after = Get-TenantDirectSendStatus
        [pscustomobject]@{
            Success = $true
            Error   = $null
            Lines   = @('RejectDirectSend set to True.', 'It can take up to 30 minutes to apply across the tenant.')
            Status  = $after
        }
    }
    catch {
        [pscustomobject]@{ Success = $false; Error = (Get-GraphErrorText $_); Lines = @(); Status = $before }
    }
}

# ---------------------------------------------------------------------------
# Exchange Online: external auto-forwarding (outbound spam filter policies)
# ---------------------------------------------------------------------------
function Get-TenantExternalForwardingStatus {
    [CmdletBinding()]
    param()
    try {
        $policies = @(Get-HostedOutboundSpamFilterPolicy | ForEach-Object {
            [pscustomobject]@{ Name = $_.Name; AutoForwardingMode = [string]$_.AutoForwardingMode; IsDefault = $_.IsDefault }
        })
        [pscustomobject]@{ Success = $true; Error = $null; Policies = $policies }
    }
    catch {
        [pscustomobject]@{ Success = $false; Error = (Get-GraphErrorText $_); Policies = @() }
    }
}

function Disable-TenantExternalForwarding {
    [CmdletBinding()]
    param()
    $before = Get-TenantExternalForwardingStatus
    if (-not $before.Success) {
        return [pscustomobject]@{ Success = $false; Error = $before.Error; Lines = @(); Status = $before }
    }
    $lines = @()
    $failures = @()
    foreach ($p in $before.Policies) {
        if ($p.AutoForwardingMode -eq 'Off') {
            $lines += "$($p.Name): already Off."
            continue
        }
        try {
            Set-HostedOutboundSpamFilterPolicy -Identity $p.Name -AutoForwardingMode Off
            $lines += "$($p.Name): $($p.AutoForwardingMode) -> Off."
        }
        catch {
            $failures += "$($p.Name): $(Get-GraphErrorText $_)"
        }
    }
    $after = Get-TenantExternalForwardingStatus
    [pscustomobject]@{
        Success = ($failures.Count -eq 0)
        Error   = if ($failures.Count -gt 0) { $failures -join '; ' } else { $null }
        Lines   = $lines
        Status  = $after
    }
}

# ---------------------------------------------------------------------------
# Entra ID: password expiration (per verified domain)
# ---------------------------------------------------------------------------
$script:NeverExpires = 2147483647

function Get-TenantPasswordExpirationStatus {
    [CmdletBinding()]
    param()
    try {
        $domains = @(Get-MgDomain -All | ForEach-Object {
            $days = $_.PasswordValidityPeriodInDays
            [pscustomobject]@{
                Id                 = $_.Id
                IsVerified         = [bool]$_.IsVerified
                IsDefault          = [bool]$_.IsDefault
                AuthenticationType = [string]$_.AuthenticationType
                ValidityDays       = $days
                NeverExpires       = ($days -eq $script:NeverExpires)
            }
        })
        [pscustomobject]@{ Success = $true; Error = $null; Domains = $domains }
    }
    catch {
        [pscustomobject]@{ Success = $false; Error = (Get-GraphErrorText $_); Domains = @() }
    }
}

function Set-TenantPasswordsNeverExpire {
    [CmdletBinding()]
    param()
    $before = Get-TenantPasswordExpirationStatus
    if (-not $before.Success) {
        return [pscustomobject]@{ Success = $false; Error = $before.Error; Lines = @(); Status = $before }
    }
    $lines = @()
    $failures = @()
    foreach ($d in $before.Domains) {
        if (-not $d.IsVerified) { $lines += "$($d.Id): skipped (not verified)."; continue }
        if ($d.AuthenticationType -ne 'Managed') { $lines += "$($d.Id): skipped ($($d.AuthenticationType) domain - password policy is managed on-premises)."; continue }
        if ($d.NeverExpires) { $lines += "$($d.Id): already never expires."; continue }
        try {
            Update-MgDomain -DomainId $d.Id -PasswordValidityPeriodInDays $script:NeverExpires
            $lines += "$($d.Id): set to never expire."
        }
        catch {
            $failures += "$($d.Id): $(Get-GraphErrorText $_)"
        }
    }
    $after = Get-TenantPasswordExpirationStatus
    [pscustomobject]@{
        Success = ($failures.Count -eq 0)
        Error   = if ($failures.Count -gt 0) { $failures -join '; ' } else { $null }
        Lines   = $lines
        Status  = $after
    }
}

# ---------------------------------------------------------------------------
# Entra ID: accounts holding admin roles
# ---------------------------------------------------------------------------
function Get-TenantAdminAccounts {
    <#
    .SYNOPSIS
        Every user that holds an Entra ID directory role, either directly or through a role-assignable
        group. Covers active assignments only: PIM-eligible assignments (Entra ID P2) and Exchange
        role groups are not included.
    #>
    [CmdletBinding()]
    param()
    $globalAdminTemplateId = '62e90394-69f5-4237-9190-012177145e10'
    try {
        $roleName = @{}
        $roleIsGa = @{}
        foreach ($d in (Invoke-GraphPaged 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions?$select=id,displayName,templateId')) {
            $roleName[$d['id']] = $d['displayName']
            $roleIsGa[$d['id']] = (($d['templateId'] -eq $globalAdminTemplateId) -or ($d['displayName'] -eq 'Global Administrator'))
        }

        $assignments = Invoke-GraphPaged 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?$expand=principal'

        $users = @{}
        $servicePrincipals = 0
        $groupMembers = @{}

        foreach ($a in $assignments) {
            $roleId = $a['roleDefinitionId']
            $label = if ($roleName.ContainsKey($roleId)) { $roleName[$roleId] } else { $roleId }
            if ($a['directoryScopeId'] -and $a['directoryScopeId'] -ne '/') { $label += ' (scoped)' }
            $isGa = [bool]$roleIsGa[$roleId]
            $p = $a['principal']
            if (-not $p) { continue }

            switch ($p['@odata.type']) {
                '#microsoft.graph.user' {
                    Add-AdminEntry $users $p['id'] $p['displayName'] $p['userPrincipalName'] $p['accountEnabled'] $label 'Direct' $isGa
                }
                '#microsoft.graph.group' {
                    $gid = $p['id']
                    if (-not $groupMembers.ContainsKey($gid)) {
                        $groupMembers[$gid] = @(Invoke-GraphPaged ('https://graph.microsoft.com/v1.0/groups/' + $gid + '/transitiveMembers/microsoft.graph.user?$select=id,displayName,userPrincipalName,accountEnabled'))
                    }
                    foreach ($m in $groupMembers[$gid]) {
                        Add-AdminEntry $users $m['id'] $m['displayName'] $m['userPrincipalName'] $m['accountEnabled'] $label ("Group: " + $p['displayName']) $isGa
                    }
                }
                '#microsoft.graph.servicePrincipal' { $servicePrincipals++ }
            }
        }

        # Licenses: the tenant's SKUs once, then each admin's assigned licenses in one batched call.
        $catalog = $null
        $licenseResults = @{}
        $licenseUrlFormat = '/users/{0}?$select=id,assignedLicenses'
        try {
            $catalog = Get-SkuCatalog
            $licenseUrls = @($users.Values | ForEach-Object { $licenseUrlFormat -f $_.Id })
            if ($licenseUrls.Count -gt 0) { $licenseResults = Invoke-GraphBatchGet -RelativeUrls $licenseUrls }
        }
        catch { $catalog = $null }

        $records = @($users.Values | ForEach-Object {
            $mfa = Get-UserMfaSummary -UserId $_.Id
            $licenseText = 'Unknown'
            $licenseNames = ''
            $hasLicense = $null
            $hasUserLicense = $null
            $lr = $licenseResults[($licenseUrlFormat -f $_.Id)]
            if ($catalog -and $lr -and $lr.Status -eq 200 -and $lr.Body) {
                $summary = Get-UserLicenseSummary -AssignedLicenses $lr.Body['assignedLicenses'] -Catalog $catalog
                $hasLicense = ($summary.Names.Count -gt 0)
                $hasUserLicense = ($summary.UserLicenseNames.Count -gt 0)
                $licenseNames = ($summary.Names -join ', ')
                if ($hasUserLicense) {
                    $licenseText = 'USER LICENSE: ' + ($summary.UserLicenseNames -join ', ')
                    $others = @($summary.Names | Where-Object { $summary.UserLicenseNames -notcontains $_ })
                    if ($others.Count -gt 0) { $licenseText += ' (+ ' + ($others -join ', ') + ')' }
                }
                elseif ($hasLicense) { $licenseText = 'Other: ' + $licenseNames }
                else { $licenseText = 'None' }
            }
            $mfaText = 'Unknown'
            if ($mfa.Known -and $mfa.HasMfa) { $mfaText = "Yes: $($mfa.Methods)" }
            elseif ($mfa.Known) { $mfaText = 'NONE' }
            [pscustomobject]@{
                Id                = $_.Id
                DisplayName       = $_.DisplayName
                UserPrincipalName = $_.UserPrincipalName
                AccountEnabled    = $_.AccountEnabled
                IsGlobalAdmin     = $_.IsGlobalAdmin
                HasMfa            = $mfa.HasMfa
                MfaMethods        = $mfa.Methods
                Mfa               = $mfaText
                Licenses          = $licenseNames
                HasLicense        = $hasLicense
                HasUserLicense    = $hasUserLicense
                LicenseText       = $licenseText
                RoleCount         = $_.RoleSet.Count
                Roles             = (($_.RoleSet | Sort-Object) -join '; ')
                Assignment        = (($_.ViaSet | Sort-Object) -join '; ')
            }
        } | Sort-Object -Property @{ Expression = 'IsGlobalAdmin'; Descending = $true }, DisplayName)

        [pscustomobject]@{ Success = $true; Error = $null; Users = $records; ServicePrincipalCount = $servicePrincipals }
    }
    catch {
        [pscustomobject]@{ Success = $false; Error = (Get-GraphErrorText $_); Users = @(); ServicePrincipalCount = 0 }
    }
}

# ---------------------------------------------------------------------------
# Entra ID: user consent to applications + admin consent workflow
# ---------------------------------------------------------------------------
function Get-TenantAppConsentStatus {
    [CmdletBinding()]
    param()
    try {
        $auth = Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/policies/authorizationPolicy'
        $assigned = @()
        if ($auth['defaultUserRolePermissions']) {
            $assigned = @($auth['defaultUserRolePermissions']['permissionGrantPoliciesAssigned'] | Where-Object { $_ })
        }

        $req = Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/policies/adminConsentRequestPolicy'
        $reviewers = @($req['reviewers'] | Where-Object { $_ })

        [pscustomobject]@{
            Success                = $true
            Error                  = $null
            UserConsentAllowed     = ($assigned.Count -gt 0)
            GrantPolicies          = $assigned
            RequestWorkflowEnabled = [bool]$req['isEnabled']
            ReviewerCount          = $reviewers.Count
            Reviewers              = $reviewers
            RequestDurationInDays  = $req['requestDurationInDays']
        }
    }
    catch {
        [pscustomobject]@{ Success = $false; Error = (Get-GraphErrorText $_) }
    }
}

function Set-TenantAppConsentLockdown {
    <#
    .SYNOPSIS
        Turns on the admin consent workflow first (reviewers = every enabled Global Administrator,
        merged with any reviewers already configured), and only then removes users' ability to grant
        consent themselves - so blocking consent never leaves users with no way to ask.
    #>
    [CmdletBinding()]
    param()

    $before = Get-TenantAppConsentStatus
    if (-not $before.Success) {
        return [pscustomobject]@{ Success = $false; Error = $before.Error; Lines = @(); Status = $before }
    }

    $lines = @()
    $admins = Get-TenantAdminAccounts
    if (-not $admins.Success) {
        return [pscustomobject]@{ Success = $false; Error = "Could not list Global Administrators: $($admins.Error)"; Lines = @(); Status = $before }
    }
    $globalAdmins = @($admins.Users | Where-Object { $_.IsGlobalAdmin -and $_.AccountEnabled })
    if ($globalAdmins.Count -eq 0 -and $before.ReviewerCount -eq 0) {
        return [pscustomobject]@{ Success = $false; Error = 'No enabled Global Administrator found to act as reviewer, so consent was left unchanged.'; Lines = @(); Status = $before }
    }

    # 1. Admin consent request workflow
    try {
        $reviewers = @()
        $known = @{}
        foreach ($r in $before.Reviewers) {
            $reviewers += @{ query = $r['query']; queryType = $r['queryType'] }
            $known[[string]$r['query']] = $true
        }
        foreach ($ga in $globalAdmins) {
            $q = "/users/$($ga.Id)"
            if (-not $known.ContainsKey($q)) { $reviewers += @{ query = $q; queryType = 'MicrosoftGraph' } }
        }
        $days = 30
        if ($before.RequestDurationInDays -and [int]$before.RequestDurationInDays -gt 0) { $days = [int]$before.RequestDurationInDays }

        $body = @{
            isEnabled             = $true
            notifyReviewers       = $true
            remindersEnabled      = $true
            requestDurationInDays = $days
            reviewers             = $reviewers
        }
        Update-MgPolicyAdminConsentRequestPolicy -BodyParameter $body
        $lines += "Admin consent workflow enabled with $($reviewers.Count) reviewer(s) ($($globalAdmins.Count) Global Administrator(s))."
    }
    catch {
        return [pscustomobject]@{
            Success = $false
            Error   = "Could not enable the admin consent workflow, so user consent was left unchanged: $(Get-GraphErrorText $_)"
            Lines   = $lines
            Status  = (Get-TenantAppConsentStatus)
        }
    }

    # 2. Remove user consent
    try {
        Invoke-MgGraphRequest -Method PATCH -Uri 'https://graph.microsoft.com/v1.0/policies/authorizationPolicy' `
            -Body '{"defaultUserRolePermissions":{"permissionGrantPoliciesAssigned":[]}}' -ContentType 'application/json' | Out-Null
        $lines += 'User consent to applications removed (permissionGrantPoliciesAssigned cleared).'
    }
    catch {
        return [pscustomobject]@{
            Success = $false
            Error   = "Admin consent workflow is on, but removing user consent failed: $(Get-GraphErrorText $_)"
            Lines   = $lines
            Status  = (Get-TenantAppConsentStatus)
        }
    }

    $after = Get-TenantAppConsentStatus
    $ok = ($after.Success -and -not $after.UserConsentAllowed -and $after.RequestWorkflowEnabled)
    [pscustomobject]@{
        Success = $ok
        Error   = if ($ok) { $null } else { 'Changes were sent but the tenant does not report the expected state yet; check again shortly.' }
        Lines   = $lines
        Status  = $after
    }
}

# ---------------------------------------------------------------------------
# Entra ID: MFA verification methods (authentication methods policy)
# ---------------------------------------------------------------------------
$script:MethodNames = @{
    MicrosoftAuthenticator = 'Microsoft Authenticator (push notification)'
    Voice                  = 'Voice call'
    Sms                    = 'Text message (SMS)'
    Fido2                  = 'Passkey (FIDO2)'
    SoftwareOath           = 'Software OATH tokens'
    HardwareOath           = 'Hardware OATH tokens'
    Email                  = 'Email OTP'
    TemporaryAccessPass    = 'Temporary Access Pass'
    X509Certificate        = 'Certificate-based authentication'
    QRCodePin              = 'QR code'
}
$script:MethodOdataTypes = @{
    Voice                  = '#microsoft.graph.voiceAuthenticationMethodConfiguration'
    MicrosoftAuthenticator = '#microsoft.graph.microsoftAuthenticatorAuthenticationMethodConfiguration'
}
$script:MfaCapableMethodIds = @('MicrosoftAuthenticator', 'Fido2', 'SoftwareOath', 'HardwareOath', 'Sms', 'Voice', 'X509Certificate')

function Get-AuthMethodConfigurations {
    <#
    .SYNOPSIS
        The authentication method configurations (voice, Microsoft Authenticator, SMS, ...), read from
        the authenticationMethodsPolicy resource itself, where Microsoft returns them expanded.
        Listing the .../authenticationMethodConfigurations sub-collection directly is rejected with
        a 400 by the service. Beta is tried first because only beta includes every method (Voice);
        v1.0 is the fallback.
    #>
    $problems = @()
    foreach ($version in 'beta', 'v1.0') {
        try {
            $policy = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/$version/policies/authenticationMethodsPolicy"
            $configs = @($policy['authenticationMethodConfigurations'] | Where-Object { $_ })
            if ($configs.Count -gt 0) {
                return [pscustomobject]@{ Version = $version; Items = $configs }
            }
            $problems += "${version}: the policy came back without any method configurations"
        }
        catch {
            $problems += "${version}: $(Get-GraphErrorText $_)"
        }
    }
    throw ($problems -join ' | ')
}

function Get-TenantMfaMethodPolicyStatus {
    [CmdletBinding()]
    param()
    try {
        $cfg = Get-AuthMethodConfigurations
        $methods = @($cfg.Items | ForEach-Object {
            $id = $_['id']
            [pscustomobject]@{
                Id           = $id
                FriendlyName = if ($script:MethodNames.ContainsKey($id)) { $script:MethodNames[$id] } else { $id }
                State        = [string]$_['state']
                ODataType    = $_['@odata.type']
            }
        })
        [pscustomobject]@{ Success = $true; Error = $null; Methods = $methods; ApiVersion = $cfg.Version }
    }
    catch {
        [pscustomobject]@{ Success = $false; Error = (Get-GraphErrorText $_); Methods = @() }
    }
}

function Disable-TenantMfaMethods {
    <#
    .SYNOPSIS
        Disables the chosen verification methods in the tenant's authentication methods policy.
        Refuses if that would leave no MFA-capable method enabled at all, because users could then
        no longer register or satisfy MFA.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [ValidateSet('Voice', 'MicrosoftAuthenticator')] [string[]] $MethodIds
    )

    $before = Get-TenantMfaMethodPolicyStatus
    if (-not $before.Success) {
        return [pscustomobject]@{ Success = $false; Error = $before.Error; Lines = @(); Status = $before }
    }

    $remaining = @($before.Methods | Where-Object {
        $_.State -eq 'enabled' -and ($script:MfaCapableMethodIds -contains $_.Id) -and ($MethodIds -notcontains $_.Id)
    })
    if ($remaining.Count -eq 0) {
        return [pscustomobject]@{
            Success = $false
            Error   = 'Disabling these would leave no MFA-capable method enabled (passkey, OATH token, SMS, certificate...). Enable another method first.'
            Lines   = @()
            Status  = $before
        }
    }

    $lines = @()
    $failures = @()
    foreach ($id in $MethodIds) {
        $m = $before.Methods | Where-Object { $_.Id -eq $id } | Select-Object -First 1
        if (-not $m) {
            $hint = ''
            if ($before.ApiVersion -eq 'v1.0') { $hint = ' (only the v1.0 API answered, and it may not expose this method)' }
            $failures += "${id}: not found in the authentication methods policy$hint."
            continue
        }
        if ($m.State -eq 'disabled') { $lines += "$($m.FriendlyName): already disabled."; continue }
        $type = if ($m.ODataType) { $m.ODataType } else { $script:MethodOdataTypes[$id] }
        try {
            $body = @{ '@odata.type' = $type; state = 'disabled' } | ConvertTo-Json
            Invoke-MgGraphRequest -Method PATCH -Uri "https://graph.microsoft.com/$($before.ApiVersion)/policies/authenticationMethodsPolicy/authenticationMethodConfigurations/$id" -Body $body -ContentType 'application/json' | Out-Null
            $lines += "$($m.FriendlyName): disabled."
        }
        catch {
            $failures += "$($m.FriendlyName): $(Get-GraphErrorText $_)"
        }
    }

    $after = Get-TenantMfaMethodPolicyStatus
    [pscustomobject]@{
        Success = ($failures.Count -eq 0)
        Error   = if ($failures.Count -gt 0) { $failures -join '; ' } else { $null }
        Lines   = $lines
        Status  = $after
    }
}

# ---------------------------------------------------------------------------
# Exchange Online: mail flow connectors
# ---------------------------------------------------------------------------
function Get-TenantMailConnectors {
    <#
    .SYNOPSIS
        Every inbound and outbound connector, with the settings that matter for security, and flags
        for the ones worth a closer look. Connectors decide who may deliver mail into the tenant and
        where outgoing mail is sent, and a new one is a classic way for an intruder to spoof the
        domain or siphon mail out, so this is read-only review material, not a fix.
        Severity High = a configuration that is unsafe as set; Review = unusual or worth confirming.
    #>
    [CmdletBinding()]
    param()
    try {
        $cutoff = (Get-Date).AddDays(-30)
        $rows = @()

        foreach ($c in @(Get-InboundConnector)) {
            $high = @(); $review = @()
            $enabled = [bool]$c.Enabled
            $type = [string]$c.ConnectorType
            $domains = @($c.SenderDomains | ForEach-Object { [string]$_ })
            $endpoints = @($c.SenderIPAddresses | ForEach-Object { [string]$_ })
            if ($c.TlsSenderCertificateName) { $endpoints += "cert: $($c.TlsSenderCertificateName)" }

            if ($enabled) {
                if ($c.TreatMessagesAsInternal) { $high += 'treats its mail as internal (skips spam filtering)' }
                if ($domains -contains '*') { $high += 'accepts any sender domain' }
                if ($type -eq 'Partner' -and -not $c.RestrictDomainsToIPAddresses -and -not $c.RestrictDomainsToCertificate) {
                    $high += 'not restricted by IP address or certificate'
                }
                if ($type -eq 'Partner' -and -not $c.RequireTls) { $review += 'TLS not required' }
                if ($type -eq 'OnPremises' -and [string]$c.ConnectorSource -ne 'HybridWizard') {
                    $review += 'grants relay rights and was not created by the Hybrid wizard'
                }
            }
            $recent = [bool]($c.WhenCreated -and $c.WhenCreated -gt $cutoff)
            if ($recent) { $review += 'created in the last 30 days' }

            $created = ''
            if ($c.WhenCreated) { $created = ([datetime]$c.WhenCreated).ToString('yyyy-MM-dd') }
            $tls = 'Not required'
            if ($c.RequireTls) { $tls = 'Required' }

            $rows += [pscustomobject]@{
                Direction = 'Inbound'
                Name      = [string]$c.Name
                Enabled   = $enabled
                Type      = "$type / $($c.ConnectorSource)"
                Scope     = ($domains -join ', ')
                Endpoints = ($endpoints -join ', ')
                Tls       = $tls
                Created   = $created
                Recent    = $recent
                Severity  = $(if ($high.Count) { 'High' } elseif ($review.Count) { 'Review' } else { '' })
                Flags     = ((@($high) + @($review)) -join '; ')
            }
        }

        foreach ($c in @(Get-OutboundConnector)) {
            $review = @()
            $enabled = [bool]$c.Enabled
            $type = [string]$c.ConnectorType
            $domains = @($c.RecipientDomains | ForEach-Object { [string]$_ })
            $hosts = @($c.SmartHosts | ForEach-Object { [string]$_ })
            $viaSmartHost = ((-not $c.UseMXRecord) -and $hosts.Count -gt 0)
            $tlsText = [string]$c.TlsSettings

            if ($enabled) {
                if ($viaSmartHost -and ($domains -contains '*')) { $review += 'sends ALL outbound mail through a smart host' }
                if ($viaSmartHost -and -not $tlsText) { $review += 'TLS not enforced to the smart host' }
                if ($c.PSObject.Properties.Name -contains 'MtaStsMode' -and [string]$c.MtaStsMode -eq 'None') { $review += 'MTA-STS validation turned off' }
                if ($c.PSObject.Properties.Name -contains 'SmtpDaneMode' -and [string]$c.SmtpDaneMode -eq 'None') { $review += 'DANE validation turned off' }
                if ($c.IsTransportRuleScoped) { $review += 'used by a mail flow rule (check those rules)' }
            }
            $recent = [bool]($c.WhenCreated -and $c.WhenCreated -gt $cutoff)
            if ($recent) { $review += 'created in the last 30 days' }

            $created = ''
            if ($c.WhenCreated) { $created = ([datetime]$c.WhenCreated).ToString('yyyy-MM-dd') }
            $endpointText = 'MX records'
            if ($viaSmartHost) { $endpointText = ($hosts -join ', ') }
            $scope = ($domains -join ', ')
            if (-not $scope) { $scope = '(none - rule-scoped)' }
            if (-not $tlsText) { $tlsText = 'Not enforced' }

            $rows += [pscustomobject]@{
                Direction = 'Outbound'
                Name      = [string]$c.Name
                Enabled   = $enabled
                Type      = "$type / $($c.ConnectorSource)"
                Scope     = $scope
                Endpoints = $endpointText
                Tls       = $tlsText
                Created   = $created
                Recent    = $recent
                Severity  = $(if ($review.Count) { 'Review' } else { '' })
                Flags     = ($review -join '; ')
            }
        }

        $order = @{ 'High' = 0; 'Review' = 1; '' = 2 }
        $rows = @($rows | Sort-Object -Property @{ Expression = { $order[$_.Severity] } }, @{ Expression = 'Direction'; Descending = $true }, Name)

        $summary = [pscustomobject]@{
            Total    = $rows.Count
            Inbound  = @($rows | Where-Object { $_.Direction -eq 'Inbound' }).Count
            Outbound = @($rows | Where-Object { $_.Direction -eq 'Outbound' }).Count
            Enabled  = @($rows | Where-Object { $_.Enabled }).Count
            High     = @($rows | Where-Object { $_.Severity -eq 'High' }).Count
            Review   = @($rows | Where-Object { $_.Severity -eq 'Review' }).Count
            Recent   = @($rows | Where-Object { $_.Recent }).Count
        }
        [pscustomobject]@{ Success = $true; Error = $null; Connectors = $rows; Summary = $summary }
    }
    catch {
        [pscustomobject]@{ Success = $false; Error = (Get-GraphErrorText $_); Connectors = @(); Summary = $null }
    }
}

# ---------------------------------------------------------------------------
# Entra ID: full user MFA report
# ---------------------------------------------------------------------------
function Set-ReportProgress {
    param($Progress, [string] $Text)
    if ($Progress) { $Progress['Text'] = $Text }
}

function Invoke-GraphBatchGet {
    <#
    .SYNOPSIS
        Runs many GET requests through the Graph $batch endpoint, 20 per call, and returns a hashtable
        of request URL -> @{ Status; Body }. Requests answered 429 or 5xx are retried a few times,
        honoring Retry-After; ones that never succeed come back with the last status instead of
        throwing, so one throttled or forbidden user can't sink a whole report.
    .PARAMETER RelativeUrls
        URLs relative to the API version root, e.g. /users/{id}/authentication/methods.
    #>
    param(
        [Parameter(Mandatory)] [string[]] $RelativeUrls,
        [ValidateSet('v1.0', 'beta')] [string] $Version = 'v1.0',
        $Progress,
        [string] $Label = 'requests'
    )

    $results = @{}
    $pending = @($RelativeUrls)
    $batchUri = "https://graph.microsoft.com/$Version/`$batch"

    for ($attempt = 0; $attempt -lt 4 -and $pending.Count -gt 0; $attempt++) {
        $retry = @()
        $wait = 0
        for ($i = 0; $i -lt $pending.Count; $i += 20) {
            $last = [Math]::Min($i + 19, $pending.Count - 1)
            $chunk = @($pending[$i..$last])
            $requests = @()
            for ($n = 0; $n -lt $chunk.Count; $n++) {
                $requests += @{ id = [string]($n + 1); method = 'GET'; url = $chunk[$n] }
            }
            $body = @{ requests = $requests } | ConvertTo-Json -Depth 5
            $response = Invoke-MgGraphRequest -Method POST -Uri $batchUri -Body $body -ContentType 'application/json'

            foreach ($r in @($response['responses'])) {
                $url = $chunk[[int]$r['id'] - 1]
                $status = [int]$r['status']
                if ($status -eq 429 -or $status -ge 500) {
                    $retry += $url
                    $retryAfter = 0
                    if ($r['headers'] -and $r['headers']['Retry-After']) { $retryAfter = [int]$r['headers']['Retry-After'] }
                    $wait = [Math]::Max($wait, [Math]::Max($retryAfter, 3))
                    $results[$url] = @{ Status = $status; Body = $null }
                }
                else {
                    $results[$url] = @{ Status = $status; Body = $r['body'] }
                }
            }
            $note = ''
            if ($attempt -gt 0) { $note = ' (retrying throttled requests)' }
            Set-ReportProgress $Progress "$Label $($last + 1)/$($pending.Count)$note"
        }
        $pending = $retry
        if ($pending.Count -gt 0 -and $attempt -lt 3) {
            Set-ReportProgress $Progress "$Label throttled - waiting $([Math]::Min($wait, 60))s before retrying $($pending.Count)"
            Start-Sleep -Seconds ([Math]::Min($wait, 60))
        }
    }
    $results
}

function Get-TenantMfaReport {
    <#
    .SYNOPSIS
        Every user's MFA position, on any tenant (no Entra ID Premium needed): which MFA-capable
        methods they have registered, whether anything enforces MFA for them (Security Defaults or
        legacy per-user MFA), and a Status that combines the two. Conditional Access is not
        evaluated. Methods and per-user state are read through $batch, 20 users per request.
    #>
    [CmdletBinding()]
    param(
        [bool] $IncludeDisabled = $false,
        [bool] $IncludeGuests = $false,
        [hashtable] $Progress
    )
    try {
        Set-ReportProgress $Progress 'listing users'
        $all = @(Invoke-GraphPaged 'https://graph.microsoft.com/v1.0/users?$select=id,displayName,userPrincipalName,accountEnabled,userType&$top=999')
        $users = @($all | Where-Object {
            ($IncludeDisabled -or $_['accountEnabled'] -ne $false) -and ($IncludeGuests -or $_['userType'] -ne 'Guest')
        })

        $securityDefaults = $null
        try { $securityDefaults = [bool](Get-MgPolicyIdentitySecurityDefaultEnforcementPolicy).IsEnabled } catch { }

        $methodUrls = @($users | ForEach-Object { "/users/$($_['id'])/authentication/methods" })
        $stateUrls = @($users | ForEach-Object { "/users/$($_['id'])/authentication/requirements" })
        $methodResults = @{}
        $stateResults = @{}
        if ($users.Count -gt 0) {
            $methodResults = Invoke-GraphBatchGet -RelativeUrls $methodUrls -Version 'v1.0' -Progress $Progress -Label 'reading registered MFA methods'
            $stateResults = Invoke-GraphBatchGet -RelativeUrls $stateUrls -Version 'beta' -Progress $Progress -Label 'reading per-user MFA state'
        }

        $severity = @{
            'UNPROTECTED' = 0; 'No MFA (enforcement unknown)' = 1; 'Enforced, not registered' = 2
            'Registered, not enforced' = 3; 'Registered (enforcement unknown)' = 4; 'Unknown' = 5; 'Protected' = 6
        }

        Set-ReportProgress $Progress 'building report'
        $rows = @(foreach ($u in $users) {
            $id = $u['id']
            $m = $methodResults["/users/$id/authentication/methods"]
            $s = $stateResults["/users/$id/authentication/requirements"]

            $hasMfa = $null
            $methodNames = ''
            if ($m -and $m.Status -eq 200 -and $m.Body) {
                $names = @(@($m.Body['value']) | ForEach-Object { $script:MfaCapableMethodTypes[[string]$_['@odata.type']] } | Where-Object { $_ } | Select-Object -Unique)
                $hasMfa = ($names.Count -gt 0)
                $methodNames = $names -join ', '
            }

            $perUser = $null
            if ($s -and $s.Status -eq 200 -and $s.Body) {
                $perUser = [string]$s.Body['perUserMfaState']
                if (-not $perUser) { $perUser = 'disabled' }
            }

            $enforcedBy = @()
            if ($securityDefaults) { $enforcedBy += 'Security Defaults' }
            if ($perUser -in @('enabled', 'enforced')) { $enforcedBy += "Per-user MFA ($perUser)" }
            $enforced = ($enforcedBy.Count -gt 0)
            $enforcementKnown = ($enforced -or (($null -ne $securityDefaults) -and ($null -ne $perUser)))

            if ($null -eq $hasMfa)                       { $status = 'Unknown' }
            elseif ($hasMfa -and $enforced)              { $status = 'Protected' }
            elseif ($hasMfa -and $enforcementKnown)      { $status = 'Registered, not enforced' }
            elseif ($hasMfa)                             { $status = 'Registered (enforcement unknown)' }
            elseif ($enforced)                           { $status = 'Enforced, not registered' }
            elseif ($enforcementKnown)                   { $status = 'UNPROTECTED' }
            else                                         { $status = 'No MFA (enforcement unknown)' }

            $mfaText = 'Unknown'
            if ($hasMfa -eq $true) { $mfaText = 'Yes' } elseif ($hasMfa -eq $false) { $mfaText = 'NO' }
            $userType = $u['userType']
            if (-not $userType) { $userType = 'Member' }
            $perUserText = 'unknown'
            if ($null -ne $perUser) { $perUserText = $perUser }

            [pscustomobject]@{
                Id                = $id
                DisplayName       = $u['displayName']
                UserPrincipalName = $u['userPrincipalName']
                UserType          = $userType
                AccountEnabled    = ($u['accountEnabled'] -ne $false)
                HasMfa            = $hasMfa
                Mfa               = $mfaText
                Methods           = $methodNames
                PerUserMfaState   = $perUserText
                EnforcedBy        = ($enforcedBy -join '; ')
                Status            = $status
            }
        })
        $rows = @($rows | Sort-Object -Property @{ Expression = { $severity[$_.Status] } }, DisplayName)

        $summary = [pscustomobject]@{
            Total                 = $rows.Count
            Protected             = @($rows | Where-Object { $_.Status -eq 'Protected' }).Count
            RegisteredNotEnforced = @($rows | Where-Object { $_.Status -eq 'Registered, not enforced' }).Count
            EnforcedNotRegistered = @($rows | Where-Object { $_.Status -eq 'Enforced, not registered' }).Count
            Unprotected           = @($rows | Where-Object { $_.Status -eq 'UNPROTECTED' }).Count
            Unknown               = @($rows | Where-Object { $_.Status -match 'unknown|^Unknown$' }).Count
        }

        Set-ReportProgress $Progress 'done'
        [pscustomobject]@{
            Success          = $true
            Error            = $null
            Rows             = $rows
            Summary          = $summary
            SecurityDefaults = $securityDefaults
            UsersListed      = $all.Count
        }
    }
    catch {
        [pscustomobject]@{ Success = $false; Error = (Get-GraphErrorText $_); Rows = @(); Summary = $null; SecurityDefaults = $null; UsersListed = 0 }
    }
}

Export-ModuleMember -Function Get-TenantOrgCustomizationStatus, Enable-TenantOrgCustomization, `
    Get-TenantUnifiedAuditLogStatus, Enable-TenantUnifiedAuditLog, `
    Get-TenantDirectSendStatus, Disable-TenantDirectSend, `
    Get-TenantExternalForwardingStatus, Disable-TenantExternalForwarding, `
    Get-TenantPasswordExpirationStatus, Set-TenantPasswordsNeverExpire, `
    Get-TenantAdminAccounts, `
    Get-TenantAppConsentStatus, Set-TenantAppConsentLockdown, `
    Get-TenantMfaMethodPolicyStatus, Disable-TenantMfaMethods, `
    Get-TenantMfaReport, `
    Get-TenantMailConnectors
