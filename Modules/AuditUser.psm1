<#
    Backend for the "Audit User" tab - read-only investigation helpers plus the handful of
    response actions (password reset, session revoke, MFA method wipe) used when running a
    secondary check on a suspected-compromised account. Every action function returns a result
    object rather than throwing, matching the pattern used by New-O365UserAccount /
    Remove-O365UserAccount, so the caller can show exactly what happened.
#>

Import-Module (Join-Path $PSScriptRoot 'GraphHelpers.psm1')

function Get-UserSignInActivity {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $UserId,
        [int] $Top = 50
    )
    Get-MgAuditLogSignIn -Filter "userId eq '$UserId'" -Top $Top -All:$false |
        Sort-Object CreatedDateTime -Descending |
        Select-Object CreatedDateTime, AppDisplayName, IpAddress,
            @{N='Location';E={"$($_.Location.City), $($_.Location.State), $($_.Location.CountryOrRegion)"}},
            @{N='Status';E={ if ($_.Status.ErrorCode -eq 0) { 'Success' } else { "Failed ($($_.Status.ErrorCode)): $($_.Status.FailureReason)" } }},
            @{N='MfaResult';E={$_.AuthenticationRequirement}},
            ClientAppUsed
}

function Get-UserDirectoryAuditActivity {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $UserId,
        [int] $Top = 50
    )
    Get-MgAuditLogDirectoryAudit -Filter "targetResources/any(t:t/id eq '$UserId')" -Top $Top -All:$false |
        Sort-Object ActivityDateTime -Descending |
        Select-Object ActivityDateTime, ActivityDisplayName,
            @{N='InitiatedBy';E={
                if ($_.InitiatedBy.User.UserPrincipalName) { $_.InitiatedBy.User.UserPrincipalName }
                elseif ($_.InitiatedBy.App.DisplayName) { "$($_.InitiatedBy.App.DisplayName) (app)" }
                else { 'Unknown' }
            }},
            Result
}

function Get-UserRegisteredDevicesSorted {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string] $UserId)

    Get-MgUserRegisteredDevice -UserId $UserId -All | ForEach-Object {
        $p = $_.AdditionalProperties
        $lastSignIn = $null
        if ($p['approximateLastSignInDateTime']) {
            try { $lastSignIn = [datetime]$p['approximateLastSignInDateTime'] } catch { $lastSignIn = $null }
        }
        [pscustomobject]@{
            DisplayName      = $p['displayName']
            OperatingSystem  = "$($p['operatingSystem']) $($p['operatingSystemVersion'])".Trim()
            TrustType        = $p['trustType']
            IsManaged        = $p['isManaged']
            IsCompliant      = $p['isCompliant']
            LastSignIn       = $lastSignIn
        }
    } | Sort-Object -Property @{ Expression = { if ($_.LastSignIn) { $_.LastSignIn } else { [datetime]::MinValue } }; Descending = $true }
}

function New-SecureRandomPassword {
    <#
    .SYNOPSIS
        Cryptographically-random password guaranteed to contain upper/lower/digit/special,
        for the "reset password" response action (not the create-user flow, which uses an
        admin-typed password by design).
    #>
    [CmdletBinding()]
    param([int] $Length = 16)

    $upper   = 'ABCDEFGHJKLMNPQRSTUVWXYZ'   # no I/O to avoid visual ambiguity
    $lower   = 'abcdefghijkmnpqrstuvwxyz'
    $digits  = '23456789'
    $special = '!@#$%^&*-_=+'
    $all     = $upper + $lower + $digits + $special

    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        function Get-RandomChar([string]$set) {
            $bytes = New-Object byte[] 4
            $rng.GetBytes($bytes)
            $idx = [BitConverter]::ToUInt32($bytes, 0) % $set.Length
            return $set[$idx]
        }

        $chars = @(
            Get-RandomChar $upper
            Get-RandomChar $lower
            Get-RandomChar $digits
            Get-RandomChar $special
        )
        for ($i = $chars.Count; $i -lt $Length; $i++) { $chars += Get-RandomChar $all }

        # Fisher-Yates shuffle so the guaranteed characters aren't always in the same positions
        for ($i = $chars.Count - 1; $i -gt 0; $i--) {
            $bytes = New-Object byte[] 4
            $rng.GetBytes($bytes)
            $j = [BitConverter]::ToUInt32($bytes, 0) % ($i + 1)
            $tmp = $chars[$i]; $chars[$i] = $chars[$j]; $chars[$j] = $tmp
        }
        -join $chars
    }
    finally { $rng.Dispose() }
}

function Reset-UserPasswordForIncident {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $UserId,
        [Parameter(Mandatory)] [string] $Password,
        [bool] $ForceChangeNextSignIn = $true
    )
    try {
        Update-MgUser -UserId $UserId -PasswordProfile @{
            Password                     = $Password
            ForceChangePasswordNextSignIn = $ForceChangeNextSignIn
        }
        [pscustomobject]@{ Success = $true; Error = $null }
    }
    catch {
        [pscustomobject]@{ Success = $false; Error = (Get-GraphErrorText $_) }
    }
}

function Get-UserAuthenticationMethodsSummary {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string] $UserId)

    $friendlyNames = @{
        '#microsoft.graph.passwordAuthenticationMethod'                       = 'Password'
        '#microsoft.graph.phoneAuthenticationMethod'                          = 'Phone'
        '#microsoft.graph.microsoftAuthenticatorAuthenticationMethod'         = 'Microsoft Authenticator'
        '#microsoft.graph.softwareOathAuthenticationMethod'                   = 'Software OATH token'
        '#microsoft.graph.fido2AuthenticationMethod'                          = 'FIDO2 security key'
        '#microsoft.graph.windowsHelloForBusinessAuthenticationMethod'        = 'Windows Hello for Business'
        '#microsoft.graph.emailAuthenticationMethod'                          = 'Email (SSPR)'
        '#microsoft.graph.temporaryAccessPassAuthenticationMethod'            = 'Temporary Access Pass'
    }

    Get-MgUserAuthenticationMethod -UserId $UserId -All | ForEach-Object {
        $type = $_.AdditionalProperties['@odata.type']
        [pscustomobject]@{
            Id       = $_.Id
            Type     = if ($friendlyNames.ContainsKey($type)) { $friendlyNames[$type] } else { $type }
            OdataType = $type
        }
    }
}

function Reset-UserAuthenticationMethods {
    <#
    .SYNOPSIS
        Deletes every non-password authentication method registered to the user (mirrors the
        Entra portal's "Require re-register MFA" action), so they must re-enroll MFA on next
        sign-in. Does not touch the password method - that's handled separately by
        Reset-UserPasswordForIncident.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $UserId,
        [Parameter(Mandatory)] [array]  $Methods   # from Get-UserAuthenticationMethodsSummary
    )

    $result = [ordered]@{ Removed = @(); Failed = @(); Skipped = @() }

    foreach ($m in $Methods) {
        if ($m.OdataType -eq '#microsoft.graph.passwordAuthenticationMethod') {
            $result.Skipped += "$($m.Type) (not an MFA method)"
            continue
        }

        try {
            switch ($m.OdataType) {
                '#microsoft.graph.phoneAuthenticationMethod' {
                    Remove-MgUserAuthenticationPhoneMethod -UserId $UserId -PhoneAuthenticationMethodId $m.Id
                }
                '#microsoft.graph.microsoftAuthenticatorAuthenticationMethod' {
                    Remove-MgUserAuthenticationMicrosoftAuthenticatorMethod -UserId $UserId -MicrosoftAuthenticatorAuthenticationMethodId $m.Id
                }
                '#microsoft.graph.softwareOathAuthenticationMethod' {
                    Remove-MgUserAuthenticationSoftwareOathMethod -UserId $UserId -SoftwareOathAuthenticationMethodId $m.Id
                }
                '#microsoft.graph.fido2AuthenticationMethod' {
                    Remove-MgUserAuthenticationFido2Method -UserId $UserId -Fido2AuthenticationMethodId $m.Id
                }
                '#microsoft.graph.windowsHelloForBusinessAuthenticationMethod' {
                    Remove-MgUserAuthenticationWindowsHelloForBusinessMethod -UserId $UserId -WindowsHelloForBusinessAuthenticationMethodId $m.Id
                }
                '#microsoft.graph.emailAuthenticationMethod' {
                    Remove-MgUserAuthenticationEmailMethod -UserId $UserId -EmailAuthenticationMethodId $m.Id
                }
                '#microsoft.graph.temporaryAccessPassAuthenticationMethod' {
                    Remove-MgUserAuthenticationTemporaryAccessPassMethod -UserId $UserId -TemporaryAccessPassAuthenticationMethodId $m.Id
                }
                default {
                    $result.Skipped += "$($m.Type) (no removal cmdlet mapped for $($m.OdataType))"
                    continue
                }
            }
            $result.Removed += $m.Type
        }
        catch {
            # Most common cause: this is the user's default MFA method and Entra ID won't let it
            # be deleted until another method is made default first.
            $result.Failed += "$($m.Type): $(Get-GraphErrorText $_)"
        }
    }

    return [pscustomobject]$result
}

function Test-UserMfaRegistrationStatus {
    <#
    .SYNOPSIS
        Reports whether MFA is registered for the user and whether anything in the tenant enforces it.
        Uses the authentication-methods registration report when the tenant has Entra ID P1/P2; on a
        non-premium tenant (where that report errors) it falls back to reading the user's registered
        authentication methods directly, which works on any tenant. Enforcement is checked through
        Security Defaults and per-user MFA, the two mechanisms available without Conditional Access.
        Conditional Access policies are not evaluated.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $UserId,
        [Parameter(Mandatory)] [string] $UserPrincipalName
    )

    $mfaCapableTypes = @(
        '#microsoft.graph.phoneAuthenticationMethod',
        '#microsoft.graph.microsoftAuthenticatorAuthenticationMethod',
        '#microsoft.graph.softwareOathAuthenticationMethod',
        '#microsoft.graph.fido2AuthenticationMethod',
        '#microsoft.graph.windowsHelloForBusinessAuthenticationMethod'
    )

    $result = [ordered]@{
        Success             = $true
        Error               = $null
        Source              = $null
        IsMfaRegistered     = $null
        IsMfaCapable        = $null
        IsSsprRegistered    = $null
        MethodsRegistered   = $null
        SecurityDefaults    = $null    # $true / $false / $null = could not be read
        PerUserMfaState     = $null    # 'disabled' / 'enabled' / 'enforced' / $null = could not be read
        EnforcedBy          = @()
        Notes               = @()
    }

    # 1. Registration: premium report first, direct method listing as the fallback
    try {
        $detail = Get-MgReportAuthenticationMethodUserRegistrationDetail -Filter "userPrincipalName eq '$UserPrincipalName'" | Select-Object -First 1
        if (-not $detail) { throw 'No registration detail found for this user.' }
        $result.Source            = 'Authentication methods registration report'
        $result.IsMfaRegistered   = $detail.IsMfaRegistered
        $result.IsMfaCapable      = $detail.IsMfaCapable
        $result.IsSsprRegistered  = $detail.IsSsprRegistered
        $result.MethodsRegistered = ($detail.MethodsRegistered -join ', ')
    }
    catch {
        $result.Notes += "Registration report unavailable ($((Get-GraphErrorText $_))); read the user's registered methods directly instead."
        try {
            $methods = @(Get-UserAuthenticationMethodsSummary -UserId $UserId)
            $strong  = @($methods | Where-Object { $mfaCapableTypes -contains $_.OdataType })
            $result.Source            = 'Registered authentication methods'
            $result.IsMfaRegistered   = ($strong.Count -gt 0)
            $result.MethodsRegistered = (($methods | ForEach-Object { $_.Type }) -join ', ')
        }
        catch {
            return [pscustomobject]@{ Success = $false; Error = "Could not read authentication methods: $(Get-GraphErrorText $_)" }
        }
    }

    # 2. Enforcement: Security Defaults (tenant-wide)
    try {
        $result.SecurityDefaults = [bool](Get-MgPolicyIdentitySecurityDefaultEnforcementPolicy).IsEnabled
        if ($result.SecurityDefaults) { $result.EnforcedBy += 'Security Defaults (tenant-wide)' }
    }
    catch { $result.Notes += "Security Defaults state could not be read: $((Get-GraphErrorText $_))" }

    # 3. Enforcement: legacy per-user MFA (beta endpoint; called directly to avoid the beta module)
    try {
        $req = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/users/$UserId/authentication/requirements"
        $result.PerUserMfaState = [string]$req['perUserMfaState']
        if ($result.PerUserMfaState -in @('enabled', 'enforced')) { $result.EnforcedBy += "Per-user MFA ($($result.PerUserMfaState))" }
    }
    catch { $result.Notes += "Per-user MFA state could not be read: $((Get-GraphErrorText $_))" }

    $result.Notes += 'Conditional Access policies (Entra ID P1) were not evaluated.'
    [pscustomobject]$result
}

function Set-UserPerUserMfaState {
    <#
    .SYNOPSIS
        Sets the legacy per-user MFA state (disabled / enabled / enforced) for a user, then reads it
        back to confirm. Works without Entra ID Premium. Uses the beta authentication-requirements
        endpoint through Invoke-MgGraphRequest, so no beta module is needed.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $UserId,
        [Parameter(Mandatory)] [ValidateSet('disabled', 'enabled', 'enforced')] [string] $State
    )

    $uri = "https://graph.microsoft.com/beta/users/$UserId/authentication/requirements"
    try {
        $before = [string](Invoke-MgGraphRequest -Method GET -Uri $uri)['perUserMfaState']
        if ($before -eq $State) {
            return [pscustomobject]@{ Success = $true; Error = $null; Before = $before; After = $before; Changed = $false }
        }

        Invoke-MgGraphRequest -Method PATCH -Uri $uri -Body (@{ perUserMfaState = $State } | ConvertTo-Json) -ContentType 'application/json' | Out-Null

        $after = [string](Invoke-MgGraphRequest -Method GET -Uri $uri)['perUserMfaState']
        $ok = ($after -eq $State)
        [pscustomobject]@{
            Success = $ok
            Error   = if ($ok) { $null } else { "Requested '$State' but the tenant reports '$after'." }
            Before  = $before
            After   = $after
            Changed = $true
        }
    }
    catch {
        [pscustomobject]@{ Success = $false; Error = (Get-GraphErrorText $_); Before = $null; After = $null; Changed = $false }
    }
}

function Get-UserInboxRulesList {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string] $UserPrincipalName)

    Get-InboxRule -Mailbox $UserPrincipalName | ForEach-Object {
        $suspiciousBits = @()
        if ($_.ForwardTo)        { $suspiciousBits += "Forwards to $($_.ForwardTo -join ', ')" }
        if ($_.RedirectTo)       { $suspiciousBits += "Redirects to $($_.RedirectTo -join ', ')" }
        if ($_.ForwardAsAttachmentTo) { $suspiciousBits += "Forwards as attachment to $($_.ForwardAsAttachmentTo -join ', ')" }
        if ($_.DeleteMessage)    { $suspiciousBits += 'Deletes messages' }
        if ($_.MoveToFolder -match 'RSS|Archive|Deleted|Junk|Clutter') { $suspiciousBits += "Moves to $($_.MoveToFolder)" }

        [pscustomobject]@{
            Name       = $_.Name
            Enabled    = $_.Enabled
            Priority   = $_.Priority
            Suspicious = ($suspiciousBits.Count -gt 0)
            Summary    = if ($suspiciousBits.Count -gt 0) { $suspiciousBits -join '; ' } else { 'No forward/redirect/delete actions' }
        }
    }
}

function Test-UserRestrictedSender {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string] $UserPrincipalName)

    try {
        $blocked = Get-BlockedSenderAddress -SenderAddress $UserPrincipalName -ErrorAction Stop
        if ($blocked) {
            [pscustomobject]@{ Success = $true; Error = $null; IsRestricted = $true; Details = $blocked }
        } else {
            [pscustomobject]@{ Success = $true; Error = $null; IsRestricted = $false; Details = $null }
        }
    }
    catch {
        [pscustomobject]@{ Success = $false; Error = (Get-GraphErrorText $_); IsRestricted = $null; Details = $null }
    }
}

function Get-UserMessageTraceReport {
    <#
    .SYNOPSIS
        Wraps Get-MessageTraceV2, which only accepts up to a 10-day window per call (90 days max
        lookback) - this chunks the requested [StartDate, EndDate] range into <=10-day windows
        and merges the results.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]   $UserPrincipalName,
        [Parameter(Mandatory)] [datetime] $StartDate,
        [Parameter(Mandatory)] [datetime] $EndDate,
        [ValidateSet('Sent', 'Received', 'Both')] [string] $Direction = 'Both'
    )

    $earliestAllowed = (Get-Date).AddDays(-90)
    if ($StartDate -lt $earliestAllowed) { $StartDate = $earliestAllowed }
    if ($EndDate -gt (Get-Date))         { $EndDate = Get-Date }

    $results = @()
    $windowStart = $StartDate
    while ($windowStart -lt $EndDate) {
        $windowEnd = $windowStart.AddDays(10)
        if ($windowEnd -gt $EndDate) { $windowEnd = $EndDate }

        if ($Direction -in @('Sent', 'Both')) {
            $results += Get-MessageTraceV2 -SenderAddress $UserPrincipalName -StartDate $windowStart -EndDate $windowEnd -ResultSize 5000 |
                Select-Object Received, SenderAddress, RecipientAddress, Subject, Status, Size, MessageId
        }
        if ($Direction -in @('Received', 'Both')) {
            $results += Get-MessageTraceV2 -RecipientAddress $UserPrincipalName -StartDate $windowStart -EndDate $windowEnd -ResultSize 5000 |
                Select-Object Received, SenderAddress, RecipientAddress, Subject, Status, Size, MessageId
        }

        $windowStart = $windowEnd
    }

    $results | Sort-Object MessageId, RecipientAddress -Unique | Sort-Object Received -Descending
}

Export-ModuleMember -Function Get-UserSignInActivity, Get-UserDirectoryAuditActivity, Get-UserRegisteredDevicesSorted, `
    New-SecureRandomPassword, Reset-UserPasswordForIncident, Get-UserAuthenticationMethodsSummary, `
    Reset-UserAuthenticationMethods, Test-UserMfaRegistrationStatus, Set-UserPerUserMfaState, Get-UserInboxRulesList, `
    Test-UserRestrictedSender, Get-UserMessageTraceReport
