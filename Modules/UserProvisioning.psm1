Import-Module (Join-Path $PSScriptRoot 'GraphHelpers.psm1')

function Test-PasswordStrength {
    <#
    .SYNOPSIS
        Client-side sanity check only. Entra ID's own password policy is the real
        gatekeeper and will reject the request server-side if it disagrees.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Password)

    $issues = @()
    if ($Password.Length -lt 8)            { $issues += 'At least 8 characters' }
    if ($Password -cnotmatch '[A-Z]')      { $issues += 'At least one uppercase letter' }
    if ($Password -cnotmatch '[a-z]')      { $issues += 'At least one lowercase letter' }
    if ($Password -notmatch '[0-9]')       { $issues += 'At least one digit' }
    if ($Password -notmatch '[^a-zA-Z0-9]'){ $issues += 'At least one special character' }

    [pscustomobject]@{
        IsStrong = ($issues.Count -eq 0)
        Issues   = $issues
    }
}

function New-O365UserAccount {
    <#
    .SYNOPSIS
        Creates the Entra ID user, assigns a license, and adds group/DL/shared-mailbox
        memberships. Returns a step-by-step result log; does not throw on partial failure
        so the caller can show the admin exactly what did and didn't succeed.
    .PARAMETER Password
        Plain string. Caller is responsible for having captured it from a masked control;
        this function does not persist it anywhere.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $FirstName,
        [Parameter(Mandatory)] [string] $LastName,
        [Parameter(Mandatory)] [string] $DisplayName,
        [Parameter(Mandatory)] [string] $UserPrincipalName,
        [Parameter(Mandatory)] [string] $Password,
        [string] $UsageLocation = 'US',
        [string[]] $LicenseSkuIds = @(),
        [string[]] $SecurityGroupIds = @(),
        [string[]] $TeamGroupIds = @(),
        [string[]] $DistributionListIdentities = @(),
        [array]    $SharedMailboxAssignments = @()   # [pscustomobject]@{ Identity=...; AccessRights=@('FullAccess','SendAs') }
    )

    $result = [ordered]@{
        UserCreated       = $false
        UserId            = $null
        LicenseAssigned   = @()
        LicenseFailed     = @()
        GroupsAdded       = @()
        GroupsFailed      = @()
        DlsAdded          = @()
        DlsFailed         = @()
        MailboxesGranted  = @()
        MailboxesFailed   = @()
        Errors            = @()
    }

    $mailNickname = ($UserPrincipalName -split '@')[0]

    try {
        $newUser = New-MgUser -DisplayName $DisplayName `
            -GivenName $FirstName `
            -Surname $LastName `
            -UserPrincipalName $UserPrincipalName `
            -MailNickname $mailNickname `
            -AccountEnabled `
            -UsageLocation $UsageLocation `
            -PasswordProfile @{
                Password                             = $Password
                ForceChangePasswordNextSignIn         = $false
                ForceChangePasswordNextSignInWithMfa  = $false
            }
        $result.UserCreated = $true
        $result.UserId = $newUser.Id
    }
    catch {
        $result.Errors += "User creation failed: $(Get-GraphErrorText $_)"
        return [pscustomobject]$result
    }

    foreach ($skuId in $LicenseSkuIds) {
        try {
            Set-MgUserLicense -UserId $result.UserId -AddLicenses @(@{SkuId = $skuId}) -RemoveLicenses @() | Out-Null
            $result.LicenseAssigned += $skuId
        }
        catch {
            $result.LicenseFailed += $skuId
            $result.Errors += "License $skuId failed: $(Get-GraphErrorText $_)"
        }
    }

    foreach ($groupId in ($SecurityGroupIds + $TeamGroupIds)) {
        try {
            New-MgGroupMember -GroupId $groupId -DirectoryObjectId $result.UserId
            $result.GroupsAdded += $groupId
        }
        catch {
            $result.GroupsFailed += $groupId
            $result.Errors += "Group $groupId failed: $(Get-GraphErrorText $_)"
        }
    }

    foreach ($dlIdentity in $DistributionListIdentities) {
        try {
            Add-DistributionGroupMember -Identity $dlIdentity -Member $UserPrincipalName -Confirm:$false
            $result.DlsAdded += $dlIdentity
        }
        catch {
            $result.DlsFailed += $dlIdentity
            $result.Errors += "Distribution list $dlIdentity failed: $(Get-GraphErrorText $_)"
        }
    }

    foreach ($mbx in $SharedMailboxAssignments) {
        try {
            if ($mbx.AccessRights -contains 'FullAccess') {
                Add-MailboxPermission -Identity $mbx.Identity -User $UserPrincipalName -AccessRights FullAccess -AutoMapping $true -Confirm:$false | Out-Null
            }
            if ($mbx.AccessRights -contains 'SendAs') {
                Add-RecipientPermission -Identity $mbx.Identity -Trustee $UserPrincipalName -AccessRights SendAs -Confirm:$false | Out-Null
            }
            $result.MailboxesGranted += $mbx.Identity
        }
        catch {
            $result.MailboxesFailed += $mbx.Identity
            $result.Errors += "Shared mailbox $($mbx.Identity) failed: $(Get-GraphErrorText $_)"
        }
    }

    return [pscustomobject]$result
}

function Get-UserOffboardContext {
    <#
    .SYNOPSIS
        Looks up what a specific user actually holds right now - licenses, and which of the
        tenant's security groups / Teams / distribution lists / shared mailboxes they belong to -
        so the offboard UI can pre-check only real memberships instead of showing the whole
        tenant catalog.
    .PARAMETER CandidateSecurityGroups / CandidateTeams / CandidateDistributionLists / CandidateSharedMailboxes
        The tenant-wide lists already fetched by Get-TenantSecurityGroups / Get-TenantTeams /
        Get-TenantDistributionLists / Get-TenantSharedMailboxes at Connect time; this function
        narrows them down to what this one user actually has.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $UserId,
        [Parameter(Mandatory)] [string] $UserPrincipalName,
        [array] $CandidateSecurityGroups = @(),
        [array] $CandidateTeams = @(),
        [array] $CandidateDistributionLists = @(),
        [array] $CandidateSharedMailboxes = @()
    )

    $memberOfIds = @(
        Get-MgUserMemberOf -UserId $UserId -All |
            Where-Object { $_.AdditionalProperties['@odata.type'] -eq '#microsoft.graph.group' } |
            ForEach-Object { $_.Id }
    )

    $currentSecurityGroups = @($CandidateSecurityGroups | Where-Object { $memberOfIds -contains $_.Id })
    $currentTeams          = @($CandidateTeams          | Where-Object { $memberOfIds -contains $_.Id })

    $currentDls = @(
        foreach ($dl in $CandidateDistributionLists) {
            $isMember = Get-DistributionGroupMember -Identity $dl.Id -ResultSize Unlimited |
                Where-Object { $_.PrimarySmtpAddress -eq $UserPrincipalName }
            if ($isMember) { $dl }
        }
    )

    $currentMailboxAccess = @(
        foreach ($mbx in $CandidateSharedMailboxes) {
            $rights = @()
            $fullAccess = Get-MailboxPermission -Identity $mbx.Id -User $UserPrincipalName -ErrorAction SilentlyContinue
            if ($fullAccess | Where-Object { $_.AccessRights -contains 'FullAccess' }) { $rights += 'FullAccess' }
            $sendAs = Get-RecipientPermission -Identity $mbx.Id -Trustee $UserPrincipalName -ErrorAction SilentlyContinue
            if ($sendAs) { $rights += 'SendAs' }
            if ($rights.Count -gt 0) {
                $mbx | Add-Member -NotePropertyName AccessRights -NotePropertyValue $rights -Force -PassThru
            }
        }
    )

    $licenses = @(Get-MgUserLicenseDetail -UserId $UserId -All)

    [pscustomobject]@{
        SecurityGroups       = $currentSecurityGroups
        Teams                = $currentTeams
        DistributionLists    = $currentDls
        SharedMailboxAccess  = $currentMailboxAccess
        Licenses             = $licenses
    }
}

function Remove-O365UserAccount {
    <#
    .SYNOPSIS
        Offboards a user: optionally disables the account and revokes sign-in sessions, removes
        the requested licenses/group/DL/shared-mailbox memberships, and optionally converts the
        mailbox to shared (with an optional manager access grant). Mirrors New-O365UserAccount's
        shape - returns a step-by-step result log rather than throwing, so partial failures are
        visible instead of silent.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $UserId,
        [Parameter(Mandatory)] [string] $UserPrincipalName,
        [bool]     $DisableAccount = $true,
        [bool]     $RevokeSessions = $true,
        [string[]] $LicenseSkuIdsToRemove = @(),
        [string[]] $GroupIdsToRemove = @(),
        [string[]] $DistributionListIdentitiesToRemove = @(),
        [array]    $SharedMailboxAccessToRemove = @(),   # [pscustomobject]@{ Identity=...; AccessRights=@('FullAccess','SendAs') }
        [bool]     $ConvertMailboxToShared = $false,
        [string]   $GrantMailboxAccessTo = ''
    )

    $result = [ordered]@{
        AccountDisabled      = $false
        SessionsRevoked      = $false
        LicensesRemoved      = @()
        LicensesFailed       = @()
        GroupsRemoved        = @()
        GroupsFailed         = @()
        DlsRemoved           = @()
        DlsFailed            = @()
        MailboxAccessRemoved = @()
        MailboxAccessFailed  = @()
        MailboxConverted     = $false
        Errors               = @()
    }

    if ($DisableAccount) {
        try {
            Update-MgUser -UserId $UserId -AccountEnabled:$false
            $result.AccountDisabled = $true
        }
        catch { $result.Errors += "Disable account failed: $(Get-GraphErrorText $_)" }
    }

    if ($RevokeSessions) {
        try {
            Revoke-MgUserSignInSession -UserId $UserId | Out-Null
            $result.SessionsRevoked = $true
        }
        catch { $result.Errors += "Revoke sign-in sessions failed: $(Get-GraphErrorText $_)" }
    }

    foreach ($skuId in $LicenseSkuIdsToRemove) {
        try {
            Set-MgUserLicense -UserId $UserId -AddLicenses @() -RemoveLicenses @($skuId) | Out-Null
            $result.LicensesRemoved += $skuId
        }
        catch {
            $result.LicensesFailed += $skuId
            $result.Errors += "Remove license $skuId failed: $(Get-GraphErrorText $_)"
        }
    }

    foreach ($groupId in $GroupIdsToRemove) {
        try {
            Remove-MgGroupMemberByRef -GroupId $groupId -DirectoryObjectId $UserId
            $result.GroupsRemoved += $groupId
        }
        catch {
            $result.GroupsFailed += $groupId
            $result.Errors += "Remove from group $groupId failed: $(Get-GraphErrorText $_)"
        }
    }

    foreach ($dlIdentity in $DistributionListIdentitiesToRemove) {
        try {
            Remove-DistributionGroupMember -Identity $dlIdentity -Member $UserPrincipalName -Confirm:$false
            $result.DlsRemoved += $dlIdentity
        }
        catch {
            $result.DlsFailed += $dlIdentity
            $result.Errors += "Remove from distribution list $dlIdentity failed: $(Get-GraphErrorText $_)"
        }
    }

    foreach ($mbx in $SharedMailboxAccessToRemove) {
        try {
            if ($mbx.AccessRights -contains 'FullAccess') {
                Remove-MailboxPermission -Identity $mbx.Identity -User $UserPrincipalName -AccessRights FullAccess -Confirm:$false | Out-Null
            }
            if ($mbx.AccessRights -contains 'SendAs') {
                Remove-RecipientPermission -Identity $mbx.Identity -Trustee $UserPrincipalName -AccessRights SendAs -Confirm:$false | Out-Null
            }
            $result.MailboxAccessRemoved += $mbx.Identity
        }
        catch {
            $result.MailboxAccessFailed += $mbx.Identity
            $result.Errors += "Remove shared mailbox access $($mbx.Identity) failed: $(Get-GraphErrorText $_)"
        }
    }

    if ($ConvertMailboxToShared) {
        try {
            Set-Mailbox -Identity $UserPrincipalName -Type Shared
            $result.MailboxConverted = $true

            if ($GrantMailboxAccessTo) {
                Add-MailboxPermission -Identity $UserPrincipalName -User $GrantMailboxAccessTo -AccessRights FullAccess -AutoMapping $true -Confirm:$false | Out-Null
                Add-RecipientPermission -Identity $UserPrincipalName -Trustee $GrantMailboxAccessTo -AccessRights SendAs -Confirm:$false | Out-Null
            }
        }
        catch { $result.Errors += "Convert mailbox to shared failed: $(Get-GraphErrorText $_)" }
    }

    return [pscustomobject]$result
}

Export-ModuleMember -Function Test-PasswordStrength, New-O365UserAccount, Get-UserOffboardContext, Remove-O365UserAccount
