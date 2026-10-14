Import-Module (Join-Path $PSScriptRoot 'GraphHelpers.psm1')

function Get-TenantExistingUsers {
    [CmdletBinding()]
    param()
    Get-MgUser -All -Property Id,DisplayName,GivenName,Surname,UserPrincipalName,Mail |
        Select-Object Id,DisplayName,GivenName,Surname,UserPrincipalName,Mail
}

function Get-TenantLicenses {
    <#
    .SYNOPSIS
        Returns each SKU with human-readable name, total, consumed, and available seats.
    #>
    [CmdletBinding()]
    param()

    Get-MgSubscribedSku -All | ForEach-Object {
        $total    = $_.PrepaidUnits.Enabled
        $consumed = $_.ConsumedUnits
        [pscustomobject]@{
            SkuId         = $_.SkuId
            SkuPartNumber = $_.SkuPartNumber
            FriendlyName  = (Get-LicenseFriendlyName $_.SkuPartNumber)
            Total         = $total
            Consumed      = $consumed
            Available     = [math]::Max(0, $total - $consumed)
        }
    } | Sort-Object FriendlyName
}

function Get-TenantSecurityGroups {
    <#
    .SYNOPSIS
        Security groups that are NOT Microsoft 365 / Teams groups (plain assignment/mail-enabled security groups).
    #>
    [CmdletBinding()]
    param()

    Get-MgGroup -All -Property Id,DisplayName,Description,GroupTypes,SecurityEnabled,MailEnabled |
        Where-Object {
            $_.SecurityEnabled -and ($_.GroupTypes -notcontains 'Unified')
        } |
        Select-Object Id,DisplayName,Description
}

function Get-TenantTeams {
    <#
    .SYNOPSIS
        Microsoft 365 groups that have Teams provisioned on them.
    #>
    [CmdletBinding()]
    param()

    Get-MgGroup -All -Filter "resourceProvisioningOptions/Any(x:x eq 'Team')" -Property Id,DisplayName,Description |
        Select-Object Id,DisplayName,Description
}

function Get-TenantDistributionLists {
    <#
    .SYNOPSIS
        Classic (non-mail-enabled-security, non-M365-group) distribution lists via Exchange Online.
        Requires an active Connect-ExchangeOnline session.
    #>
    [CmdletBinding()]
    param()

    Get-DistributionGroup -ResultSize Unlimited -RecipientTypeDetails MailUniversalDistributionGroup |
        Select-Object @{N='Id';E={$_.Guid.ToString()}}, @{N='DisplayName';E={$_.DisplayName}}, @{N='PrimarySmtpAddress';E={$_.PrimarySmtpAddress}}
}

function Get-TenantSharedMailboxes {
    <#
    .SYNOPSIS
        Shared mailboxes via Exchange Online. Requires an active Connect-ExchangeOnline session.
    #>
    [CmdletBinding()]
    param()

    Get-Mailbox -ResultSize Unlimited -RecipientTypeDetails SharedMailbox |
        Select-Object @{N='Id';E={$_.Guid.ToString()}}, @{N='DisplayName';E={$_.DisplayName}}, @{N='PrimarySmtpAddress';E={$_.PrimarySmtpAddress}}
}

function Get-TenantSecurityDefaultsStatus {
    <#
    .SYNOPSIS
        Whether Entra ID Security Defaults is enabled for the tenant. Returns a result object
        instead of throwing so the caller can show the reason a read failed (usually a missing
        Policy.Read.All consent).
    #>
    [CmdletBinding()]
    param()

    try {
        $policy = Get-MgPolicyIdentitySecurityDefaultEnforcementPolicy
        [pscustomobject]@{
            Success     = $true
            Error       = $null
            IsEnabled   = [bool]$policy.IsEnabled
            DisplayName = $policy.DisplayName
            Description = $policy.Description
        }
    }
    catch {
        [pscustomobject]@{ Success = $false; Error = (Get-GraphErrorText $_); IsEnabled = $null; DisplayName = $null; Description = $null }
    }
}

Export-ModuleMember -Function Get-TenantExistingUsers, Get-TenantLicenses, Get-TenantSecurityGroups, Get-TenantTeams, Get-TenantDistributionLists, Get-TenantSharedMailboxes, Get-TenantSecurityDefaultsStatus
