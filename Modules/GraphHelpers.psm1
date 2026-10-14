<#
    Small helpers shared by the tenant/audit modules.
#>

function Get-GraphErrorText {
    <#
    .SYNOPSIS
        A readable reason for a failed Graph (or Exchange) call. Invoke-MgGraphRequest and the Graph
        cmdlets often raise only "Response status code does not indicate success: BadRequest", with
        the service's actual explanation in the response body (ErrorDetails); this pulls that out as
        "code: message" so the UI shows why a call was rejected.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] $ErrorRecord)

    $message = [string]$ErrorRecord.Exception.Message
    $body = $null
    if ($ErrorRecord.ErrorDetails -and $ErrorRecord.ErrorDetails.Message) {
        $body = [string]$ErrorRecord.ErrorDetails.Message
    }
    if (-not $body) { return $message.Trim() }

    try {
        $json = $body | ConvertFrom-Json -ErrorAction Stop
        if ($json.error -and $json.error.message) {
            if ($json.error.code) { return "$($json.error.code): $($json.error.message)" }
            return [string]$json.error.message
        }
    }
    catch { }
    "$message $body".Trim()
}

$script:SkuFriendlyNames = @{
    'SPE_E3'                   = 'Microsoft 365 E3'
    'SPE_E5'                   = 'Microsoft 365 E5'
    'SPE_F1'                   = 'Microsoft 365 F3'
    'ENTERPRISEPACK'           = 'Office 365 E3'
    'ENTERPRISEPREMIUM'        = 'Office 365 E5'
    'DESKLESSPACK'             = 'Office 365 F3'
    'O365_BUSINESS_PREMIUM'    = 'Microsoft 365 Business Standard'
    'SPB'                      = 'Microsoft 365 Business Premium'
    'O365_BUSINESS_ESSENTIALS' = 'Microsoft 365 Business Basic'
    'O365_BUSINESS'            = 'Microsoft 365 Apps for business'
    'OFFICESUBSCRIPTION'       = 'Microsoft 365 Apps for enterprise'
    'EXCHANGESTANDARD'         = 'Exchange Online (Plan 1)'
    'EXCHANGEENTERPRISE'       = 'Exchange Online (Plan 2)'
    'AAD_PREMIUM'              = 'Microsoft Entra ID P1'
    'AAD_PREMIUM_P2'           = 'Microsoft Entra ID P2'
    'EMS'                      = 'Enterprise Mobility + Security E3'
    'EMSPREMIUM'               = 'Enterprise Mobility + Security E5'
    'FLOW_FREE'                = 'Power Automate Free'
    'POWER_BI_STANDARD'        = 'Power BI (Free)'
    'TEAMS_EXPLORATORY'        = 'Teams Exploratory'
}

function Get-LicenseFriendlyName {
    <#
    .SYNOPSIS
        A readable name for a SKU part number, falling back to the raw part number for SKUs not in the
        map. Extend the map for tenant-specific SKUs.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string] $SkuPartNumber)

    if ($script:SkuFriendlyNames.ContainsKey($SkuPartNumber)) { return $script:SkuFriendlyNames[$SkuPartNumber] }
    $SkuPartNumber
}

Export-ModuleMember -Function Get-GraphErrorText, Get-LicenseFriendlyName
