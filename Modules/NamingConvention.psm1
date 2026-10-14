function Get-NamingConventionSuggestions {
    <#
    .SYNOPSIS
        Infers the tenant's UPN naming convention from existing users and generates
        candidate UPNs/display names for a new hire.
    .PARAMETER ExistingUsers
        Collection of objects with GivenName, Surname, UserPrincipalName (from Get-MgUser).
    .PARAMETER FirstName / LastName
        New user's name.
    .PARAMETER DomainSuffix
        e.g. "example.com". If not supplied, inferred from the most common domain in ExistingUsers.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [array]  $ExistingUsers,
        [Parameter(Mandatory)] [string] $FirstName,
        [Parameter(Mandatory)] [string] $LastName,
        [string] $DomainSuffix
    )

    function Normalize([string]$s) {
        if ([string]::IsNullOrWhiteSpace($s)) { return '' }
        ($s.ToLowerInvariant() -replace '[^a-z0-9]', '')
    }

    $first = Normalize $FirstName
    $last  = Normalize $LastName
    $firstInitial = if ($first.Length -gt 0) { $first[0] } else { '' }
    $lastInitial  = if ($last.Length  -gt 0) { $last[0]  } else { '' }

    # Candidate pattern generators: name -> local-part
    $patterns = [ordered]@{
        'first'        = { param($f,$l) $f }
        'flast'        = { param($f,$l) "$($f[0])$l" }
        'first.last'   = { param($f,$l) "$f.$l" }
        'firstlast'    = { param($f,$l) "$f$l" }
        'first_last'   = { param($f,$l) "$($f)_$l" }
        'lastfirst'    = { param($f,$l) "$l$f" }
        'lastf'        = { param($f,$l) "$l$($f[0])" }
        'last.first'   = { param($f,$l) "$l.$f" }
        'f.last'       = { param($f,$l) "$($f[0]).$l" }
    }

    # Infer the dominant domain if not supplied
    if (-not $DomainSuffix) {
        $domainCounts = @{}
        foreach ($u in $ExistingUsers) {
            if ($u.UserPrincipalName -match '@(.+)$') {
                $d = $Matches[1].ToLowerInvariant()
                $domainCounts[$d] = ($domainCounts[$d] + 1)
            }
        }
        if ($domainCounts.Count -gt 0) {
            $DomainSuffix = ($domainCounts.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 1).Key
        }
    }

    # Vote for the pattern that matches each existing user's actual UPN local-part
    $votes = @{}
    foreach ($key in $patterns.Keys) { $votes[$key] = 0 }

    foreach ($u in $ExistingUsers) {
        if (-not $u.UserPrincipalName -or $u.UserPrincipalName -notmatch '^(.+)@') { continue }
        $actualLocal = $Matches[1].ToLowerInvariant()

        $uFirst = Normalize $u.GivenName
        $uLast  = Normalize $u.Surname
        if (-not $uFirst -or -not $uLast) { continue }

        foreach ($key in $patterns.Keys) {
            $candidate = & $patterns[$key] $uFirst $uLast
            if ($candidate -eq $actualLocal) {
                $votes[$key]++
            }
        }
    }

    $ranked = $votes.GetEnumerator() | Sort-Object Value -Descending

    $suggestions = foreach ($v in $ranked) {
        $local = & $patterns[$v.Key] $first $last
        if ([string]::IsNullOrWhiteSpace($local)) { continue }
        [pscustomobject]@{
            Pattern    = $v.Key
            Votes      = $v.Value
            Upn        = if ($DomainSuffix) { "$local@$DomainSuffix" } else { $local }
        }
    }

    # De-dupe identical local-parts (e.g. very short names collapse patterns), keep highest vote
    $suggestions = $suggestions | Group-Object Upn | ForEach-Object { $_.Group | Sort-Object Votes -Descending | Select-Object -First 1 } | Sort-Object Votes -Descending

    return $suggestions
}

Export-ModuleMember -Function Get-NamingConventionSuggestions
