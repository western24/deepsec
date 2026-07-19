# dds_entra_directsetup.ps1
# Creates or updates the Entra ID resources required for Oracle Database
# external authentication with Deep Data Security app roles.
#
# The script is intentionally idempotent: existing applications, service
# principals, users, and app role assignments are reused where possible.
#
# It configures:
# - Database/resource app registration
# - Database/resource App ID URI: api://<database-application-id>
# - Database/resource delegated scope: session:scope:connect
# - Database/resource requestedAccessTokenVersion: 2
# - Database/resource Deep Data Security app roles: EMPLOYEES, MANAGERS
# - Interactive public client app registration
# - Client redirect URIs for the local direct test app
# - Client delegated API permission to request the database/resource scope
# - Delegated admin consent for the client app when permissions allow
# - Backend authorized client application entry for the interactive client app
# - Demo users and app role assignments: emma -> EMPLOYEES, marvin -> MANAGERS
# - Oracle identity provider config and setup log output
#
# Example:
#   .\dds_entrasetup.ps1 `
#     -TenantId "00000000-0000-0000-0000-000000000000" `
#     -DisplayName "OracleDB_Resource" `
#     -ClientDisplayName "OracleDB_Client"

param(
    # Target Entra tenant and database/resource application registration display name.
    [Parameter(Mandatory = $true)]
    [string]$TenantId,

    [Parameter(Mandatory = $true)]
    [Alias("AppName")]
    [string]$DisplayName,

    # Interactive public client application registration display name.
    [string]$ClientDisplayName = "",

    # Keep the existing Java callback URI first; include the plain localhost
    # redirect used by 02_setup_entra_id.sh for public client parity.
    [string[]]$ClientRedirectUris = @("http://localhost:8080/callback", "http://localhost"),

    # Oracle Database requests this delegated scope when obtaining a token.
    [string]$ScopeName = "session:scope:connect",

    [string]$ScopeDisplayName = "Connect to Oracle Database",

    [string]$ScopeDescription = "Allows users to connect to Oracle Database.",

    # Deep Data Security roles exposed by the app registration.
    [string[]]$DataRoleValues = @("EMPLOYEES", "MANAGERS"),

    # Demo user assigned to the EMPLOYEES app role.
    [string]$EmployeeRoleValue = "EMPLOYEES",

    [string]$EmployeeUserName = "emma",

    [string]$EmployeeUserObjectId = "",

    [string]$EmployeeDisplayName = "Emma Baker",

    [string]$EmployeeGivenName = "Emma",

    [string]$EmployeeSurname = "Baker",

    [string]$EmployeeInitialPassword = "",

    # Demo user assigned to the MANAGERS app role.
    [string]$ManagerRoleValue = "MANAGERS",

    [string]$ManagerUserName = "marvin",

    [string]$ManagerUserObjectId = "",

    [string]$ManagerDisplayName = "Marvin Smith",

    [string]$ManagerGivenName = "Marvin",

    [string]$ManagerSurname = "Smith",

    [string]$ManagerInitialPassword = "",

    # Use this only when you want the app registration and Oracle scope without DDS demo users.
    [switch]$SkipDeepDataSecuritySettings,

    [switch]$SkipEmployeeUserCreation,

    [switch]$RestoreDeletedDemoUsers,

    # Set this only when troubleshooting user lookup conflicts.
    [ValidateRange(1, 30)]
    [int]$UserLookupRetryCount = 6,

    [ValidateRange(1, 60)]
    [int]$UserLookupRetryDelaySeconds = 10,

    [string]$UserLookupLogPath = "",

    # Additional Microsoft Graph delegated scopes to place on the client app.
    # 02_setup_entra_id.sh does not add any by default.
    [string[]]$OptionalClaimMicrosoftGraphDelegatedScopes = @(),

    # Retained for compatibility. This script no longer writes an env file.
    [string]$OutputEnvPath = ".\oracle-db-entra-app.env",

    [string]$SetupLogPath = ".\dds_entra_directsetup.log"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

if (Test-Path -LiteralPath $SetupLogPath) {
    Clear-Content -LiteralPath $SetupLogPath
}
else {
    New-Item -ItemType File -Path $SetupLogPath -Force | Out-Null
}

if ([string]::IsNullOrWhiteSpace($ClientDisplayName)) {
    $ClientDisplayName = "$DisplayName-client"
}

if ($ClientDisplayName.ToLowerInvariant() -eq $DisplayName.ToLowerInvariant()) {
    throw "ClientDisplayName must be different from DisplayName for the two-application setup."
}

function Assert-GraphModule {
    $modules = @(
        "Microsoft.Graph.Authentication",
        "Microsoft.Graph.Applications"
    )

    foreach ($module in $modules) {
        if (-not (Get-Module -ListAvailable -Name $module)) {
            throw @"
Required PowerShell module '$module' is not installed.

Install it with:
  Install-Module Microsoft.Graph -Scope CurrentUser
"@
        }
    }
}

function Connect-EntraGraph {
    param(
        [Parameter(Mandatory = $true)]
        [string]$TenantId
    )

    $requiredScopes = @(
        "Application.ReadWrite.All",
        "AppRoleAssignment.ReadWrite.All",
        "DelegatedPermissionGrant.ReadWrite.All",
        "Directory.Read.All",
        "Directory.ReadWrite.All",
        "User.Read",
        "User.ReadWrite.All"
    )

    $ctx = Get-MgContext
    if ($ctx -and $ctx.TenantId -eq $TenantId) {
        $ctxScopes = @()
        if ($ctx.Scopes) {
            $ctxScopes = @($ctx.Scopes)
        }

        $missingScopes = @($requiredScopes | Where-Object { $ctxScopes -notcontains $_ })
        if ($missingScopes.Count -eq 0) {
            Write-Host "Reusing existing Microsoft Graph connection for tenant $TenantId."
            return
        }

        Write-Host "Existing Microsoft Graph connection is missing scopes: $($missingScopes -join ', ')"
    }

    Write-Host "Connecting to Microsoft Graph..."
    Connect-MgGraph `
        -UseDeviceCode `
        -TenantId $TenantId `
        -Scopes $requiredScopes `
        -NoWelcome

    Write-Host "Connected."
}

function ConvertTo-ODataStringLiteral {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Value
    )

    return $Value.Replace("'", "''")
}

function Invoke-GraphPatch {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Uri,

        [Parameter(Mandatory = $true)]
        [hashtable]$Body
    )

    $json = $Body | ConvertTo-Json -Depth 20
    Invoke-MgGraphRequest `
        -Method PATCH `
        -Uri $Uri `
        -ContentType "application/json" `
        -Body $json | Out-Null
}

function Invoke-GraphPost {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Uri,

        [Parameter(Mandatory = $true)]
        [hashtable]$Body
    )

    $json = $Body | ConvertTo-Json -Depth 20
    Invoke-MgGraphRequest `
        -Method POST `
        -Uri $Uri `
        -ContentType "application/json" `
        -Body $json | Out-Null
}

function Get-EntraApplicationByDisplayName {
    param(
        [Parameter(Mandatory = $true)]
        [string]$DisplayName
    )

    $escapedDisplayName = ConvertTo-ODataStringLiteral -Value $DisplayName
    return Get-MgApplication -Filter "displayName eq '$escapedDisplayName'" | Select-Object -First 1
}

function Get-ExistingScope {
    param(
        [AllowNull()]
        [object[]]$Scopes,

        [Parameter(Mandatory = $true)]
        [string]$ScopeName
    )

    if (-not $Scopes) {
        return $null
    }

    return $Scopes | Where-Object { $_.Value -eq $ScopeName } | Select-Object -First 1
}

function New-OracleDatabaseScope {
    param(
        [object]$ExistingScope,

        [Parameter(Mandatory = $true)]
        [string]$ScopeName,

        [Parameter(Mandatory = $true)]
        [string]$ScopeDisplayName,

        [Parameter(Mandatory = $true)]
        [string]$ScopeDescription
    )

    $scopeId = [guid]::NewGuid().Guid
    if ($ExistingScope -and $ExistingScope.Id) {
        $scopeId = $ExistingScope.Id
    }

    return @{
        id                       = $scopeId
        adminConsentDisplayName  = $ScopeDisplayName
        adminConsentDescription  = $ScopeDescription
        userConsentDisplayName   = $ScopeDisplayName
        userConsentDescription   = $ScopeDescription
        value                    = $ScopeName
        type                     = "User"
        isEnabled                = $true
    }
}

function Get-TenantPrimaryDomain {
    try {
        $organization = Invoke-MgGraphRequest `
            -Method GET `
            -Uri "https://graph.microsoft.com/v1.0/organization?`$select=verifiedDomains"

        $domains = $organization.value[0].verifiedDomains
        $primary = $domains | Where-Object { $_.isDefault -eq $true } | Select-Object -First 1
        if (-not $primary) {
            $primary = $domains | Where-Object { $_.isInitial -eq $true } | Select-Object -First 1
        }

        if ($primary) {
            return $primary.name
        }
    }
    catch {
        Write-Warning "Could not read tenant primary domain."
    }

    return ""
}

function Get-GraphCollection {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Uri
    )

    $items = New-Object System.Collections.Generic.List[object]
    $nextUri = $Uri

    while ($nextUri) {
        $response = Invoke-MgGraphRequest -Method GET -Uri $nextUri

        $valueProperty = $response.PSObject.Properties["value"]
        if ($valueProperty -and $valueProperty.Value) {
            foreach ($item in @($valueProperty.Value)) {
                $items.Add($item)
            }
        }

        $nextUri = $null
        $nextLinkProperty = $response.PSObject.Properties["@odata.nextLink"]
        if ($nextLinkProperty -and $nextLinkProperty.Value) {
            $nextUri = $nextLinkProperty.Value
        }
    }

    return $items.ToArray()
}

function Get-GraphProperty {
    param(
        [AllowNull()]
        [object]$InputObject,

        [Parameter(Mandatory = $true)]
        [string]$Name,

        [switch]$Required
    )

    if ($null -eq $InputObject) {
        if ($Required) {
            throw "Graph response object is null. Expected property '$Name'."
        }

        return $null
    }

    if ($InputObject -is [System.Collections.IDictionary]) {
        foreach ($key in $InputObject.Keys) {
            if ("$key" -ieq $Name) {
                return $InputObject[$key]
            }
        }
    }
    else {
        $property = $InputObject.PSObject.Properties |
            Where-Object { $_.Name -ieq $Name } |
            Select-Object -First 1

        if ($property) {
            return $property.Value
        }
    }

    if ($Required) {
        $availableProperties = @($InputObject.PSObject.Properties | ForEach-Object { $_.Name }) -join ", "
        throw "Graph response object is missing required property '$Name'. Available properties: $availableProperties"
    }

    return $null
}

function New-TemporaryPassword {
    $suffix = ([guid]::NewGuid().Guid -replace "-", "").Substring(0, 12)
    return "Dds!$($suffix)aA1"
}

function Write-UserLookupLog {
    param(
        [AllowEmptyString()]
        [string]$LogPath = "",

        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    if ([string]::IsNullOrWhiteSpace($LogPath)) {
        return
    }

    $timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss.fff zzz")
    Add-Content `
        -Path $LogPath `
        -Encoding utf8 `
        -Value "[$timestamp] $Message"
}

function Write-OptionalUserLookupLog {
    param(
        [string]$LogPath = "",

        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    if (-not [string]::IsNullOrWhiteSpace($LogPath)) {
        Write-UserLookupLog -LogPath $LogPath -Message $Message
    }
}

function Get-UserLookupLogHint {
    param(
        [AllowEmptyString()]
        [string]$LogPath = ""
    )

    if ([string]::IsNullOrWhiteSpace($LogPath)) {
        return "Rerun with -UserLookupLogPath '.\user-lookup.log' for detailed lookup diagnostics."
    }

    return "Review lookup log '$LogPath'."
}

function Get-ErrorMessage {
    param(
        [Parameter(Mandatory = $true)]
        [object]$ErrorRecord
    )

    $parts = New-Object System.Collections.Generic.List[string]

    $exception = Get-GraphProperty `
        -InputObject $ErrorRecord `
        -Name "Exception"
    if ($exception) {
        $exceptionMessage = Get-GraphProperty `
            -InputObject $exception `
            -Name "Message"
        if ($exceptionMessage) {
            $parts.Add($exceptionMessage)
        }
    }

    $errorDetails = Get-GraphProperty `
        -InputObject $ErrorRecord `
        -Name "ErrorDetails"
    if ($errorDetails) {
        $errorDetailsMessage = Get-GraphProperty `
            -InputObject $errorDetails `
            -Name "Message"
        if ($errorDetailsMessage) {
            $parts.Add($errorDetailsMessage)
        }
    }

    $parts.Add(($ErrorRecord | Out-String))
    return ($parts.ToArray() -join " ")
}

function Format-UserLookupCandidate {
    param(
        [AllowNull()]
        [object]$User
    )

    if ($null -eq $User) {
        return "<null>"
    }

    $id = Get-GraphProperty -InputObject $User -Name "id"
    $upn = Get-GraphProperty -InputObject $User -Name "userPrincipalName"
    $displayName = Get-GraphProperty -InputObject $User -Name "displayName"
    $mailNickname = Get-GraphProperty -InputObject $User -Name "mailNickname"

    return "id='$id', userPrincipalName='$upn', displayName='$displayName', mailNickname='$mailNickname'"
}

function New-MailNickname {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Value
    )

    $mailNickname = $Value.ToLowerInvariant() -replace "[^a-z0-9._-]", ""
    if ([string]::IsNullOrWhiteSpace($mailNickname)) {
        $mailNickname = "entra" + (([guid]::NewGuid().Guid -replace "-", "").Substring(0, 8))
    }

    if ($mailNickname.Length -gt 64) {
        $mailNickname = $mailNickname.Substring(0, 64)
    }

    return $mailNickname
}

# User lookup is intentionally defensive. Entra can reject user creation with
# "UPN already exists" before a simple /users/{upn} read returns the object, so
# the script tries direct reads, filters, search, fallback attributes, deleted
# users, and short retries before asking for an explicit object ID.
function Resolve-UserPrincipalName {
    param(
        [Parameter(Mandatory = $true)]
        [string]$UserName,

        [Parameter(Mandatory = $true)]
        [string]$TenantPrimaryDomain
    )

    if ($UserName -match "@") {
        return $UserName
    }

    if ([string]::IsNullOrWhiteSpace($TenantPrimaryDomain)) {
        throw "Tenant primary domain could not be resolved. Specify a full UPN such as emma@example.com."
    }

    return "$UserName@$TenantPrimaryDomain"
}

function Get-EntraUserByUserPrincipalName {
    param(
        [Parameter(Mandatory = $true)]
        [string]$UserPrincipalName,

        [string]$LogPath = ""
    )

    $candidateUsers = New-Object System.Collections.Generic.List[object]

    try {
        Write-OptionalUserLookupLog `
            -LogPath $LogPath `
            -Message "GET /users/$UserPrincipalName"

        $user = Invoke-MgGraphRequest `
            -Method GET `
            -Uri "https://graph.microsoft.com/v1.0/users/${UserPrincipalName}?`$select=id,userPrincipalName,displayName,mailNickname"

        if ($user) {
            Write-OptionalUserLookupLog `
                -LogPath $LogPath `
                -Message "GET raw UPN returned candidate: $(Format-UserLookupCandidate -User $user)"
            $candidateUsers.Add($user)
        }
    }
    catch {
        Write-OptionalUserLookupLog `
            -LogPath $LogPath `
            -Message "GET raw UPN failed: $(Get-ErrorMessage -ErrorRecord $_)"
    }

    $escapedUserPrincipalName = [System.Uri]::EscapeDataString($UserPrincipalName)
    try {
        Write-OptionalUserLookupLog `
            -LogPath $LogPath `
            -Message "GET /users/$escapedUserPrincipalName"

        $user = Invoke-MgGraphRequest `
            -Method GET `
            -Uri "https://graph.microsoft.com/v1.0/users/${escapedUserPrincipalName}?`$select=id,userPrincipalName,displayName,mailNickname"

        if ($user) {
            Write-OptionalUserLookupLog `
                -LogPath $LogPath `
                -Message "GET encoded UPN returned candidate: $(Format-UserLookupCandidate -User $user)"
            $candidateUsers.Add($user)
        }
    }
    catch {
        Write-OptionalUserLookupLog `
            -LogPath $LogPath `
            -Message "GET encoded UPN failed: $(Get-ErrorMessage -ErrorRecord $_)"
    }

    $escapedUpn = ConvertTo-ODataStringLiteral -Value $UserPrincipalName
    $uri = "https://graph.microsoft.com/v1.0/users?`$filter=userPrincipalName eq '$escapedUpn'&`$select=id,userPrincipalName,displayName"
    $filterUsers = @(Get-GraphCollection -Uri $uri)
    Write-OptionalUserLookupLog `
        -LogPath $LogPath `
        -Message "FILTER userPrincipalName eq returned $($filterUsers.Count) candidates."
    foreach ($user in $filterUsers) {
        Write-OptionalUserLookupLog `
            -LogPath $LogPath `
            -Message "FILTER userPrincipalName candidate: $(Format-UserLookupCandidate -User $user)"
        $candidateUsers.Add($user)
    }

    $userNamePart = $UserPrincipalName.Split("@")[0]
    if (-not [string]::IsNullOrWhiteSpace($userNamePart)) {
        $escapedUserNamePart = ConvertTo-ODataStringLiteral -Value $userNamePart
        $uri = "https://graph.microsoft.com/v1.0/users?`$filter=startsWith(userPrincipalName,'$escapedUserNamePart')&`$select=id,userPrincipalName,displayName"
        $startsWithUsers = @(Get-GraphCollection -Uri $uri)
        Write-OptionalUserLookupLog `
            -LogPath $LogPath `
            -Message "FILTER startsWith(userPrincipalName,'$userNamePart') returned $($startsWithUsers.Count) candidates."
        foreach ($user in $startsWithUsers) {
            Write-OptionalUserLookupLog `
                -LogPath $LogPath `
                -Message "FILTER startsWith candidate: $(Format-UserLookupCandidate -User $user)"
            $candidateUsers.Add($user)
        }
    }

    try {
        $search = [System.Uri]::EscapeDataString("`"userPrincipalName:$UserPrincipalName`"")
        Write-OptionalUserLookupLog `
            -LogPath $LogPath `
            -Message "SEARCH users for userPrincipalName '$UserPrincipalName'"

        $response = Invoke-MgGraphRequest `
            -Method GET `
            -Uri "https://graph.microsoft.com/v1.0/users?`$search=$search&`$select=id,userPrincipalName,displayName&`$count=true" `
            -Headers @{
                ConsistencyLevel = "eventual"
            }

        $value = Get-GraphProperty `
            -InputObject $response `
            -Name "value"

        $searchUsers = @($value)
        Write-OptionalUserLookupLog `
            -LogPath $LogPath `
            -Message "SEARCH returned $($searchUsers.Count) candidates."
        foreach ($user in $searchUsers) {
            Write-OptionalUserLookupLog `
                -LogPath $LogPath `
                -Message "SEARCH candidate: $(Format-UserLookupCandidate -User $user)"
            $candidateUsers.Add($user)
        }
    }
    catch {
        Write-OptionalUserLookupLog `
            -LogPath $LogPath `
            -Message "SEARCH failed: $(Get-ErrorMessage -ErrorRecord $_)"
    }

    foreach ($candidateUser in $candidateUsers) {
        $candidateUpn = Get-GraphProperty `
            -InputObject $candidateUser `
            -Name "userPrincipalName"

        if ("$candidateUpn".ToLowerInvariant() -eq $UserPrincipalName.ToLowerInvariant()) {
            Write-OptionalUserLookupLog `
                -LogPath $LogPath `
                -Message "Exact UPN match selected: $(Format-UserLookupCandidate -User $candidateUser)"
            return $candidateUser
        }
    }

    Write-OptionalUserLookupLog `
        -LogPath $LogPath `
        -Message "No exact UPN match selected from $($candidateUsers.Count) total candidates."

    return $null
}

function Get-EntraUserByObjectId {
    param(
        [Parameter(Mandatory = $true)]
        [string]$UserObjectId
    )

    try {
        return Invoke-MgGraphRequest `
            -Method GET `
            -Uri "https://graph.microsoft.com/v1.0/users/$UserObjectId?`$select=id,userPrincipalName,displayName"
    }
    catch {
        return $null
    }
}

function Get-EntraUserByFallbackAttributes {
    param(
        [Parameter(Mandatory = $true)]
        [string]$UserPrincipalName,

        [Parameter(Mandatory = $true)]
        [string]$DisplayName,

        [string]$LogPath = ""
    )

    $candidateUsers = New-Object System.Collections.Generic.List[object]
    $userNamePart = $UserPrincipalName.Split("@")[0]

    if (-not [string]::IsNullOrWhiteSpace($userNamePart)) {
        $escapedMailNickname = ConvertTo-ODataStringLiteral -Value $userNamePart
        $uri = "https://graph.microsoft.com/v1.0/users?`$filter=mailNickname eq '$escapedMailNickname'&`$select=id,userPrincipalName,displayName,mailNickname"
        $mailNicknameUsers = @(Get-GraphCollection -Uri $uri)
        Write-OptionalUserLookupLog `
            -LogPath $LogPath `
            -Message "FILTER mailNickname eq '$userNamePart' returned $($mailNicknameUsers.Count) candidates."
        foreach ($user in $mailNicknameUsers) {
            Write-OptionalUserLookupLog `
                -LogPath $LogPath `
                -Message "FILTER mailNickname candidate: $(Format-UserLookupCandidate -User $user)"
            $candidateUsers.Add($user)
        }
    }

    if (-not [string]::IsNullOrWhiteSpace($DisplayName)) {
        $escapedDisplayName = ConvertTo-ODataStringLiteral -Value $DisplayName
        $uri = "https://graph.microsoft.com/v1.0/users?`$filter=displayName eq '$escapedDisplayName'&`$select=id,userPrincipalName,displayName,mailNickname"
        $displayNameUsers = @(Get-GraphCollection -Uri $uri)
        Write-OptionalUserLookupLog `
            -LogPath $LogPath `
            -Message "FILTER displayName eq '$DisplayName' returned $($displayNameUsers.Count) candidates."
        foreach ($user in $displayNameUsers) {
            Write-OptionalUserLookupLog `
                -LogPath $LogPath `
                -Message "FILTER displayName candidate: $(Format-UserLookupCandidate -User $user)"
            $candidateUsers.Add($user)
        }
    }

    $uniqueUsers = @(
        $candidateUsers |
            Where-Object { Get-GraphProperty -InputObject $_ -Name "id" } |
            Sort-Object { Get-GraphProperty -InputObject $_ -Name "id" } -Unique
    )

    if ($uniqueUsers.Count -eq 1) {
        $resolvedUpn = Get-GraphProperty `
            -InputObject $uniqueUsers[0] `
            -Name "userPrincipalName"
        Write-Host "User resolved by fallback attributes: $resolvedUpn"
        Write-OptionalUserLookupLog `
            -LogPath $LogPath `
            -Message "Fallback selected one unique candidate: $(Format-UserLookupCandidate -User $uniqueUsers[0])"
        return $uniqueUsers[0]
    }

    if ($uniqueUsers.Count -gt 1) {
        Write-Warning "Multiple fallback users matched '$UserPrincipalName'. Specify -EmployeeUserObjectId or -ManagerUserObjectId."
        Write-OptionalUserLookupLog `
            -LogPath $LogPath `
            -Message "Fallback found multiple unique candidates: $($uniqueUsers.Count)"
    }

    Write-OptionalUserLookupLog `
        -LogPath $LogPath `
        -Message "Fallback returned no selectable user."

    return $null
}

function Get-DeletedEntraUserByUserPrincipalName {
    param(
        [Parameter(Mandatory = $true)]
        [string]$UserPrincipalName,

        [string]$LogPath = ""
    )

    $escapedUpn = ConvertTo-ODataStringLiteral -Value $UserPrincipalName
    $uri = "https://graph.microsoft.com/v1.0/directory/deletedItems/microsoft.graph.user?`$filter=userPrincipalName eq '$escapedUpn'&`$select=id,userPrincipalName,displayName"
    $deletedUser = Get-GraphCollection -Uri $uri | Select-Object -First 1
    if ($deletedUser) {
        Write-OptionalUserLookupLog `
            -LogPath $LogPath `
            -Message "Deleted user exact filter matched: $(Format-UserLookupCandidate -User $deletedUser)"
        return $deletedUser
    }

    $uri = "https://graph.microsoft.com/v1.0/directory/deletedItems/microsoft.graph.user?`$select=id,userPrincipalName,displayName"
    $deletedUsers = Get-GraphCollection -Uri $uri
    Write-OptionalUserLookupLog `
        -LogPath $LogPath `
        -Message "Deleted users full scan returned $(@($deletedUsers).Count) candidates."
    foreach ($candidate in $deletedUsers) {
        $candidateUpn = Get-GraphProperty `
            -InputObject $candidate `
            -Name "userPrincipalName"

        if ("$candidateUpn".ToLowerInvariant() -eq $UserPrincipalName.ToLowerInvariant()) {
            Write-OptionalUserLookupLog `
                -LogPath $LogPath `
                -Message "Deleted user full scan matched: $(Format-UserLookupCandidate -User $candidate)"
            return $candidate
        }
    }

    Write-OptionalUserLookupLog `
        -LogPath $LogPath `
        -Message "No matching deleted user found."

    return $null
}

function Restore-DeletedEntraUser {
    param(
        [Parameter(Mandatory = $true)]
        [object]$DeletedUser,

        [Parameter(Mandatory = $true)]
        [string]$UserPrincipalName
    )

    $deletedUserObjectId = Get-GraphProperty `
        -InputObject $DeletedUser `
        -Name "id" `
        -Required

    Write-Host "Restoring deleted user: $UserPrincipalName"
    $restoredUser = Invoke-MgGraphRequest `
        -Method POST `
        -Uri "https://graph.microsoft.com/v1.0/directory/deletedItems/$deletedUserObjectId/restore"

    $restoredUserPrincipalName = Get-GraphProperty `
        -InputObject $restoredUser `
        -Name "userPrincipalName"

    if ($restoredUserPrincipalName) {
        return $restoredUser
    }

    for ($i = 1; $i -le 12; $i++) {
        Start-Sleep -Seconds 5
        $user = Get-EntraUserByUserPrincipalName `
            -UserPrincipalName $UserPrincipalName `
            -LogPath $LogPath
        if ($user) {
            return $user
        }

        Write-Host "Waiting for restored user read-back... attempt $i/12"
    }

    throw "Deleted user '$UserPrincipalName' was restored, but could not be read back."
}

function Wait-EntraUserLookup {
    param(
        [Parameter(Mandatory = $true)]
        [string]$UserPrincipalName,

        [Parameter(Mandatory = $true)]
        [string]$DisplayName,

        [Parameter(Mandatory = $true)]
        [int]$RetryCount,

        [Parameter(Mandatory = $true)]
        [int]$DelaySeconds,

        [AllowEmptyString()]
        [string]$LogPath = ""
    )

    Write-UserLookupLog `
        -LogPath $LogPath `
        -Message "Start retry lookup for UPN='$UserPrincipalName', displayName='$DisplayName', retryCount=$RetryCount, delaySeconds=$DelaySeconds"

    for ($i = 1; $i -le $RetryCount; $i++) {
        Write-Host "Rechecking existing user: $UserPrincipalName attempt $i/$RetryCount"
        Write-UserLookupLog `
            -LogPath $LogPath `
            -Message "Attempt $i/${RetryCount}: Get-EntraUserByUserPrincipalName"

        $user = Get-EntraUserByUserPrincipalName `
            -UserPrincipalName $UserPrincipalName `
            -LogPath $LogPath
        if ($user) {
            $userObjectId = Get-GraphProperty -InputObject $user -Name "id"
            $resolvedUpn = Get-GraphProperty -InputObject $user -Name "userPrincipalName"
            Write-UserLookupLog `
                -LogPath $LogPath `
                -Message "Attempt $i/${RetryCount}: found by UPN lookup. id='$userObjectId', userPrincipalName='$resolvedUpn'"
            return $user
        }

        Write-UserLookupLog `
            -LogPath $LogPath `
            -Message "Attempt $i/${RetryCount}: UPN lookup returned no user. Trying fallback attributes."

        $user = Get-EntraUserByFallbackAttributes `
            -UserPrincipalName $UserPrincipalName `
            -DisplayName $DisplayName `
            -LogPath $LogPath

        if ($user) {
            $userObjectId = Get-GraphProperty -InputObject $user -Name "id"
            $resolvedUpn = Get-GraphProperty -InputObject $user -Name "userPrincipalName"
            Write-UserLookupLog `
                -LogPath $LogPath `
                -Message "Attempt $i/${RetryCount}: found by fallback attributes. id='$userObjectId', userPrincipalName='$resolvedUpn'"
            return $user
        }

        $deletedUser = Get-DeletedEntraUserByUserPrincipalName `
            -UserPrincipalName $UserPrincipalName `
            -LogPath $LogPath
        if ($deletedUser) {
            $deletedUserObjectId = Get-GraphProperty -InputObject $deletedUser -Name "id"
            Write-UserLookupLog `
                -LogPath $LogPath `
                -Message "Attempt $i/${RetryCount}: matching deleted user found. id='$deletedUserObjectId'"
            return $null
        }

        Write-UserLookupLog `
            -LogPath $LogPath `
            -Message "Attempt $i/${RetryCount}: no active or deleted user found."

        if ($i -lt $RetryCount) {
            Start-Sleep -Seconds $DelaySeconds
        }
    }

    Write-UserLookupLog `
        -LogPath $LogPath `
        -Message "Retry lookup exhausted for UPN='$UserPrincipalName'."

    return $null
}

function Ensure-EntraUser {
    param(
        [Parameter(Mandatory = $true)]
        [string]$UserPrincipalName,

        [Parameter(Mandatory = $true)]
        [string]$DisplayName,

        [string]$GivenName = "",

        [string]$Surname = "",

        [string]$InitialPassword = "",

        [switch]$RestoreDeletedUser,

        [int]$UserLookupRetryCount = 6,

        [int]$UserLookupRetryDelaySeconds = 10,

        [string]$UserLookupLogPath = ""
    )

        $user = Get-EntraUserByUserPrincipalName `
            -UserPrincipalName $UserPrincipalName `
            -LogPath $UserLookupLogPath
    if (-not $user) {
        $user = Get-EntraUserByFallbackAttributes `
            -UserPrincipalName $UserPrincipalName `
            -DisplayName $DisplayName `
            -LogPath $UserLookupLogPath
    }

    if ($user) {
        Write-Host "User already exists: $UserPrincipalName"
        return @{
            User = $user
            Created = $false
            TemporaryPassword = ""
        }
    }

    $password = $InitialPassword
    if ([string]::IsNullOrWhiteSpace($password)) {
        $password = New-TemporaryPassword
    }

    if ($RestoreDeletedUser) {
        $deletedUser = Get-DeletedEntraUserByUserPrincipalName `
            -UserPrincipalName $UserPrincipalName `
            -LogPath $UserLookupLogPath
        if ($deletedUser) {
            $restoredUser = Restore-DeletedEntraUser `
                -DeletedUser $deletedUser `
                -UserPrincipalName $UserPrincipalName

            return @{
                User = $restoredUser
                Created = $false
                TemporaryPassword = ""
            }
        }
    }

    Write-Host "Creating user: $UserPrincipalName"
    $body = @{
        accountEnabled = $true
        displayName = $DisplayName
        mailNickname = New-MailNickname -Value ($UserPrincipalName.Split("@")[0])
        userPrincipalName = $UserPrincipalName
        passwordProfile = @{
            forceChangePasswordNextSignIn = $true
            password = $password
        }
    }

    if (-not [string]::IsNullOrWhiteSpace($GivenName)) {
        $body.givenName = $GivenName
    }

    if (-not [string]::IsNullOrWhiteSpace($Surname)) {
        $body.surname = $Surname
    }

    $json = $body | ConvertTo-Json -Depth 20
    try {
        $createdUser = Invoke-MgGraphRequest `
            -Method POST `
            -Uri "https://graph.microsoft.com/v1.0/users" `
            -ContentType "application/json" `
            -Body $json
    }
    catch {
        $message = Get-ErrorMessage -ErrorRecord $_

        if ($message -match "userPrincipalName already exists" -or
            $message -match "Another object with the same value for property userPrincipalName already exists" -or
            $message -match "ObjectConflict") {
            Write-Host "User already exists but was not returned by the first lookup. Rechecking: $UserPrincipalName"
            Write-UserLookupLog `
                -LogPath $UserLookupLogPath `
                -Message "Create user conflict for UPN='$UserPrincipalName'. Graph error: $message"

            $existingUser = Wait-EntraUserLookup `
                -UserPrincipalName $UserPrincipalName `
                -DisplayName $DisplayName `
                -RetryCount $UserLookupRetryCount `
                -DelaySeconds $UserLookupRetryDelaySeconds `
                -LogPath $UserLookupLogPath

            if ($existingUser) {
                return @{
                    User = $existingUser
                    Created = $false
                    TemporaryPassword = ""
                }
            }

            $deletedUser = Get-DeletedEntraUserByUserPrincipalName `
                -UserPrincipalName $UserPrincipalName `
                -LogPath $UserLookupLogPath
            if ($deletedUser) {
                if ($RestoreDeletedUser) {
                    $restoredUser = Restore-DeletedEntraUser `
                        -DeletedUser $deletedUser `
                        -UserPrincipalName $UserPrincipalName

                    return @{
                        User = $restoredUser
                        Created = $false
                        TemporaryPassword = ""
                    }
                }

                throw "A deleted user with UPN '$UserPrincipalName' exists and blocks creation. Rerun with -RestoreDeletedDemoUsers to restore and reuse it, or permanently delete it from Deleted users. $(Get-UserLookupLogHint -LogPath $UserLookupLogPath)"
            }

            throw "A directory object with UPN '$UserPrincipalName' already exists, but Microsoft Graph did not return it after $UserLookupRetryCount lookup attempts. $(Get-UserLookupLogHint -LogPath $UserLookupLogPath) Workaround: rerun with -EmployeeUserObjectId or -ManagerUserObjectId."
        }

        throw
    }

    return @{
        User = $createdUser
        Created = $true
        TemporaryPassword = $password
    }
}

function Get-AppRoleByValue {
    param(
        [AllowNull()]
        [object[]]$AppRoles,

        [Parameter(Mandatory = $true)]
        [string]$Value
    )

    if (-not $AppRoles) {
        return $null
    }

    return $AppRoles |
        Where-Object { $_.Value -and $_.Value.ToUpperInvariant() -eq $Value.ToUpperInvariant() } |
        Select-Object -First 1
}

function ConvertTo-AppRoleBody {
    param(
        [Parameter(Mandatory = $true)]
        [object]$AppRole
    )

    $allowedMemberTypes = @()
    if ($AppRole.AllowedMemberTypes) {
        $allowedMemberTypes = @($AppRole.AllowedMemberTypes)
    }

    return @{
        allowedMemberTypes = $allowedMemberTypes
        description = $AppRole.Description
        displayName = $AppRole.DisplayName
        id = "$($AppRole.Id)"
        isEnabled = [bool]$AppRole.IsEnabled
        value = $AppRole.Value
    }
}

function New-DdsAppRole {
    param(
        [AllowNull()]
        [object]$ExistingAppRole,

        [Parameter(Mandatory = $true)]
        [string]$RoleValue
    )

    $roleId = [guid]::NewGuid().Guid
    if ($ExistingAppRole -and $ExistingAppRole.Id) {
        $roleId = "$($ExistingAppRole.Id)"
    }

    return @{
        allowedMemberTypes = @("User", "Application")
        description = "$RoleValue data role for Oracle Database Deep Data Security."
        displayName = $RoleValue
        id = $roleId
        isEnabled = $true
        value = $RoleValue
    }
}

function Set-DdsAppRoles {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Application,

        [Parameter(Mandatory = $true)]
        [string[]]$RoleValues
    )

    $managedRoleValues = @($RoleValues |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
        ForEach-Object { $_.ToUpperInvariant() } |
        Select-Object -Unique)

    $appRoles = New-Object System.Collections.Generic.List[object]
    if ($Application.AppRoles) {
        foreach ($existingRole in $Application.AppRoles) {
            if ($existingRole.Value -and ($managedRoleValues -contains $existingRole.Value.ToUpperInvariant())) {
                continue
            }

            $appRoles.Add((ConvertTo-AppRoleBody -AppRole $existingRole))
        }
    }

    foreach ($roleValue in $managedRoleValues) {
        $existingRole = Get-AppRoleByValue -AppRoles $Application.AppRoles -Value $roleValue
        $appRoles.Add((New-DdsAppRole -ExistingAppRole $existingRole -RoleValue $roleValue))
    }

    Write-Host "Configuring app roles: $($managedRoleValues -join ', ')"
    Invoke-GraphPatch `
        -Uri "https://graph.microsoft.com/v1.0/applications/$($Application.Id)" `
        -Body @{
            appRoles = @($appRoles.ToArray())
        }

    return Get-MgApplication -ApplicationId $Application.Id
}

function ConvertTo-ResourceAccessBody {
    param(
        [Parameter(Mandatory = $true)]
        [object]$RequiredResourceAccess
    )

    $resourceAccess = New-Object System.Collections.Generic.List[object]
    if ($RequiredResourceAccess.ResourceAccess) {
        foreach ($access in $RequiredResourceAccess.ResourceAccess) {
            $resourceAccess.Add(@{
                id = "$($access.Id)"
                type = $access.Type
            })
        }
    }

    return @{
        resourceAppId = "$($RequiredResourceAccess.ResourceAppId)"
        resourceAccess = @($resourceAccess.ToArray())
    }
}

function ConvertTo-OAuth2PermissionScopeBody {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Scope
    )

    return @{
        id = "$(Get-GraphProperty -InputObject $Scope -Name "id" -Required)"
        adminConsentDisplayName = Get-GraphProperty -InputObject $Scope -Name "adminConsentDisplayName"
        adminConsentDescription = Get-GraphProperty -InputObject $Scope -Name "adminConsentDescription"
        userConsentDisplayName = Get-GraphProperty -InputObject $Scope -Name "userConsentDisplayName"
        userConsentDescription = Get-GraphProperty -InputObject $Scope -Name "userConsentDescription"
        value = Get-GraphProperty -InputObject $Scope -Name "value"
        type = Get-GraphProperty -InputObject $Scope -Name "type"
        isEnabled = [bool](Get-GraphProperty -InputObject $Scope -Name "isEnabled")
    }
}

function Add-ResourceAccessIfMissing {
    param(
        [AllowEmptyCollection()]
        [System.Collections.Generic.List[object]]$ResourceAccess,

        [Parameter(Mandatory = $true)]
        [string]$AccessId,

        [Parameter(Mandatory = $true)]
        [string]$AccessType
    )

    $accessKey = "$($AccessType.ToLowerInvariant()):$($AccessId.ToLowerInvariant())"
    $existingKeys = @($ResourceAccess.ToArray() | ForEach-Object {
        $existingId = Get-GraphProperty -InputObject $_ -Name "id"
        $existingType = Get-GraphProperty -InputObject $_ -Name "type"
        $existingIdText = "$existingId"
        $existingTypeText = "$existingType"
        "$($existingTypeText.ToLowerInvariant()):$($existingIdText.ToLowerInvariant())"
    })

    if ($existingKeys -notcontains $accessKey) {
        $ResourceAccess.Add(@{
            id = $AccessId
            type = $AccessType
        })
    }
}

function Get-MicrosoftGraphDelegatedScopeAccess {
    param(
        [string[]]$ScopeNames = @()
    )

    $scopeNamesToAdd = @($ScopeNames |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
        ForEach-Object { $_.Trim() } |
        Select-Object -Unique)

    if ($scopeNamesToAdd.Count -eq 0) {
        return @()
    }

    $microsoftGraphAppId = "00000003-0000-0000-c000-000000000000"
    $escapedAlternateKeyAppId = $microsoftGraphAppId.Replace("'", "''")
    $graphServicePrincipal = $null

    try {
        $graphServicePrincipal = Invoke-MgGraphRequest `
            -Method GET `
            -Uri "https://graph.microsoft.com/v1.0/servicePrincipals(appId='$escapedAlternateKeyAppId')?`$select=id,appId,displayName,oauth2PermissionScopes"
    }
    catch {
        $escapedAppId = ConvertTo-ODataStringLiteral -Value $microsoftGraphAppId
        $uri = "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=appId eq '$escapedAppId'&`$select=id,appId,displayName,oauth2PermissionScopes"
        $graphServicePrincipal = Get-GraphCollection -Uri $uri | Select-Object -First 1
    }

    if (-not $graphServicePrincipal) {
        throw "Microsoft Graph service principal could not be resolved in this tenant."
    }

    $oauth2PermissionScopes = Get-GraphProperty `
        -InputObject $graphServicePrincipal `
        -Name "oauth2PermissionScopes" `
        -Required

    $resourceAccess = New-Object System.Collections.Generic.List[object]
    foreach ($scopeName in $scopeNamesToAdd) {
        $scope = $oauth2PermissionScopes |
            Where-Object { (Get-GraphProperty -InputObject $_ -Name "value") -eq $scopeName } |
            Select-Object -First 1

        if (-not $scope) {
            throw "Microsoft Graph delegated scope '$scopeName' was not found."
        }

        $scopeId = Get-GraphProperty `
            -InputObject $scope `
            -Name "id" `
            -Required

        $resourceAccess.Add(@{
            id = "$scopeId"
            type = "Scope"
        })
    }

    return $resourceAccess.ToArray()
}

function Set-RequiredResourceAccessForSelf {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Application,

        [object[]]$AppRoles = @(),

        [string[]]$MicrosoftGraphDelegatedScopeNames = @()
    )

    $microsoftGraphAppId = "00000003-0000-0000-c000-000000000000"
    $requiredResourceAccess = New-Object System.Collections.Generic.List[object]
    $selfResourceAccess = New-Object System.Collections.Generic.List[object]
    $microsoftGraphResourceAccess = New-Object System.Collections.Generic.List[object]

    if ($Application.RequiredResourceAccess) {
        foreach ($entry in $Application.RequiredResourceAccess) {
            if ("$($entry.ResourceAppId)" -eq "$($Application.AppId)") {
                if ($entry.ResourceAccess) {
                    foreach ($access in $entry.ResourceAccess) {
                        Add-ResourceAccessIfMissing `
                            -ResourceAccess $selfResourceAccess `
                            -AccessId "$($access.Id)" `
                            -AccessType "$($access.Type)"
                    }
                }

                continue
            }

            if ("$($entry.ResourceAppId)" -eq $microsoftGraphAppId) {
                if ($entry.ResourceAccess) {
                    foreach ($access in $entry.ResourceAccess) {
                        Add-ResourceAccessIfMissing `
                            -ResourceAccess $microsoftGraphResourceAccess `
                            -AccessId "$($access.Id)" `
                            -AccessType "$($access.Type)"
                    }
                }

                continue
            }

            $requiredResourceAccess.Add((ConvertTo-ResourceAccessBody -RequiredResourceAccess $entry))
        }
    }

    foreach ($appRole in @($AppRoles | Where-Object { $_ })) {
        Add-ResourceAccessIfMissing `
            -ResourceAccess $selfResourceAccess `
            -AccessId "$($appRole.Id)" `
            -AccessType "Role"
    }

    $microsoftGraphScopeAccess = @(Get-MicrosoftGraphDelegatedScopeAccess -ScopeNames $MicrosoftGraphDelegatedScopeNames)
    foreach ($access in $microsoftGraphScopeAccess) {
        $accessId = Get-GraphProperty -InputObject $access -Name "id" -Required
        $accessType = Get-GraphProperty -InputObject $access -Name "type" -Required

        Add-ResourceAccessIfMissing `
            -ResourceAccess $microsoftGraphResourceAccess `
            -AccessId "$accessId" `
            -AccessType "$accessType"
    }

    if ($selfResourceAccess.Count -gt 0) {
        $requiredResourceAccess.Add(@{
            resourceAppId = "$($Application.AppId)"
            resourceAccess = @($selfResourceAccess.ToArray())
        })
    }

    if ($microsoftGraphResourceAccess.Count -gt 0) {
        $requiredResourceAccess.Add(@{
            resourceAppId = $microsoftGraphAppId
            resourceAccess = @($microsoftGraphResourceAccess.ToArray())
        })
    }

    $configuredGraphScopes = @($MicrosoftGraphDelegatedScopeNames |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
        ForEach-Object { $_.Trim() } |
        Select-Object -Unique) -join ", "

    if ([string]::IsNullOrWhiteSpace($configuredGraphScopes)) {
        Write-Host "Configuring API permissions for app roles on the application itself."
    }
    else {
        Write-Host "Configuring API permissions for app roles and Microsoft Graph delegated scopes: $configuredGraphScopes"
    }
    Invoke-GraphPatch `
        -Uri "https://graph.microsoft.com/v1.0/applications/$($Application.Id)" `
        -Body @{
            requiredResourceAccess = @($requiredResourceAccess.ToArray())
        }
}

function ConvertTo-PreAuthorizedApplicationBody {
    param(
        [Parameter(Mandatory = $true)]
        [object]$PreAuthorizedApplication
    )

    $delegatedPermissionIds = New-Object System.Collections.Generic.List[string]
    $existingDelegatedPermissionIds = Get-GraphProperty `
        -InputObject $PreAuthorizedApplication `
        -Name "delegatedPermissionIds"

    if ($existingDelegatedPermissionIds) {
        foreach ($delegatedPermissionId in @($existingDelegatedPermissionIds)) {
            if (-not [string]::IsNullOrWhiteSpace("$delegatedPermissionId")) {
                $delegatedPermissionIds.Add("$delegatedPermissionId")
            }
        }
    }

    return @{
        appId = "$(Get-GraphProperty -InputObject $PreAuthorizedApplication -Name "appId" -Required)"
        delegatedPermissionIds = @($delegatedPermissionIds.ToArray() | Select-Object -Unique)
    }
}

function Set-BackendPreAuthorizedClient {
    param(
        [Parameter(Mandatory = $true)]
        [object]$BackendApplication,

        [Parameter(Mandatory = $true)]
        [string]$ClientAppId,

        [Parameter(Mandatory = $true)]
        [string]$DelegatedPermissionId
    )

    $api = Get-GraphProperty -InputObject $BackendApplication -Name "api"
    $preAuthorizedApplications = New-Object System.Collections.Generic.List[object]
    $clientEntryFound = $false

    if ($api) {
        $existingPreAuthorizedApplications = Get-GraphProperty `
            -InputObject $api `
            -Name "preAuthorizedApplications"

        if ($existingPreAuthorizedApplications) {
            foreach ($entry in @($existingPreAuthorizedApplications)) {
                $entryBody = ConvertTo-PreAuthorizedApplicationBody -PreAuthorizedApplication $entry
                if ("$($entryBody.appId)" -eq $ClientAppId) {
                    $clientEntryFound = $true
                    $permissionIds = New-Object System.Collections.Generic.List[string]
                    foreach ($permissionId in @($entryBody.delegatedPermissionIds)) {
                        if (-not [string]::IsNullOrWhiteSpace("$permissionId")) {
                            $permissionIds.Add("$permissionId")
                        }
                    }

                    if ($permissionIds.ToArray() -notcontains $DelegatedPermissionId) {
                        $permissionIds.Add($DelegatedPermissionId)
                    }

                    $entryBody.delegatedPermissionIds = @($permissionIds.ToArray() | Select-Object -Unique)
                }

                $preAuthorizedApplications.Add($entryBody)
            }
        }
    }

    if (-not $clientEntryFound) {
        $preAuthorizedApplications.Add(@{
            appId = $ClientAppId
            delegatedPermissionIds = @($DelegatedPermissionId)
        })
    }

    $oauth2PermissionScopes = @()
    if ($api) {
        $existingScopes = Get-GraphProperty -InputObject $api -Name "oauth2PermissionScopes"
        if ($existingScopes) {
            $scopeBodies = New-Object System.Collections.Generic.List[object]
            foreach ($scope in @($existingScopes)) {
                $scopeBodies.Add((ConvertTo-OAuth2PermissionScopeBody -Scope $scope))
            }
            $oauth2PermissionScopes = @($scopeBodies.ToArray())
        }
    }

    Write-Host "Configuring backend pre-authorized client: $ClientAppId"
    Invoke-GraphPatch `
        -Uri "https://graph.microsoft.com/v1.0/applications/$($BackendApplication.Id)" `
        -Body @{
            api = @{
                requestedAccessTokenVersion = 2
                oauth2PermissionScopes = @($oauth2PermissionScopes)
                preAuthorizedApplications = @($preAuthorizedApplications.ToArray())
            }
        }

    return Get-MgApplication -ApplicationId $BackendApplication.Id
}

function Set-ClientApplicationRedirectUris {
    param(
        [Parameter(Mandatory = $true)]
        [object]$ClientApplication,

        [Parameter(Mandatory = $true)]
        [string[]]$RedirectUris
    )

    $redirectUrisToSet = @($RedirectUris |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
        ForEach-Object { $_.Trim() } |
        Select-Object -Unique)

    if ($redirectUrisToSet.Count -eq 0) {
        throw "At least one client redirect URI is required."
    }

    Write-Host "Configuring client public redirect URIs: $($redirectUrisToSet -join ', ')"
    Invoke-GraphPatch `
        -Uri "https://graph.microsoft.com/v1.0/applications/$($ClientApplication.Id)" `
        -Body @{
            isFallbackPublicClient = $true
            publicClient = @{
                redirectUris = @($redirectUrisToSet)
            }
        }

    return Get-MgApplication -ApplicationId $ClientApplication.Id
}

function Set-ClientRequiredResourceAccess {
    param(
        [Parameter(Mandatory = $true)]
        [object]$ClientApplication,

        [Parameter(Mandatory = $true)]
        [string]$DatabaseAppId,

        [Parameter(Mandatory = $true)]
        [string]$DatabaseScopeId,

        [string[]]$MicrosoftGraphDelegatedScopeNames = @()
    )

    $microsoftGraphAppId = "00000003-0000-0000-c000-000000000000"
    $requiredResourceAccess = New-Object System.Collections.Generic.List[object]
    $databaseResourceAccess = New-Object System.Collections.Generic.List[object]
    $microsoftGraphResourceAccess = New-Object System.Collections.Generic.List[object]

    if ($ClientApplication.RequiredResourceAccess) {
        foreach ($entry in $ClientApplication.RequiredResourceAccess) {
            if ("$($entry.ResourceAppId)" -eq $DatabaseAppId) {
                if ($entry.ResourceAccess) {
                    foreach ($access in $entry.ResourceAccess) {
                        if ("$($access.Type)" -ne "Role") {
                            Add-ResourceAccessIfMissing `
                                -ResourceAccess $databaseResourceAccess `
                                -AccessId "$($access.Id)" `
                                -AccessType "$($access.Type)"
                        }
                    }
                }

                continue
            }

            if ("$($entry.ResourceAppId)" -eq $microsoftGraphAppId) {
                continue
            }

            $requiredResourceAccess.Add((ConvertTo-ResourceAccessBody -RequiredResourceAccess $entry))
        }
    }

    Add-ResourceAccessIfMissing `
        -ResourceAccess $databaseResourceAccess `
        -AccessId $DatabaseScopeId `
        -AccessType "Scope"

    $microsoftGraphScopeAccess = @(Get-MicrosoftGraphDelegatedScopeAccess -ScopeNames $MicrosoftGraphDelegatedScopeNames)
    foreach ($access in $microsoftGraphScopeAccess) {
        $accessId = Get-GraphProperty -InputObject $access -Name "id" -Required
        $accessType = Get-GraphProperty -InputObject $access -Name "type" -Required

        Add-ResourceAccessIfMissing `
            -ResourceAccess $microsoftGraphResourceAccess `
            -AccessId "$accessId" `
            -AccessType "$accessType"
    }

    $requiredResourceAccess.Add(@{
        resourceAppId = $DatabaseAppId
        resourceAccess = @($databaseResourceAccess.ToArray())
    })

    if ($microsoftGraphResourceAccess.Count -gt 0) {
        $requiredResourceAccess.Add(@{
            resourceAppId = $microsoftGraphAppId
            resourceAccess = @($microsoftGraphResourceAccess.ToArray())
        })
    }

    Write-Host "Configuring client delegated API permission for database/resource scope."
    Invoke-GraphPatch `
        -Uri "https://graph.microsoft.com/v1.0/applications/$($ClientApplication.Id)" `
        -Body @{
            requiredResourceAccess = @($requiredResourceAccess.ToArray())
        }

    return Get-MgApplication -ApplicationId $ClientApplication.Id
}

function Ensure-DelegatedPermissionGrant {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ClientServicePrincipalObjectId,

        [Parameter(Mandatory = $true)]
        [string]$ResourceServicePrincipalObjectId,

        [Parameter(Mandatory = $true)]
        [string]$ScopeName,

        [Parameter(Mandatory = $true)]
        [string]$GrantLabel
    )

    $escapedClientId = ConvertTo-ODataStringLiteral -Value $ClientServicePrincipalObjectId
    $escapedResourceId = ConvertTo-ODataStringLiteral -Value $ResourceServicePrincipalObjectId
    $uri = "https://graph.microsoft.com/v1.0/oauth2PermissionGrants?`$filter=clientId eq '$escapedClientId' and resourceId eq '$escapedResourceId'&`$select=id,clientId,resourceId,consentType,scope"
    $existingGrants = @(Get-GraphCollection -Uri $uri)
    $grant = $existingGrants |
        Where-Object { (Get-GraphProperty -InputObject $_ -Name "consentType") -eq "AllPrincipals" } |
        Select-Object -First 1

    if ($grant) {
        $grantId = Get-GraphProperty -InputObject $grant -Name "id" -Required
        $existingScopeText = "$(Get-GraphProperty -InputObject $grant -Name "scope")"
        $scopes = @($existingScopeText -split "\s+" | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
        if ($scopes -contains $ScopeName) {
            Write-Host "Delegated admin consent already exists: $GrantLabel -> $ScopeName"
            return $grant
        }

        $updatedScopeText = @($scopes + $ScopeName | Select-Object -Unique) -join " "
        Write-Host "Updating delegated admin consent: $GrantLabel -> $updatedScopeText"
        Invoke-GraphPatch `
            -Uri "https://graph.microsoft.com/v1.0/oauth2PermissionGrants/$grantId" `
            -Body @{
                scope = $updatedScopeText
            }

        return Invoke-MgGraphRequest `
            -Method GET `
            -Uri "https://graph.microsoft.com/v1.0/oauth2PermissionGrants/$grantId?`$select=id,clientId,resourceId,consentType,scope"
    }

    Write-Host "Creating delegated admin consent: $GrantLabel -> $ScopeName"
    try {
        return Invoke-MgGraphRequest `
            -Method POST `
            -Uri "https://graph.microsoft.com/v1.0/oauth2PermissionGrants" `
            -ContentType "application/json" `
            -Body (@{
                clientId = $ClientServicePrincipalObjectId
                consentType = "AllPrincipals"
                resourceId = $ResourceServicePrincipalObjectId
                scope = $ScopeName
            } | ConvertTo-Json -Depth 10)
    }
    catch {
        $message = Get-ErrorMessage -ErrorRecord $_
        if ($message -match "Permission entry already exists") {
            Write-Host "Delegated admin consent already exists: $GrantLabel -> $ScopeName"
            for ($i = 1; $i -le 6; $i++) {
                Start-Sleep -Seconds 2
                $existingGrants = @(Get-GraphCollection -Uri $uri)
                $grant = $existingGrants |
                    Where-Object { (Get-GraphProperty -InputObject $_ -Name "consentType") -eq "AllPrincipals" } |
                    Select-Object -First 1

                if ($grant) {
                    return $grant
                }
            }

            return [pscustomobject]@{
                id = ""
                clientId = $ClientServicePrincipalObjectId
                resourceId = $ResourceServicePrincipalObjectId
                consentType = "AllPrincipals"
                scope = $ScopeName
            }
        }

        throw
    }
}

function Get-EntraServicePrincipalByAppId {
    param(
        [Parameter(Mandatory = $true)]
        [string]$AppId
    )

    $escapedAlternateKeyAppId = $AppId.Replace("'", "''")
    try {
        $servicePrincipal = Invoke-MgGraphRequest `
            -Method GET `
            -Uri "https://graph.microsoft.com/v1.0/servicePrincipals(appId='$escapedAlternateKeyAppId')?`$select=id,appId,displayName,appRoles,tags"

        if (Get-GraphProperty -InputObject $servicePrincipal -Name "id") {
            return $servicePrincipal
        }
    }
    catch {
        # Fall back to collection queries below. The alternate key can lag just after app/SP creation.
    }

    $escapedAppId = ConvertTo-ODataStringLiteral -Value $AppId
    $uri = "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=appId eq '$escapedAppId'&`$select=id,appId,displayName,appRoles,tags"
    $servicePrincipal = Get-GraphCollection -Uri $uri | Select-Object -First 1
    if ($servicePrincipal) {
        return $servicePrincipal
    }

    $uri = "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=servicePrincipalNames/any(name:name eq '$escapedAppId')&`$select=id,appId,displayName,appRoles,tags"
    return Get-GraphCollection -Uri $uri | Select-Object -First 1
}

function Ensure-EnterpriseApplicationTag {
    param(
        [Parameter(Mandatory = $true)]
        [object]$ServicePrincipal
    )

    $enterpriseApplicationTag = "WindowsAzureActiveDirectoryIntegratedApp"
    $servicePrincipalObjectId = Get-GraphProperty `
        -InputObject $ServicePrincipal `
        -Name "id" `
        -Required

    $tags = @()
    $existingTags = Get-GraphProperty `
        -InputObject $ServicePrincipal `
        -Name "tags"

    if ($existingTags) {
        $tags = @($existingTags)
    }

    if ($tags -contains $enterpriseApplicationTag) {
        Write-Host "Enterprise application tag already exists."
        return $ServicePrincipal
    }

    Write-Host "Adding enterprise application tag for default portal filtering..."
    $tags = @($tags + $enterpriseApplicationTag | Select-Object -Unique)

    Invoke-GraphPatch `
        -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$servicePrincipalObjectId" `
        -Body @{
            tags = $tags
        }

    return Invoke-MgGraphRequest `
        -Method GET `
        -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$servicePrincipalObjectId?`$select=id,appId,displayName,appRoles,tags"
}

function Ensure-EntraServicePrincipal {
    param(
        [Parameter(Mandatory = $true)]
        [string]$AppId
    )

    $servicePrincipal = Get-EntraServicePrincipalByAppId -AppId $AppId
    if ($servicePrincipal) {
        Write-Host "Service principal already exists."
        return $servicePrincipal
    }

    Write-Host "Creating service principal..."
    $body = @{
        appId = $AppId
        tags = @("WindowsAzureActiveDirectoryIntegratedApp")
    }
    $json = $body | ConvertTo-Json -Depth 20
    try {
        $createdServicePrincipal = Invoke-MgGraphRequest `
            -Method POST `
            -Uri "https://graph.microsoft.com/v1.0/servicePrincipals" `
            -ContentType "application/json" `
            -Body $json
    }
    catch {
        $message = $_.Exception.Message
        if ($message -match "Request_MultipleObjectsWithSameKeyValue" -or $message -match "already in use") {
            Write-Host "Service principal already exists but was not returned by the first lookup. Waiting for read-back..."
            for ($i = 1; $i -le 12; $i++) {
                Start-Sleep -Seconds 5
                $servicePrincipal = Get-EntraServicePrincipalByAppId -AppId $AppId
                if (Get-GraphProperty -InputObject $servicePrincipal -Name "id") {
                    return $servicePrincipal
                }

                Write-Host "Waiting for existing service principal read-back... attempt $i/12"
            }
        }

        throw
    }

    $createdServicePrincipalId = Get-GraphProperty `
        -InputObject $createdServicePrincipal `
        -Name "id"

    if ($createdServicePrincipalId) {
        return $createdServicePrincipal
    }

    for ($i = 1; $i -le 12; $i++) {
        Write-Host "Waiting for service principal creation... attempt $i/12"
        Start-Sleep -Seconds 5
        $servicePrincipal = Get-EntraServicePrincipalByAppId -AppId $AppId
        if (Get-GraphProperty -InputObject $servicePrincipal -Name "id") {
            return $servicePrincipal
        }
    }

    throw "Service principal was created but could not be read back for AppId=$AppId."
}

function Wait-ServicePrincipalAppRoles {
    param(
        [Parameter(Mandatory = $true)]
        [string]$AppId,

        [Parameter(Mandatory = $true)]
        [string[]]$ExpectedAppRoleIds
    )

    for ($i = 1; $i -le 12; $i++) {
        $servicePrincipal = Get-EntraServicePrincipalByAppId -AppId $AppId
        if ($servicePrincipal) {
            $servicePrincipalRoleIds = @()
            $servicePrincipalAppRoles = Get-GraphProperty `
                -InputObject $servicePrincipal `
                -Name "appRoles"

            if ($servicePrincipalAppRoles) {
                $servicePrincipalRoleIds = @($servicePrincipalAppRoles | ForEach-Object {
                    Get-GraphProperty -InputObject $_ -Name "id"
                })
            }

            $missingRoleIds = @($ExpectedAppRoleIds | Where-Object { $servicePrincipalRoleIds -notcontains $_ })
            if ($missingRoleIds.Count -eq 0) {
                return $servicePrincipal
            }
        }

        Write-Host "Waiting for service principal app role propagation... attempt $i/12"
        Start-Sleep -Seconds 5
    }

    Write-Warning "Service principal app roles did not fully propagate yet. Continuing with application role IDs."
    $servicePrincipal = Get-EntraServicePrincipalByAppId -AppId $AppId
    Get-GraphProperty -InputObject $servicePrincipal -Name "id" -Required | Out-Null
    return $servicePrincipal
}

function Add-EntraAppRoleAssignment {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet("users", "groups", "servicePrincipals")]
        [string]$PrincipalCollection,

        [Parameter(Mandatory = $true)]
        [string]$PrincipalObjectId,

        [Parameter(Mandatory = $true)]
        [string]$ResourceServicePrincipalId,

        [Parameter(Mandatory = $true)]
        [string]$AppRoleId,

        [Parameter(Mandatory = $true)]
        [string]$RoleValue
    )

    $assignmentsUri = "https://graph.microsoft.com/v1.0/$PrincipalCollection/$PrincipalObjectId/appRoleAssignments?`$select=id,principalId,resourceId,appRoleId"
    $existingAssignments = Get-GraphCollection -Uri $assignmentsUri
    foreach ($assignment in $existingAssignments) {
        $assignmentResourceId = Get-GraphProperty `
            -InputObject $assignment `
            -Name "resourceId"
        $assignmentAppRoleId = Get-GraphProperty `
            -InputObject $assignment `
            -Name "appRoleId"

        if ("$assignmentResourceId".ToLowerInvariant() -eq $ResourceServicePrincipalId.ToLowerInvariant() -and
            "$assignmentAppRoleId".ToLowerInvariant() -eq $AppRoleId.ToLowerInvariant()) {
            Write-Host "App role already assigned: $RoleValue -> $PrincipalCollection/$PrincipalObjectId"
            return
        }
    }

    Write-Host "Assigning app role: $RoleValue -> $PrincipalCollection/$PrincipalObjectId"
    try {
        Invoke-GraphPost `
            -Uri "https://graph.microsoft.com/v1.0/$PrincipalCollection/$PrincipalObjectId/appRoleAssignments" `
            -Body @{
                principalId = $PrincipalObjectId
                resourceId = $ResourceServicePrincipalId
                appRoleId = $AppRoleId
            }
    }
    catch {
        $message = Get-ErrorMessage -ErrorRecord $_

        if ($message -match "Permission being assigned already exists" -or
            $message -match "already exists on the object" -or
            ($message -match "InvalidUpdate" -and $message -match "already exists")) {
            Write-Host "App role already assigned: $RoleValue -> $PrincipalCollection/$PrincipalObjectId"
            return
        }

        throw
    }
}

function Ensure-DdsUserRoleAssignment {
    param(
        [Parameter(Mandatory = $true)]
        [string]$UserName,

        [string]$UserObjectId = "",

        [Parameter(Mandatory = $true)]
        [string]$DisplayName,

        [string]$GivenName = "",

        [string]$Surname = "",

        [string]$InitialPassword = "",

        [Parameter(Mandatory = $true)]
        [string]$RoleValue,

        [Parameter(Mandatory = $true)]
        [string]$TenantPrimaryDomain,

        [Parameter(Mandatory = $true)]
        [object[]]$DdsAppRoles,

        [Parameter(Mandatory = $true)]
        [string]$ResourceServicePrincipalId,

        [switch]$SkipUserCreation,

        [switch]$RestoreDeletedUser,

        [int]$UserLookupRetryCount = 6,

        [int]$UserLookupRetryDelaySeconds = 10,

        [string]$UserLookupLogPath = ""
    )

    $result = @{
        User = $null
        UserPrincipalName = ""
        UserObjectId = ""
        Created = $false
        TemporaryPassword = ""
        RoleValue = $RoleValue
        RoleId = ""
        Assignment = ""
    }

    if ($SkipUserCreation) {
        return $result
    }

    $role = Get-AppRoleByValue -AppRoles $DdsAppRoles -Value $RoleValue
    if (-not $role) {
        Write-Warning "$RoleValue app role was not found. $UserName assignment will be skipped."
        return $result
    }

    $roleId = Get-GraphProperty `
        -InputObject $role `
        -Name "id" `
        -Required
    $roleValueForAssignment = Get-GraphProperty `
        -InputObject $role `
        -Name "value" `
        -Required

    $userPrincipalName = Resolve-UserPrincipalName `
        -UserName $UserName `
        -TenantPrimaryDomain $TenantPrimaryDomain

    if (-not [string]::IsNullOrWhiteSpace($UserObjectId)) {
        Write-Host "Using existing user object ID for $UserName`: $UserObjectId"
        $user = Get-EntraUserByObjectId -UserObjectId $UserObjectId
        if (-not $user) {
            Write-Warning "User object ID '$UserObjectId' could not be read. The script will still try to assign the app role to that object ID."
            $user = [pscustomobject]@{
                id = $UserObjectId
                userPrincipalName = $userPrincipalName
                displayName = $DisplayName
            }
        }

        $userResult = @{
            User = $user
            Created = $false
            TemporaryPassword = ""
        }
    }
    else {
        $userResult = Ensure-EntraUser `
            -UserPrincipalName $userPrincipalName `
            -DisplayName $DisplayName `
            -GivenName $GivenName `
            -Surname $Surname `
            -InitialPassword $InitialPassword `
            -RestoreDeletedUser:$RestoreDeletedUser `
            -UserLookupRetryCount $UserLookupRetryCount `
            -UserLookupRetryDelaySeconds $UserLookupRetryDelaySeconds `
            -UserLookupLogPath $UserLookupLogPath
    }

    $user = $userResult["User"]
    if (-not $user) {
        throw "User '$userPrincipalName' could not be resolved after retry. App role assignment cannot continue without a user object ID. $(Get-UserLookupLogHint -LogPath $UserLookupLogPath)"
    }

    $userObjectId = Get-GraphProperty `
        -InputObject $user `
        -Name "id" `
        -Required

    Add-EntraAppRoleAssignment `
        -PrincipalCollection "users" `
        -PrincipalObjectId $userObjectId `
        -ResourceServicePrincipalId $ResourceServicePrincipalId `
        -AppRoleId $roleId `
        -RoleValue $roleValueForAssignment

    $result.User = $user
    $result.UserPrincipalName = $userPrincipalName
    $result.UserObjectId = $userObjectId
    $result.Created = [bool]$userResult["Created"]
    $result.TemporaryPassword = $userResult["TemporaryPassword"]
    $result.RoleValue = $roleValueForAssignment
    $result.RoleId = $roleId
    $result.Assignment = "user:$userObjectId`:$roleValueForAssignment"

    return $result
}

# Step 1: Connect to Microsoft Graph with the permissions needed to manage
# app registrations, service principals, app role assignments, and demo users.
Assert-GraphModule
Import-Module Microsoft.Graph.Authentication
Import-Module Microsoft.Graph.Applications

Connect-EntraGraph -TenantId $TenantId

# Step 2: Create or reuse the database/resource app registration. The AppId
# becomes the application_id and the default App ID URI used by Oracle Database.
$application = Get-EntraApplicationByDisplayName -DisplayName $DisplayName
if ($application) {
    Write-Host "Database/resource application already exists. Updating: $DisplayName"
}
else {
    Write-Host "Creating database/resource application: $DisplayName"
    $application = New-MgApplication `
        -DisplayName $DisplayName `
        -SignInAudience "AzureADMyOrg"
}

$application = Get-MgApplication -ApplicationId $application.Id
$appIdUri = "api://$($application.AppId)"
$tenantPrimaryDomain = Get-TenantPrimaryDomain

# Step 3: Publish the delegated Oracle Database connect scope. Oracle uses the
# App ID URI with Entra v2 access tokens.
$existingScope = Get-ExistingScope `
    -Scopes $application.Api.Oauth2PermissionScopes `
    -ScopeName $ScopeName

$oracleScope = New-OracleDatabaseScope `
    -ExistingScope $existingScope `
    -ScopeName $ScopeName `
    -ScopeDisplayName $ScopeDisplayName `
    -ScopeDescription $ScopeDescription

$preAuthorizedApplicationsToPreserve = @()
$applicationApi = Get-GraphProperty -InputObject $application -Name "api"
if ($applicationApi) {
    $existingPreAuthorizedApplications = Get-GraphProperty `
        -InputObject $applicationApi `
        -Name "preAuthorizedApplications"

    if ($existingPreAuthorizedApplications) {
        $preAuthorizedApplicationsToPreserve = @($existingPreAuthorizedApplications | ForEach-Object {
            ConvertTo-PreAuthorizedApplicationBody -PreAuthorizedApplication $_
        })
    }
}

Write-Host "Configuring database/resource App ID URI, scope, and token version..."
Invoke-GraphPatch `
    -Uri "https://graph.microsoft.com/v1.0/applications/$($application.Id)" `
    -Body @{
        identifierUris = @($appIdUri)
        api = @{
            requestedAccessTokenVersion = 2
            oauth2PermissionScopes = @($oracleScope)
            preAuthorizedApplications = @($preAuthorizedApplicationsToPreserve)
        }
    }

$application = Get-MgApplication -ApplicationId $application.Id

# Step 4: Create or reuse the interactive public client app. This mirrors
# 02_setup_entra_id.sh: a separate public client app requests the database scope.
$clientApplication = Get-EntraApplicationByDisplayName -DisplayName $ClientDisplayName
if ($clientApplication) {
    Write-Host "Client application already exists. Updating: $ClientDisplayName"
}
else {
    Write-Host "Creating client application: $ClientDisplayName"
    $clientApplication = New-MgApplication `
        -DisplayName $ClientDisplayName `
        -SignInAudience "AzureADMyOrg"
}

$clientApplication = Get-MgApplication -ApplicationId $clientApplication.Id
$clientApplication = Set-ClientApplicationRedirectUris `
    -ClientApplication $clientApplication `
    -RedirectUris $ClientRedirectUris

$clientApplication = Set-ClientRequiredResourceAccess `
    -ClientApplication $clientApplication `
    -DatabaseAppId $application.AppId `
    -DatabaseScopeId "$($oracleScope.id)" `
    -MicrosoftGraphDelegatedScopeNames $OptionalClaimMicrosoftGraphDelegatedScopes

$application = Set-BackendPreAuthorizedClient `
    -BackendApplication $application `
    -ClientAppId $clientApplication.AppId `
    -DelegatedPermissionId "$($oracleScope.id)"

# Step 5: Ensure service principals for both applications, then grant delegated
# admin consent for the client to call the database/resource scope if possible.
$servicePrincipal = Ensure-EntraServicePrincipal -AppId $application.AppId
$servicePrincipal = Ensure-EnterpriseApplicationTag -ServicePrincipal $servicePrincipal

$clientServicePrincipal = Ensure-EntraServicePrincipal -AppId $clientApplication.AppId
$clientServicePrincipal = Ensure-EnterpriseApplicationTag -ServicePrincipal $clientServicePrincipal

$servicePrincipalObjectIdForConsent = Get-GraphProperty `
    -InputObject $servicePrincipal `
    -Name "id" `
    -Required
$clientServicePrincipalObjectIdForConsent = Get-GraphProperty `
    -InputObject $clientServicePrincipal `
    -Name "id" `
    -Required

$delegatedAdminConsent = $null
try {
    $delegatedAdminConsent = Ensure-DelegatedPermissionGrant `
        -ClientServicePrincipalObjectId $clientServicePrincipalObjectIdForConsent `
        -ResourceServicePrincipalObjectId $servicePrincipalObjectIdForConsent `
        -ScopeName $ScopeName `
        -GrantLabel "$ClientDisplayName -> $DisplayName"
}
catch {
    Write-Warning "Could not grant delegated admin consent automatically. Grant admin consent for '$ClientDisplayName' in Azure Portal if sign-in asks for consent. Details: $(Get-ErrorMessage -ErrorRecord $_)"
}

# Runtime values collected for the final object, env file, SQL file, and log.
$ddsAppRoles = @()
$employeeUser = $null
$employeeUserCreated = $false
$employeeTemporaryPassword = ""
$employeeRoleAssigned = ""
$managerUser = $null
$managerUserCreated = $false
$managerTemporaryPassword = ""
$managerRoleAssigned = ""
$ddsAssignments = New-Object System.Collections.Generic.List[string]

if ([string]::IsNullOrWhiteSpace($EmployeeRoleValue)) {
    $firstDataRoleValue = @($DataRoleValues | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -First 1)
    if ($firstDataRoleValue.Count -gt 0) {
        $EmployeeRoleValue = $firstDataRoleValue[0]
    }
}

if ([string]::IsNullOrWhiteSpace($ManagerRoleValue)) {
    $secondDataRoleValue = @($DataRoleValues | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Skip 1 | Select-Object -First 1)
    if ($secondDataRoleValue.Count -gt 0) {
        $ManagerRoleValue = $secondDataRoleValue[0]
    }
}

if (-not $SkipDeepDataSecuritySettings) {
    Write-Host "Configuring Deep Data Security Entra ID settings..."

    # Step 6: Create or update DDS app roles on the database/resource app.
    $application = Set-DdsAppRoles `
        -Application $application `
        -RoleValues $DataRoleValues

    $ddsAppRoles = @($application.AppRoles |
        Where-Object {
            $roleValue = $_.Value
            $DataRoleValues |
                Where-Object { $roleValue -and $roleValue.ToUpperInvariant() -eq $_.ToUpperInvariant() } |
                Select-Object -First 1
        })

    # Step 7: Ensure the database/resource enterprise application sees the app
    # roles after propagation.
    $application = Get-MgApplication -ApplicationId $application.Id
    $servicePrincipal = Wait-ServicePrincipalAppRoles `
        -AppId $application.AppId `
        -ExpectedAppRoleIds @($ddsAppRoles | ForEach-Object {
            Get-GraphProperty -InputObject $_ -Name "id" -Required
        })
    $servicePrincipal = Ensure-EnterpriseApplicationTag -ServicePrincipal $servicePrincipal

    $servicePrincipalObjectIdForAssignments = Get-GraphProperty `
        -InputObject $servicePrincipal `
        -Name "id" `
        -Required

    # Step 8: Create or reuse demo users, then assign DDS roles directly:
    # emma -> EMPLOYEES and marvin -> MANAGERS by default.
    $employeeUserResult = Ensure-DdsUserRoleAssignment `
        -UserName $EmployeeUserName `
        -UserObjectId $EmployeeUserObjectId `
        -DisplayName $EmployeeDisplayName `
        -GivenName $EmployeeGivenName `
        -Surname $EmployeeSurname `
        -InitialPassword $EmployeeInitialPassword `
        -RoleValue $EmployeeRoleValue `
        -TenantPrimaryDomain $tenantPrimaryDomain `
        -DdsAppRoles $ddsAppRoles `
        -ResourceServicePrincipalId $servicePrincipalObjectIdForAssignments `
        -SkipUserCreation:$SkipEmployeeUserCreation `
        -RestoreDeletedUser:$RestoreDeletedDemoUsers `
        -UserLookupRetryCount $UserLookupRetryCount `
        -UserLookupRetryDelaySeconds $UserLookupRetryDelaySeconds `
        -UserLookupLogPath $UserLookupLogPath

    $employeeUser = $employeeUserResult["User"]
    $employeeUserCreated = [bool]$employeeUserResult["Created"]
    $employeeTemporaryPassword = $employeeUserResult["TemporaryPassword"]
    $employeeRoleAssigned = $employeeUserResult["RoleValue"]
    if (-not [string]::IsNullOrWhiteSpace($employeeUserResult["Assignment"])) {
        $ddsAssignments.Add($employeeUserResult["Assignment"])
    }

    $managerUserResult = Ensure-DdsUserRoleAssignment `
        -UserName $ManagerUserName `
        -UserObjectId $ManagerUserObjectId `
        -DisplayName $ManagerDisplayName `
        -GivenName $ManagerGivenName `
        -Surname $ManagerSurname `
        -InitialPassword $ManagerInitialPassword `
        -RoleValue $ManagerRoleValue `
        -TenantPrimaryDomain $tenantPrimaryDomain `
        -DdsAppRoles $ddsAppRoles `
        -ResourceServicePrincipalId $servicePrincipalObjectIdForAssignments `
        -RestoreDeletedUser:$RestoreDeletedDemoUsers `
        -UserLookupRetryCount $UserLookupRetryCount `
        -UserLookupRetryDelaySeconds $UserLookupRetryDelaySeconds `
        -UserLookupLogPath $UserLookupLogPath

    $managerUser = $managerUserResult["User"]
    $managerUserCreated = [bool]$managerUserResult["Created"]
    $managerTemporaryPassword = $managerUserResult["TemporaryPassword"]
    $managerRoleAssigned = $managerUserResult["RoleValue"]
    if (-not [string]::IsNullOrWhiteSpace($managerUserResult["Assignment"])) {
        $ddsAssignments.Add($managerUserResult["Assignment"])
    }
}
else {
    $application = Get-MgApplication -ApplicationId $application.Id
}

# Step 9: Write Oracle configuration artifacts. The SQL block is the value to
# run in the database after the Entra resources are created.
$oracleIdentityProviderConfig = @{
    application_id_uri = $appIdUri
    tenant_id = $TenantId
    app_id = $application.AppId
} | ConvertTo-Json -Compress

$servicePrincipalObjectId = ""
if ($servicePrincipal) {
    $servicePrincipalObjectId = Get-GraphProperty `
        -InputObject $servicePrincipal `
        -Name "id"
}

$clientServicePrincipalObjectId = ""
if ($clientServicePrincipal) {
    $clientServicePrincipalObjectId = Get-GraphProperty `
        -InputObject $clientServicePrincipal `
        -Name "id"
}

$ddsAppRoleSummary = @($ddsAppRoles | ForEach-Object {
    $roleValue = Get-GraphProperty -InputObject $_ -Name "value"
    $roleId = Get-GraphProperty -InputObject $_ -Name "id"
    "$roleValue=$roleId"
}) -join ","

$employeeUserPrincipalNameOutput = ""
$employeeUserObjectId = ""
if ($employeeUser) {
    $employeeUserPrincipalNameOutput = Get-GraphProperty `
        -InputObject $employeeUser `
        -Name "userPrincipalName"
    $employeeUserObjectId = Get-GraphProperty `
        -InputObject $employeeUser `
        -Name "id"
}

$managerUserPrincipalNameOutput = ""
$managerUserObjectId = ""
if ($managerUser) {
    $managerUserPrincipalNameOutput = Get-GraphProperty `
        -InputObject $managerUser `
        -Name "userPrincipalName"
    $managerUserObjectId = Get-GraphProperty `
        -InputObject $managerUser `
        -Name "id"
}

$ddsAssignmentSummary = $ddsAssignments.ToArray() -join ","
$clientRedirectUriSummary = @($ClientRedirectUris |
    Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
    ForEach-Object { $_.Trim() } |
    Select-Object -Unique) -join ","
$clientMicrosoftGraphDelegatedScopeSummary = @($OptionalClaimMicrosoftGraphDelegatedScopes |
    Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
    ForEach-Object { $_.Trim() } |
    Select-Object -Unique) -join ","
$clientRequestedScope = "$appIdUri/$ScopeName"
$clientDefaultScope = "$appIdUri/.default"
$delegatedAdminConsentStatus = if ($delegatedAdminConsent) { "GrantedOrAlreadyExists" } else { "NotGrantedOrUnknown" }
$backendPreAuthorizedClientAppId = $clientApplication.AppId

$setupLogContent = @"
[Tenant]
TenantId=$TenantId
TenantPrimaryDomain=$tenantPrimaryDomain

[Database/Resource Application Registration]
DisplayName=$DisplayName
AppId=$($application.AppId)
AppObjectId=$($application.Id)
AppIdUri=$appIdUri
Scope=$clientRequestedScope
ScopeName=$ScopeName
ScopeId=$($oracleScope.id)
RequestedAccessTokenVersion=2
PreAuthorizedClientAppId=$backendPreAuthorizedClientAppId

[Interactive Client Application]
DisplayName=$ClientDisplayName
AppId=$($clientApplication.AppId)
AppObjectId=$($clientApplication.Id)
RedirectUris=$clientRedirectUriSummary
RequestedDatabaseScope=$clientRequestedScope
DefaultDatabaseScope=$clientDefaultScope
MicrosoftGraphDelegatedScopes=$clientMicrosoftGraphDelegatedScopeSummary
DelegatedAdminConsent=$delegatedAdminConsentStatus

[Enterprise Application]
DatabaseServicePrincipalObjectId=$servicePrincipalObjectId
ClientServicePrincipalObjectId=$clientServicePrincipalObjectId
AppRoles=$ddsAppRoleSummary
Assignments=$ddsAssignmentSummary

[Demo Users]
EmployeeUserPrincipalName=$employeeUserPrincipalNameOutput
EmployeeUserObjectId=$employeeUserObjectId
EmployeeUserCreated=$employeeUserCreated
EmployeeTemporaryPassword=$employeeTemporaryPassword
EmployeeRole=$employeeRoleAssigned
ManagerUserPrincipalName=$managerUserPrincipalNameOutput
ManagerUserObjectId=$managerUserObjectId
ManagerUserCreated=$managerUserCreated
ManagerTemporaryPassword=$managerTemporaryPassword
ManagerRole=$managerRoleAssigned

[Files]
SetupLogPath=$SetupLogPath

[Oracle Identity Provider Config]
$oracleIdentityProviderConfig

[Oracle ALTER SYSTEM SQL]
ALTER SYSTEM SET IDENTITY_PROVIDER_CONFIG = '$oracleIdentityProviderConfig' SCOPE=BOTH;

[Oracle ADB External Authentication SQL]
BEGIN
  DBMS_CLOUD_ADMIN.ENABLE_EXTERNAL_AUTHENTICATION(
      type   => 'AZURE_AD',
      params => JSON_OBJECT('tenant_id' VALUE '$TenantId',
                            'application_id' VALUE '$($application.AppId)',
                            'application_id_uri' VALUE '$appIdUri'),
      force => TRUE
  );
END;
/
"@

Add-Content -Path $SetupLogPath -Value $setupLogContent -Encoding utf8

[pscustomobject]@{
    TenantId                               = $TenantId
    TenantPrimaryDomain                    = $tenantPrimaryDomain
    DatabaseDisplayName                    = $DisplayName
    DatabaseAppId                          = $application.AppId
    DatabaseAppObjectId                    = $application.Id
    DatabaseAppIdUri                       = $appIdUri
    DatabaseScope                          = $clientRequestedScope
    DatabaseDefaultScope                   = $clientDefaultScope
    DatabaseScopeName                      = $ScopeName
    DatabaseScopeId                        = $oracleScope.id
    DatabaseRequestedAccessTokenVersion    = 2
    DatabasePreAuthorizedClientAppId       = $backendPreAuthorizedClientAppId
    ClientDisplayName                      = $ClientDisplayName
    ClientAppId                            = $clientApplication.AppId
    ClientAppObjectId                      = $clientApplication.Id
    ClientRedirectUris                     = $clientRedirectUriSummary
    ClientMicrosoftGraphDelegatedScopes    = $clientMicrosoftGraphDelegatedScopeSummary
    ClientDelegatedAdminConsent            = $delegatedAdminConsentStatus
    DatabaseServicePrincipalObjectId       = $servicePrincipalObjectId
    ClientServicePrincipalObjectId         = $clientServicePrincipalObjectId
    DdsAppRoles                            = $ddsAppRoleSummary
    EmployeeUserPrincipalName              = $employeeUserPrincipalNameOutput
    EmployeeUserObjectId                   = $employeeUserObjectId
    EmployeeUserCreated                    = $employeeUserCreated
    EmployeeTemporaryPassword              = $employeeTemporaryPassword
    EmployeeRole                           = $employeeRoleAssigned
    ManagerUserPrincipalName               = $managerUserPrincipalNameOutput
    ManagerUserObjectId                    = $managerUserObjectId
    ManagerUserCreated                     = $managerUserCreated
    ManagerTemporaryPassword               = $managerTemporaryPassword
    ManagerRole                            = $managerRoleAssigned
    DdsAssignments                         = $ddsAssignmentSummary
    SetupLogPath                           = $SetupLogPath
} | Format-List
