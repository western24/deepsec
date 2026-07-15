# dds_entrasetup_app.ps1
# Creates or updates two Entra ID applications for Oracle Database external
# authentication with Deep Data Security app roles.
#
# The script is intentionally idempotent: existing applications, service
# principals, users, and app role assignments are reused where possible.
#
# It configures:
# - Backend/API app registration for Oracle Database
# - Backend App ID URI: api://<backend-application-id>
# - Backend delegated scope: session:scope:connect
# - Backend Deep Data Security app roles: EMPLOYEE, MANAGER
# - Frontend/client app registration that authenticates users
# - User token scope used by DeepsecNoOBO_app.java: api://<backend-application-id>/session:scope:connect
# - Frontend redirect URI used by DeepsecNoOBO_app.java: http://localhost:8080/callback
# - Frontend client secret used by DeepsecNoOBO_app.java for client credentials
# - Frontend API permission to call the backend session:scope:connect scope
# - Frontend delegated permission to request backend user tokens
# - Backend pre-authorized client entry for the frontend application
# - Demo users and backend app role assignments: emma -> EMPLOYEE, marvin -> MANAGER
# - Oracle SQL and setup log output
#
# Example:
#   .\dds_entrasetup_app.ps1 `
#     -TenantId "00000000-0000-0000-0000-000000000000" `
#     -DisplayName "OracleDB_Resource" `
#     -ClientDisplayName "OracleDB_Client"

param(
    # Target Entra tenant and application registration display name.
    [Parameter(Mandatory = $true)]
    [string]$TenantId,

    [Parameter(Mandatory = $true)]
    [Alias("AppName")]
    [string]$DisplayName,

    [string]$ClientDisplayName = "",

    [ValidateSet("PublicClient", "Spa", "Web")]
    [string]$ClientApplicationType = "PublicClient",

    [string[]]$ClientRedirectUris = @("http://localhost:8080/callback"),

    [ValidateSet("TenantDomain", "Api")]
    [string]$BackendAppIdUriMode = "Api",

    # Oracle Database requests this delegated scope when obtaining a token.
    [string]$ScopeName = "session:scope:connect",

    [string]$ScopeDisplayName = "Connect to Oracle Database",

    [string]$ScopeDescription = "Allows users to connect to Oracle Database.",

    # Deep Data Security roles exposed by the app registration.
    [string[]]$DataRoleValues = @("EMPLOYEE", "MANAGER"),

    # Demo user assigned to the EMPLOYEE app role.
    [string]$EmployeeRoleValue = "EMPLOYEE",

    [string]$EmployeeUserName = "emma",

    [string]$EmployeeUserObjectId = "",

    [string]$EmployeeDisplayName = "Emma Baker",

    [string]$EmployeeGivenName = "Emma",

    [string]$EmployeeSurname = "Baker",

    [string]$EmployeeInitialPassword = "",

    # Demo user assigned to the MANAGER app role.
    [string]$ManagerRoleValue = "MANAGER",

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

    [string[]]$ClientMicrosoftGraphDelegatedScopes = @(),

    [string]$ClientSecretDisplayName = "DeepsecNoOBO_app",

    [ValidateRange(1, 24)]
    [int]$ClientSecretMonths = 24,

    [switch]$RotateClientSecret,

    [switch]$SkipClientSecret,

    [string]$OutputJavaConfigPath = "",

    [string]$JdbcDbUserName = "HR",

    [string]$JdbcDbPassword = "",

    [string]$SetupLogPath = ".\dds_entrasetup_app.log"
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

if ([string]::IsNullOrWhiteSpace($OutputJavaConfigPath)) {
    $OutputJavaConfigPath = Join-Path `
        -Path $PSScriptRoot `
        -ChildPath "vscode\deepsec\DeepsecNoOBO_app.generated.properties"
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

function ConvertTo-PythonDoubleQuotedString {
    param(
        [AllowNull()]
        [string]$Value = ""
    )

    if ($null -eq $Value) {
        $Value = ""
    }

    $escaped = $Value.Replace('\', '\\').Replace('"', '\"')
    $escaped = $escaped.Replace("`r", '\r').Replace("`n", '\n')
    return '"' + $escaped + '"'
}
function Connect-EntraGraph {
    param(
        [Parameter(Mandatory = $true)]
        [string]$TenantId
    )

    $requiredScopes = @(
        "Application.ReadWrite.All",
        "AppRoleAssignment.ReadWrite.All",
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
        allowedMemberTypes = @("User")
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

function Remove-MicrosoftGraphDelegatedScopes {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Application,

        [string[]]$ScopeNames = @()
    )

    $scopeNamesToRemove = @($ScopeNames |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
        ForEach-Object { $_.Trim() } |
        Select-Object -Unique)

    if ($scopeNamesToRemove.Count -eq 0) {
        return $Application
    }

    $microsoftGraphAppId = "00000003-0000-0000-c000-000000000000"
    $scopeAccessToRemove = @(Get-MicrosoftGraphDelegatedScopeAccess -ScopeNames $scopeNamesToRemove)
    $scopeAccessKeysToRemove = @($scopeAccessToRemove | ForEach-Object {
        $accessId = "$(Get-GraphProperty -InputObject $_ -Name "id" -Required)"
        $accessType = "$(Get-GraphProperty -InputObject $_ -Name "type" -Required)"
        "$($accessType.ToLowerInvariant()):$($accessId.ToLowerInvariant())"
    })

    $requiredResourceAccess = New-Object System.Collections.Generic.List[object]
    if ($Application.RequiredResourceAccess) {
        foreach ($entry in $Application.RequiredResourceAccess) {
            if ("$($entry.ResourceAppId)" -ne $microsoftGraphAppId) {
                $requiredResourceAccess.Add((ConvertTo-ResourceAccessBody -RequiredResourceAccess $entry))
                continue
            }

            $remainingResourceAccess = New-Object System.Collections.Generic.List[object]
            if ($entry.ResourceAccess) {
                foreach ($access in $entry.ResourceAccess) {
                    $accessId = "$(Get-GraphProperty -InputObject $access -Name "id")"
                    $accessType = "$(Get-GraphProperty -InputObject $access -Name "type")"
                    $accessKey = "$($accessType.ToLowerInvariant()):$($accessId.ToLowerInvariant())"
                    if ($scopeAccessKeysToRemove -contains $accessKey) {
                        continue
                    }

                    $remainingResourceAccess.Add(@{
                        id = $accessId
                        type = $accessType
                    })
                }
            }

            if ($remainingResourceAccess.Count -gt 0) {
                $requiredResourceAccess.Add(@{
                    resourceAppId = $microsoftGraphAppId
                    resourceAccess = @($remainingResourceAccess.ToArray())
                })
            }
        }
    }

    Write-Host "Removing unused Microsoft Graph delegated scopes from $($Application.DisplayName): $($scopeNamesToRemove -join ', ')"
    Invoke-GraphPatch `
        -Uri "https://graph.microsoft.com/v1.0/applications/$($Application.Id)" `
        -Body @{
            requiredResourceAccess = @($requiredResourceAccess.ToArray())
        }

    return Get-MgApplication -ApplicationId $Application.Id
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
        [ValidateSet("PublicClient", "Spa", "Web")]
        [string]$ApplicationType,

        [string[]]$RedirectUris = @()
    )

    $redirectUrisToSet = @($RedirectUris |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
        ForEach-Object { $_.Trim() } |
        Select-Object -Unique)

    $body = @{}
    switch ($ApplicationType) {
        "PublicClient" {
            $body.publicClient = @{
                redirectUris = @($redirectUrisToSet)
            }
            $body.isFallbackPublicClient = $true
        }
        "Spa" {
            $body.spa = @{
                redirectUris = @($redirectUrisToSet)
            }
            $body.isFallbackPublicClient = $false
        }
        "Web" {
            $body.web = @{
                redirectUris = @($redirectUrisToSet)
            }
            $body.isFallbackPublicClient = $false
        }
    }

    Write-Host "Configuring frontend redirect URIs for $ApplicationType."
    Invoke-GraphPatch `
        -Uri "https://graph.microsoft.com/v1.0/applications/$($ClientApplication.Id)" `
        -Body $body

    return Get-MgApplication -ApplicationId $ClientApplication.Id
}

function ConvertTo-OptionalClaimBody {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Claim
    )

    $body = @{
        name = "$(Get-GraphProperty -InputObject $Claim -Name "name" -Required)"
        essential = [bool](Get-GraphProperty -InputObject $Claim -Name "essential")
        additionalProperties = @()
    }

    $source = Get-GraphProperty -InputObject $Claim -Name "source"
    if ($null -ne $source) {
        $body.source = $source
    }

    $additionalProperties = Get-GraphProperty `
        -InputObject $Claim `
        -Name "additionalProperties"
    if ($additionalProperties) {
        $body.additionalProperties = @($additionalProperties)
    }

    return $body
}

function Get-OptionalClaimBodiesWithoutName {
    param(
        [AllowNull()]
        [object[]]$Claims,

        [Parameter(Mandatory = $true)]
        [string]$ClaimName
    )

    $bodies = New-Object System.Collections.Generic.List[object]
    if ($Claims) {
        foreach ($claim in @($Claims)) {
            if ($null -eq $claim) {
                continue
            }

            $name = Get-GraphProperty -InputObject $claim -Name "name"
            if ($name -and "$name" -eq $ClaimName) {
                continue
            }

            $bodies.Add((ConvertTo-OptionalClaimBody -Claim $claim))
        }
    }

    return @($bodies.ToArray())
}

function Remove-ClientApplicationApiExposure {
    param(
        [Parameter(Mandatory = $true)]
        [object]$ClientApplication,

        [string]$ScopeName = "access_as_user",

        [string]$OptionalClaimName = "upn"
    )

    $clientAppIdUri = "api://$($ClientApplication.AppId)"
    $clientApi = Get-GraphProperty -InputObject $ClientApplication -Name "api"
    $existingClientScopes = @()
    if ($clientApi) {
        $existingClientScopes = @(Get-GraphProperty -InputObject $clientApi -Name "oauth2PermissionScopes")
    }

    $scopeBodies = New-Object System.Collections.Generic.List[object]
    if ($existingClientScopes) {
        foreach ($scope in @($existingClientScopes)) {
            $scopeValue = Get-GraphProperty -InputObject $scope -Name "value"
            if ($scopeValue -and "$scopeValue" -eq $ScopeName) {
                continue
            }

            $scopeBodies.Add((ConvertTo-OAuth2PermissionScopeBody -Scope $scope))
        }
    }

    $identifierUris = New-Object System.Collections.Generic.List[string]
    foreach ($identifierUri in @($ClientApplication.IdentifierUris)) {
        if ([string]::IsNullOrWhiteSpace("$identifierUri")) {
            continue
        }

        if ($scopeBodies.Count -eq 0 -and "$identifierUri" -eq $clientAppIdUri) {
            continue
        }

        $identifierUris.Add("$identifierUri")
    }

    $optionalClaims = Get-GraphProperty `
        -InputObject $ClientApplication `
        -Name "optionalClaims"
    $idTokenClaims = @()
    $accessTokenClaims = @()
    $saml2TokenClaims = @()
    if ($optionalClaims) {
        $idTokenClaims = @(Get-GraphProperty -InputObject $optionalClaims -Name "idToken")
        $accessTokenClaims = @(Get-GraphProperty -InputObject $optionalClaims -Name "accessToken")
        $saml2TokenClaims = @(Get-GraphProperty -InputObject $optionalClaims -Name "saml2Token")
    }

    Write-Host "Removing unused frontend API exposure: $clientAppIdUri/$ScopeName"
    Invoke-GraphPatch `
        -Uri "https://graph.microsoft.com/v1.0/applications/$($ClientApplication.Id)" `
        -Body @{
            identifierUris = @($identifierUris.ToArray())
            api = @{
                oauth2PermissionScopes = @($scopeBodies.ToArray())
            }
            optionalClaims = @{
                idToken = @(Get-OptionalClaimBodiesWithoutName `
                    -Claims $idTokenClaims `
                    -ClaimName $OptionalClaimName)
                accessToken = @(Get-OptionalClaimBodiesWithoutName `
                    -Claims $accessTokenClaims `
                    -ClaimName $OptionalClaimName)
                saml2Token = @(Get-OptionalClaimBodiesWithoutName `
                    -Claims $saml2TokenClaims `
                    -ClaimName $OptionalClaimName)
            }
        }

    return Get-MgApplication -ApplicationId $ClientApplication.Id
}

function Ensure-ClientApplicationSecret {
    param(
        [Parameter(Mandatory = $true)]
        [object]$ClientApplication,

        [Parameter(Mandatory = $true)]
        [string]$DisplayName,

        [Parameter(Mandatory = $true)]
        [int]$LifetimeMonths,

        [switch]$Rotate,

        [switch]$Skip
    )

    $result = @{
        Created = $false
        SecretText = ""
        KeyId = ""
        EndDateTime = ""
        DisplayName = $DisplayName
    }

    if ($Skip) {
        Write-Host "Skipping frontend client secret creation."
        return $result
    }

    $clientApplicationWithSecrets = Invoke-MgGraphRequest `
        -Method GET `
        -Uri "https://graph.microsoft.com/v1.0/applications/$($ClientApplication.Id)?`$select=id,appId,displayName,passwordCredentials"

    $now = (Get-Date).ToUniversalTime()
    $existingSecret = $null
    $passwordCredentials = Get-GraphProperty `
        -InputObject $clientApplicationWithSecrets `
        -Name "passwordCredentials"

    if ($passwordCredentials) {
        $existingSecret = $passwordCredentials | Where-Object {
            $secretDisplayName = Get-GraphProperty -InputObject $_ -Name "displayName"
            $secretEndDateTime = Get-GraphProperty -InputObject $_ -Name "endDateTime"
            $secretDisplayName -eq $DisplayName -and
                $secretEndDateTime -and
                ([datetime]$secretEndDateTime).ToUniversalTime() -gt $now.AddDays(7)
        } | Select-Object -First 1
    }

    if ($existingSecret -and -not $Rotate) {
        $result.KeyId = "$(Get-GraphProperty -InputObject $existingSecret -Name "keyId")"
        $result.EndDateTime = "$(Get-GraphProperty -InputObject $existingSecret -Name "endDateTime")"
        Write-Host "Frontend client secret already exists. Existing secret value cannot be read back. Use -RotateClientSecret to create a new one."
        return $result
    }

    $endDateTime = $now.AddMonths($LifetimeMonths)
    $body = @{
        passwordCredential = @{
            displayName = $DisplayName
            endDateTime = $endDateTime.ToString("o")
        }
    }
    $json = $body | ConvertTo-Json -Depth 20

    Write-Host "Creating frontend client secret: $DisplayName"
    $createdSecret = Invoke-MgGraphRequest `
        -Method POST `
        -Uri "https://graph.microsoft.com/v1.0/applications/$($ClientApplication.Id)/addPassword" `
        -ContentType "application/json" `
        -Body $json

    $result.Created = $true
    $result.SecretText = "$(Get-GraphProperty -InputObject $createdSecret -Name "secretText")"
    $result.KeyId = "$(Get-GraphProperty -InputObject $createdSecret -Name "keyId")"
    $result.EndDateTime = "$(Get-GraphProperty -InputObject $createdSecret -Name "endDateTime")"

    return $result
}

function Set-ClientRequiredResourceAccess {
    param(
        [Parameter(Mandatory = $true)]
        [object]$ClientApplication,

        [Parameter(Mandatory = $true)]
        [string]$BackendAppId,

        [Parameter(Mandatory = $true)]
        [string]$BackendScopeId,

        [string[]]$MicrosoftGraphDelegatedScopeNames = @()
    )

    $microsoftGraphAppId = "00000003-0000-0000-c000-000000000000"
    $requiredResourceAccess = New-Object System.Collections.Generic.List[object]
    $backendResourceAccess = New-Object System.Collections.Generic.List[object]
    $microsoftGraphResourceAccess = New-Object System.Collections.Generic.List[object]

    if ($ClientApplication.RequiredResourceAccess) {
        foreach ($entry in $ClientApplication.RequiredResourceAccess) {
            if ("$($entry.ResourceAppId)" -eq $BackendAppId) {
                if ($entry.ResourceAccess) {
                    foreach ($access in $entry.ResourceAccess) {
                        if ("$($access.Type)" -ne "Role") {
                            Add-ResourceAccessIfMissing `
                                -ResourceAccess $backendResourceAccess `
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
        -ResourceAccess $backendResourceAccess `
        -AccessId $BackendScopeId `
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
        resourceAppId = $BackendAppId
        resourceAccess = @($backendResourceAccess.ToArray())
    })

    if ($microsoftGraphResourceAccess.Count -gt 0) {
        $requiredResourceAccess.Add(@{
            resourceAppId = $microsoftGraphAppId
            resourceAccess = @($microsoftGraphResourceAccess.ToArray())
        })
    }

    Write-Host "Configuring frontend delegated API permission for backend scope."
    Invoke-GraphPatch `
        -Uri "https://graph.microsoft.com/v1.0/applications/$($ClientApplication.Id)" `
        -Body @{
            requiredResourceAccess = @($requiredResourceAccess.ToArray())
        }

    return Get-MgApplication -ApplicationId $ClientApplication.Id
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

function Remove-EntraAppRoleAssignments {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet("users", "groups", "servicePrincipals")]
        [string]$PrincipalCollection,

        [Parameter(Mandatory = $true)]
        [string]$PrincipalObjectId,

        [Parameter(Mandatory = $true)]
        [string]$ResourceServicePrincipalId,

        [Parameter(Mandatory = $true)]
        [object[]]$AppRoles
    )

    $roleIds = @($AppRoles |
        Where-Object { $_ } |
        ForEach-Object { "$(Get-GraphProperty -InputObject $_ -Name "id" -Required)".ToLowerInvariant() } |
        Select-Object -Unique)

    if ($roleIds.Count -eq 0) {
        return
    }

    $assignmentsUri = "https://graph.microsoft.com/v1.0/$PrincipalCollection/$PrincipalObjectId/appRoleAssignments?`$select=id,principalId,resourceId,appRoleId"
    $existingAssignments = Get-GraphCollection -Uri $assignmentsUri
    foreach ($assignment in $existingAssignments) {
        $assignmentId = Get-GraphProperty `
            -InputObject $assignment `
            -Name "id"
        $assignmentResourceId = Get-GraphProperty `
            -InputObject $assignment `
            -Name "resourceId"
        $assignmentAppRoleId = Get-GraphProperty `
            -InputObject $assignment `
            -Name "appRoleId"

        if (-not $assignmentId) {
            continue
        }

        if ("$assignmentResourceId".ToLowerInvariant() -eq $ResourceServicePrincipalId.ToLowerInvariant() -and
            $roleIds -contains "$assignmentAppRoleId".ToLowerInvariant()) {
            Write-Host "Removing app role assignment from $PrincipalCollection/$($PrincipalObjectId): $assignmentAppRoleId"
            Invoke-MgGraphRequest `
                -Method DELETE `
                -Uri "https://graph.microsoft.com/v1.0/$PrincipalCollection/$PrincipalObjectId/appRoleAssignments/$assignmentId" `
                | Out-Null
        }
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

# Step 2: Create or reuse the backend app registration. By default, the
# backend exposes an Entra v2 API audience: api://<backend-application-id>.
$application = Get-EntraApplicationByDisplayName -DisplayName $DisplayName
if ($application) {
    Write-Host "Application already exists. Updating: $DisplayName"
}
else {
    Write-Host "Creating application: $DisplayName"
    $application = New-MgApplication `
        -DisplayName $DisplayName `
        -SignInAudience "AzureADMyOrg"
}

$application = Get-MgApplication -ApplicationId $application.Id
$tenantPrimaryDomain = Get-TenantPrimaryDomain
if ($BackendAppIdUriMode -eq "TenantDomain") {
    if ([string]::IsNullOrWhiteSpace($tenantPrimaryDomain)) {
        throw "Tenant primary domain could not be resolved. Use -BackendAppIdUriMode Api or specify a tenant where the primary domain is readable."
    }

    $appIdUri = "https://$tenantPrimaryDomain/$($application.AppId)"
}
else {
    $appIdUri = "api://$($application.AppId)"
}

# Step 3: Publish the delegated Oracle Database connect scope. Oracle uses
# this App ID URI with v2 tokens.
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

$backendOptionalClaims = Get-GraphProperty `
    -InputObject $application `
    -Name "optionalClaims"
$backendIdTokenClaims = @()
$backendAccessTokenClaims = @()
$backendSaml2TokenClaims = @()
if ($backendOptionalClaims) {
    $backendIdTokenClaims = @(Get-GraphProperty -InputObject $backendOptionalClaims -Name "idToken")
    $backendAccessTokenClaims = @(Get-GraphProperty -InputObject $backendOptionalClaims -Name "accessToken")
    $backendSaml2TokenClaims = @(Get-GraphProperty -InputObject $backendOptionalClaims -Name "saml2Token")
}

Write-Host "Configuring App ID URI, scope, and token version..."
Invoke-GraphPatch `
    -Uri "https://graph.microsoft.com/v1.0/applications/$($application.Id)" `
    -Body @{
        identifierUris = @($appIdUri)
        api = @{
            requestedAccessTokenVersion = 2
            oauth2PermissionScopes = @($oracleScope)
            preAuthorizedApplications = @($preAuthorizedApplicationsToPreserve)
        }
        optionalClaims = @{
            idToken = @(Get-OptionalClaimBodiesWithoutName `
                -Claims $backendIdTokenClaims `
                -ClaimName "upn")
            accessToken = @(Get-OptionalClaimBodiesWithoutName `
                -Claims $backendAccessTokenClaims `
                -ClaimName "upn")
            saml2Token = @(Get-OptionalClaimBodiesWithoutName `
                -Claims $backendSaml2TokenClaims `
                -ClaimName "upn")
        }
    }

$application = Get-MgApplication -ApplicationId $application.Id
$application = Remove-MicrosoftGraphDelegatedScopes `
    -Application $application `
    -ScopeNames @("profile")

# Step 4: Create or reuse the frontend/client app. This app authenticates users
# and requests the backend API scope: api://<backend-app-id>/session:scope:connect.
$clientApplication = Get-EntraApplicationByDisplayName -DisplayName $ClientDisplayName
if ($clientApplication) {
    Write-Host "Frontend application already exists. Updating: $ClientDisplayName"
}
else {
    Write-Host "Creating frontend application: $ClientDisplayName"
    $clientApplication = New-MgApplication `
        -DisplayName $ClientDisplayName `
        -SignInAudience "AzureADMyOrg"
}

$clientApplication = Get-MgApplication -ApplicationId $clientApplication.Id
$clientApplication = Set-ClientApplicationRedirectUris `
    -ClientApplication $clientApplication `
    -ApplicationType $ClientApplicationType `
    -RedirectUris $ClientRedirectUris

$clientApplication = Remove-ClientApplicationApiExposure `
    -ClientApplication $clientApplication `
    -ScopeName "access_as_user"

$clientApplication = Set-ClientRequiredResourceAccess `
    -ClientApplication $clientApplication `
    -BackendAppId $application.AppId `
    -BackendScopeId "$($oracleScope.id)" `
    -MicrosoftGraphDelegatedScopeNames $ClientMicrosoftGraphDelegatedScopes

$application = Set-BackendPreAuthorizedClient `
    -BackendApplication $application `
    -ClientAppId $clientApplication.AppId `
    -DelegatedPermissionId "$($oracleScope.id)"

$clientSecretResult = Ensure-ClientApplicationSecret `
    -ClientApplication $clientApplication `
    -DisplayName $ClientSecretDisplayName `
    -LifetimeMonths $ClientSecretMonths `
    -Rotate:$RotateClientSecret `
    -Skip:$SkipClientSecret

$clientServicePrincipal = Ensure-EntraServicePrincipal -AppId $clientApplication.AppId
$clientServicePrincipal = Ensure-EnterpriseApplicationTag -ServicePrincipal $clientServicePrincipal

# Runtime values collected for the final object, env file, SQL file, and log.
$servicePrincipal = $null
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

    $existingDdsAppRoles = @($application.AppRoles |
        Where-Object {
            $roleValue = $_.Value
            $DataRoleValues |
                Where-Object { $roleValue -and $roleValue.ToUpperInvariant() -eq $_.ToUpperInvariant() } |
                Select-Object -First 1
        })

    if ($existingDdsAppRoles.Count -gt 0) {
        $servicePrincipal = Ensure-EntraServicePrincipal -AppId $application.AppId
        $servicePrincipalObjectIdForCleanup = Get-GraphProperty `
            -InputObject $servicePrincipal `
            -Name "id" `
            -Required
        $clientServicePrincipalObjectIdForCleanup = Get-GraphProperty `
            -InputObject $clientServicePrincipal `
            -Name "id" `
            -Required

        # Older script versions assigned DDS roles to the frontend service
        # principal, which put roles into the app-only DB token. Remove those
        # stale assignments because DDS roles belong in the user token here.
        Remove-EntraAppRoleAssignments `
            -PrincipalCollection "servicePrincipals" `
            -PrincipalObjectId $clientServicePrincipalObjectIdForCleanup `
            -ResourceServicePrincipalId $servicePrincipalObjectIdForCleanup `
            -AppRoles $existingDdsAppRoles
    }

    # Step 5: Create or update user-only DDS app roles on the backend application.
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

    # Keep the frontend app permission delegated-only. The user token carries
    # EMPLOYEE/MANAGER; the app-only DB token should not carry DDS roles.
    $clientApplication = Set-ClientRequiredResourceAccess `
        -ClientApplication $clientApplication `
        -BackendAppId $application.AppId `
        -BackendScopeId "$($oracleScope.id)" `
        -MicrosoftGraphDelegatedScopeNames $ClientMicrosoftGraphDelegatedScopes

    # Step 6: Ensure the backend enterprise application exists and appears in the
    # default Enterprise Applications portal filter.
    $application = Get-MgApplication -ApplicationId $application.Id
    $servicePrincipal = Ensure-EntraServicePrincipal -AppId $application.AppId
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

    $clientServicePrincipalObjectIdForAssignments = Get-GraphProperty `
        -InputObject $clientServicePrincipal `
        -Name "id" `
        -Required

    # Step 7: Remove any stale frontend service principal role assignments left
    # by older script versions. The app-only DB token should be role-free.
    Remove-EntraAppRoleAssignments `
        -PrincipalCollection "servicePrincipals" `
        -PrincipalObjectId $clientServicePrincipalObjectIdForAssignments `
        -ResourceServicePrincipalId $servicePrincipalObjectIdForAssignments `
        -AppRoles $ddsAppRoles

    # Step 8: Create or reuse demo users, then assign DDS roles directly:
    # emma -> EMPLOYEE and marvin -> MANAGER by default.
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

# Step 9: Write Oracle configuration artifacts. Oracle checks application_id
# against the token aud claim. With api://<app-id>/.default, Entra v2 still
# emits the backend application ID GUID as aud, so application_id stays GUID
# while application_id_uri stays api://<backend-application-id>.
$oracleExpectedAudience = $application.AppId

$oracleIdentityProviderConfig = @{
    application_id_uri = $appIdUri
    tenant_id = $TenantId
    app_id = $oracleExpectedAudience
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
$primaryClientRedirectUri = @($ClientRedirectUris |
    Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
    Select-Object -First 1)
if ($primaryClientRedirectUri.Count -gt 0) {
    $primaryClientRedirectUri = $primaryClientRedirectUri[0].Trim()
}
else {
    $primaryClientRedirectUri = ""
}
$clientMicrosoftGraphDelegatedScopeSummary = @($ClientMicrosoftGraphDelegatedScopes |
    Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
    ForEach-Object { $_.Trim() } |
    Select-Object -Unique) -join ","
$clientRequestedScope = "$appIdUri/$ScopeName"
$backendDefaultScope = "$appIdUri/.default"
$clientSecretCreated = [bool]$clientSecretResult["Created"]
$clientSecretValue = "$($clientSecretResult["SecretText"])"
$clientSecretKeyId = "$($clientSecretResult["KeyId"])"
$clientSecretEndDateTime = "$($clientSecretResult["EndDateTime"])"
$clientSecretStatus = if ($clientSecretCreated) { "Created" } elseif ($SkipClientSecret) { "Skipped" } else { "ExistingSecretValueNotReadable" }

if ([string]::IsNullOrWhiteSpace($clientSecretValue) -and
    -not [string]::IsNullOrWhiteSpace($OutputJavaConfigPath) -and
    (Test-Path -LiteralPath $OutputJavaConfigPath)) {
    $existingSecretLine = Get-Content -LiteralPath $OutputJavaConfigPath |
        Where-Object { $_ -match "^TOKEN_CLIENT_SECRET=.+$" } |
        Select-Object -First 1

    if ($existingSecretLine) {
        $clientSecretValue = $existingSecretLine.Substring("TOKEN_CLIENT_SECRET=".Length).Trim()
        $clientSecretStatus = "ExistingSecretValuePreservedFromConfig"
    }
}


$setupLogContent = @"
[Tenant]
TenantId=$TenantId
TenantPrimaryDomain=$tenantPrimaryDomain

[Backend Application Registration]
DisplayName=$DisplayName
AppId=$($application.AppId)
AppObjectId=$($application.Id)
AppIdUri=$appIdUri
ExpectedAudience=$oracleExpectedAudience
Scope=$clientRequestedScope
ScopeName=$ScopeName
ScopeId=$($oracleScope.id)
RequestedAccessTokenVersion=2

[Frontend Client Application]
DisplayName=$ClientDisplayName
AppId=$($clientApplication.AppId)
AppObjectId=$($clientApplication.Id)
ApplicationType=$ClientApplicationType
RedirectUris=$clientRedirectUriSummary
CallbackPort=8080
RequestedBackendScope=$clientRequestedScope
UserTokenScope=$clientRequestedScope
MicrosoftGraphDelegatedScopes=$clientMicrosoftGraphDelegatedScopeSummary
ServicePrincipalObjectId=$clientServicePrincipalObjectId
ClientSecretStatus=$clientSecretStatus
ClientSecretKeyId=$clientSecretKeyId
ClientSecretEndDateTime=$clientSecretEndDateTime

[Enterprise Application]
BackendServicePrincipalObjectId=$servicePrincipalObjectId
FrontendServicePrincipalObjectId=$clientServicePrincipalObjectId
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
OutputJavaConfigPath=$OutputJavaConfigPath
SetupLogPath=$SetupLogPath

[Oracle Identity Provider Config]
$oracleIdentityProviderConfig

[Oracle ALTER SYSTEM SQL]
ALTER SYSTEM SET IDENTITY_PROVIDER_CONFIG = '$oracleIdentityProviderConfig' SCOPE=BOTH;
"@

$javaConfigContent = @"
# Generated values for com.example.DeepsecNoOBO_app
# Secret values can only be emitted when a new secret is created.
CLIENT_APP_ID=$($clientApplication.AppId)
TOKEN_CLIENT_APP_ID=$($clientApplication.AppId)
TOKEN_CLIENT_SECRET=$clientSecretValue
DB_APP_ID=$($application.AppId)
TENANT_ID=$TenantId
USER_ACCESS_SCOPE=$clientRequestedScope
DB_SCOPE=$backendDefaultScope
REDIRECT_URI=$primaryClientRedirectUri
CALLBACK_PORT=8080
DB_USERNAME=$JdbcDbUserName
DB_PASSWORD=$JdbcDbPassword
"@

$tokenClientSecretForManagePy = $clientSecretValue
if ([string]::IsNullOrWhiteSpace($tokenClientSecretForManagePy)) {
    $tokenClientSecretForManagePy = "<client secret value is not readable; rerun dds_entrasetup_app.ps1 with -RotateClientSecret or copy it from a previous generated config>"
}

$pythonConfigureEnvironmentContent = @"

[変更パラメータ]
AZURE_USER_CLIENT_ID = $(ConvertTo-PythonDoubleQuotedString -Value "$($clientApplication.AppId)")
AZURE_USER_AUTHORITY = $(ConvertTo-PythonDoubleQuotedString -Value "https://login.microsoftonline.com/$TenantId")
AZURE_USER_REDIRECT_URI = $(ConvertTo-PythonDoubleQuotedString -Value "$primaryClientRedirectUri")
CALLBACK_PORT = $(ConvertTo-PythonDoubleQuotedString -Value "8080")
AZURE_USER_SCOPES = $(ConvertTo-PythonDoubleQuotedString -Value "$clientRequestedScope")

AZURE_DB_CLIENT_ID = $(ConvertTo-PythonDoubleQuotedString -Value "$($clientApplication.AppId)")
AZURE_DB_CLIENT_CREDENTIAL = $(ConvertTo-PythonDoubleQuotedString -Value "$tokenClientSecretForManagePy")
AZURE_DB_AUTHORITY = $(ConvertTo-PythonDoubleQuotedString -Value "https://login.microsoftonline.com/$TenantId")
AZURE_DB_SCOPES = $(ConvertTo-PythonDoubleQuotedString -Value "$backendDefaultScope")

"@

foreach ($outputPath in @($OutputJavaConfigPath, $SetupLogPath)) {
    $outputDirectory = Split-Path -Path $outputPath -Parent
    if (-not [string]::IsNullOrWhiteSpace($outputDirectory) -and
        -not (Test-Path -LiteralPath $outputDirectory)) {
        New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null
    }
}

Set-Content -Path $OutputJavaConfigPath -Value $javaConfigContent -Encoding utf8
Add-Content -Path $SetupLogPath -Value $setupLogContent -Encoding utf8
Add-Content -Path $SetupLogPath -Value $pythonConfigureEnvironmentContent -Encoding utf8

[pscustomobject]@{
    TenantId                                  = $TenantId
    TenantPrimaryDomain                       = $tenantPrimaryDomain
    BackendDisplayName                        = $DisplayName
    BackendAppId                              = $application.AppId
    BackendAppObjectId                        = $application.Id
    BackendAppIdUri                           = $appIdUri
    BackendExpectedAudience                   = $oracleExpectedAudience
    BackendScope                              = $clientRequestedScope
    BackendDefaultScope                       = $backendDefaultScope
    BackendScopeName                          = $ScopeName
    BackendScopeId                            = $oracleScope.id
    BackendRequestedAccessTokenVersion        = 2
    FrontendDisplayName                       = $ClientDisplayName
    FrontendAppId                             = $clientApplication.AppId
    FrontendAppObjectId                       = $clientApplication.Id
    FrontendApplicationType                   = $ClientApplicationType
    FrontendRedirectUris                      = $clientRedirectUriSummary
    FrontendRequestedBackendScope             = $clientRequestedScope
    FrontendMicrosoftGraphDelegatedScopes     = $clientMicrosoftGraphDelegatedScopeSummary
    FrontendClientSecretStatus                = $clientSecretStatus
    FrontendClientSecretKeyId                 = $clientSecretKeyId
    FrontendClientSecretEndDateTime           = $clientSecretEndDateTime
    BackendServicePrincipalObjectId           = $servicePrincipalObjectId
    FrontendServicePrincipalObjectId          = $clientServicePrincipalObjectId
    DdsAppRoles                               = $ddsAppRoleSummary
    EmployeeUserPrincipalName                 = $employeeUserPrincipalNameOutput
    EmployeeUserObjectId                      = $employeeUserObjectId
    EmployeeUserCreated                       = $employeeUserCreated
    EmployeeTemporaryPassword                 = $employeeTemporaryPassword
    EmployeeRole                              = $employeeRoleAssigned
    ManagerUserPrincipalName                  = $managerUserPrincipalNameOutput
    ManagerUserObjectId                       = $managerUserObjectId
    ManagerUserCreated                        = $managerUserCreated
    ManagerTemporaryPassword                  = $managerTemporaryPassword
    ManagerRole                               = $managerRoleAssigned
    DdsAssignments                            = $ddsAssignmentSummary
    OutputJavaConfigPath                      = $OutputJavaConfigPath
    SetupLogPath                              = $SetupLogPath
} | Format-List










