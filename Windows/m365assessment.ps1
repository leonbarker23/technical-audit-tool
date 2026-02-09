<#
.SYNOPSIS
    Microsoft 365 Assessment data collection script for Technical Audit Tool.

.DESCRIPTION
    Connects to Microsoft Graph and collects comprehensive M365 tenant data
    for MSP discovery and roadmapping. Uses Maester for security testing.

.PARAMETER OutputPath
    Directory to save the assessment results.

.PARAMETER ClientName
    Client name for folder organisation.

.PARAMETER SkipMaester
    Skip Maester security tests (runs by default).

.NOTES
    Requires: PowerShell 7+, Microsoft.Graph modules, Maester
#>

param(
    [Parameter(Mandatory=$true)]
    [string]$OutputPath,

    [Parameter(Mandatory=$true)]
    [string]$ClientName,

    [switch]$SkipMaester,

    [switch]$UpdateMaesterTests
)

$ErrorActionPreference = "Stop"

# ── Helper functions ─────────────────────────────────────────────────────────

function Write-Status {
    param([string]$Message, [string]$Type = "INFO")
    $prefix = switch ($Type) {
        "INFO"    { "[*]" }
        "SUCCESS" { "[+]" }
        "WARNING" { "[!]" }
        "ERROR"   { "[!]" }
        default   { "[*]" }
    }
    Write-Host "$prefix $Message"
}

# ── Check prerequisites ──────────────────────────────────────────────────────

Write-Status "Checking prerequisites..."

# Check PowerShell version
if ($PSVersionTable.PSVersion.Major -lt 7) {
    Write-Status "PowerShell 7+ required. Current version: $($PSVersionTable.PSVersion)" "ERROR"
    exit 1
}

# Check/install required modules
$requiredModules = @(
    'Microsoft.Graph.Authentication',
    'Microsoft.Graph.Users',
    'Microsoft.Graph.Identity.SignIns',
    'Microsoft.Graph.Identity.DirectoryManagement',
    'Microsoft.Graph.Reports',
    'Microsoft.Graph.Security',
    'Microsoft.Graph.Applications',
    'Microsoft.Graph.DeviceManagement',
    'Microsoft.Graph.Sites',
    'Microsoft.Graph.Groups'
)

# Add Maester and related modules if not skipping
if (-not $SkipMaester) {
    $requiredModules += @(
        'Maester',
        'ExchangeOnlineManagement',
        'MicrosoftTeams'
    )
}

# Check for module version conflicts and update if needed
$graphModules = $requiredModules | Where-Object { $_ -like 'Microsoft.Graph.*' }
$needsUpdate = $false

# Check if Microsoft.Graph.Authentication is installed
$authModule = Get-Module -ListAvailable -Name 'Microsoft.Graph.Authentication' | Sort-Object Version -Descending | Select-Object -First 1
if ($authModule) {
    $authVersion = $authModule.Version
    # Check if other Graph modules have mismatched versions
    foreach ($module in $graphModules) {
        $installed = Get-Module -ListAvailable -Name $module | Sort-Object Version -Descending | Select-Object -First 1
        if ($installed -and $installed.Version -ne $authVersion) {
            Write-Status "Module version mismatch detected: $module ($($installed.Version)) vs Authentication ($authVersion)" "WARNING"
            $needsUpdate = $true
            break
        }
    }
}

# Install/update modules
foreach ($module in $requiredModules) {
    $installed = Get-Module -ListAvailable -Name $module
    if (-not $installed) {
        Write-Status "Installing $module..." "INFO"
        try {
            Install-Module $module -Scope CurrentUser -Force -AllowClobber -Repository PSGallery
        }
        catch {
            Write-Status "Failed to install $module - $_" "WARNING"
        }
    }
    elseif ($needsUpdate -and $module -like 'Microsoft.Graph.*') {
        Write-Status "Updating $module to fix version mismatch..." "INFO"
        try {
            Update-Module $module -Force -ErrorAction SilentlyContinue
        }
        catch {
            # Try reinstalling if update fails
            try {
                Install-Module $module -Scope CurrentUser -Force -AllowClobber -Repository PSGallery
            }
            catch {
                Write-Status "Could not update $module - $_" "WARNING"
            }
        }
    }
}

# Import all Microsoft.Graph modules upfront to avoid version conflicts
# This ensures all modules are loaded with compatible assembly versions
Write-Status "Loading Microsoft Graph modules..."
foreach ($module in $graphModules) {
    try {
        Import-Module $module -Force -ErrorAction Stop
    }
    catch {
        Write-Status "Warning: Could not import $module - $_" "WARNING"
    }
}

Write-Status "Required modules available" "SUCCESS"

# ── Create output directory ──────────────────────────────────────────────────

$clientFolder = Join-Path $OutputPath $ClientName
if (-not (Test-Path $clientFolder)) {
    New-Item -ItemType Directory -Path $clientFolder -Force | Out-Null
}

$timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm"
$jsonFile = "m365assessment_$timestamp.json"
$jsonPath = Join-Path $clientFolder $jsonFile

# ── Connect to Microsoft Graph ───────────────────────────────────────────────

Write-Status "Connecting to Microsoft Graph..."
Write-Status "A browser window will open for authentication" "INFO"
Write-Status "Sign in with Global Reader or Global Admin credentials" "INFO"

# Define scopes - include Maester-required scopes if running Maester tests
$scopes = @(
    # Core M365 assessment scopes
    "Directory.Read.All",
    "Organization.Read.All",
    "Domain.Read.All",
    "User.Read.All",
    "UserAuthenticationMethod.Read.All",
    "AuditLog.Read.All",
    "Reports.Read.All",
    "Policy.Read.All",
    "SecurityEvents.Read.All",
    "Application.Read.All",
    "DeviceManagementConfiguration.Read.All",
    "DeviceManagementManagedDevices.Read.All",
    "DeviceManagementApps.Read.All",
    "Sites.Read.All",
    "Team.ReadBasic.All",
    "IdentityRiskyUser.Read.All",
    "Group.Read.All"
)

# Add Maester-required scopes if not skipping Maester tests
if (-not $SkipMaester) {
    $maesterScopes = @(
        "ReportSettings.Read.All",
        "SecurityIdentitiesSensors.Read.All",
        "SecurityIdentitiesHealth.Read.All",
        "SharePointTenantSettings.Read.All",
        "ThreatHunting.Read.All",
        "MailboxSettings.Read",
        "RoleEligibilitySchedule.ReadWrite.Directory",  # ReadWrite needed for PIM eligible role queries
        "RoleAssignmentSchedule.Read.Directory",
        "RoleManagement.Read.All",
        "CrossTenantInformation.ReadBasic.All",
        "Policy.Read.ConditionalAccess",
        "PrivilegedAccess.Read.AzureAD",
        "IdentityProvider.Read.All",
        "AccessReview.Read.All",
        "Agreement.Read.All",
        "EntitlementManagement.Read.All"
    )
    $scopes = $scopes + $maesterScopes
}

try {
    # Use device code flow for non-interactive terminals
    # ContextScope Process ensures token persists across cmdlet calls
    Connect-MgGraph -Scopes $scopes -UseDeviceCode -NoWelcome -ContextScope Process
    Write-Status "Connected to Microsoft Graph" "SUCCESS"

    $context = Get-MgContext
    if (-not $context) {
        Write-Status "Failed to establish Graph context after authentication" "ERROR"
        exit 1
    }
    Write-Status "Tenant: $($context.TenantId)" "INFO"
}
catch {
    Write-Status "Authentication failed: $_" "ERROR"
    exit 1
}

# ── Collect Assessment Data ──────────────────────────────────────────────────

Write-Status "Running M365 Assessment..."
Write-Status "This may take several minutes depending on tenant size" "INFO"

try {
    # Initialize assessment data structure
    $assessmentData = @{
        metadata = @{
            clientName = $ClientName
            assessmentDate = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
            tenantId = (Get-MgContext).TenantId
            tenantName = $null
            primaryDomain = $null
            createdDateTime = $null
            dataGaps = @()
        }
        licensing = @{
            subscribedSkus = @()
            totalUsers = 0
            licensedUsers = 0
            guestUsers = 0
        }
        securityScore = @{
            currentScore = 0
            maxScore = 0
            percentage = 0
            identityScore = @{}
            recommendations = @()
        }
        identity = @{
            conditionalAccess = @()
            mfaEnforcement = @{}
            authenticationMethods = @{}
            mfaStatus = @{}
            sspr = @{}
            privilegedAccess = @{}
            riskyUsers = @{}
        }
        intune = @{
            compliancePolicies = @()
            configurationProfiles = @()
            managedDevices = @{}
            appProtectionPolicies = @()
        }
        sharepoint = @{
            storageUsed = 0
            storageAllocated = 0
            siteCount = 0
        }
        teams = @{
            teamsCount = 0
        }
        applications = @{
            enterpriseApps = 0
            appRegistrations = 0
        }
        governance = @{
            adminRoles = @()
            namedLocations = @()
        }
        maester = @{
            summary = @{}
            testResults = @()
        }
        userInsights = @{
            staleAccounts = @{
                stale90Days = 0
                stale180Days = 0
                stale365Days = 0
                neverSignedIn = 0
                totalAnalysed = 0
                topStaleWithLicenses = @()
            }
            guestAnalysis = @{
                totalGuests = 0
                activeGuests = 0
                inactiveGuests = 0
                neverSignedIn = 0
                topDomains = @()
            }
            licenseWaste = @{
                inactiveUsers = 0
                licensesAffected = 0
                estimatedMonthlyGBP = 0.0
                byLicense = @()
            }
            mfaDetails = @{
                capable = 0
                registered = 0
                smsOnly = 0
                passwordless = 0
                methods = @()
            }
        }
    }

    # ── Get Organization Info ────────────────────────────────────────────────

    Write-Status "Getting organization info..."
    try {
        $org = Get-MgOrganization
        $assessmentData.metadata.tenantName = $org.DisplayName
        $assessmentData.metadata.createdDateTime = if ($org.CreatedDateTime) { $org.CreatedDateTime.ToString() } else { $null }
        Write-Status "  Organization: $($org.DisplayName)" "SUCCESS"
    }
    catch {
        Write-Status "  Could not retrieve organization info: $_" "WARNING"
        $assessmentData.metadata.dataGaps += "Organization info"
    }

    # Get domains
    try {
        $domains = Get-MgDomain
        $primaryDomain = $domains | Where-Object { $_.IsDefault -eq $true } | Select-Object -First 1
        $assessmentData.metadata.primaryDomain = $primaryDomain.Id
        Write-Status "  Primary domain: $($primaryDomain.Id)" "SUCCESS"
    }
    catch {
        Write-Status "  Could not retrieve domains: $_" "WARNING"
        $assessmentData.metadata.dataGaps += "Domains"
    }

    # ── Licensing Information ────────────────────────────────────────────────

    Write-Status "Collecting licensing information..."
    try {
        $skus = Get-MgSubscribedSku
        $assessmentData.licensing.subscribedSkus = @($skus | ForEach-Object {
            @{
                skuPartNumber = $_.SkuPartNumber
                skuId = $_.SkuId
                consumedUnits = $_.ConsumedUnits
                prepaidUnits = $_.PrepaidUnits.Enabled
                warningUnits = $_.PrepaidUnits.Warning
                suspendedUnits = $_.PrepaidUnits.Suspended
            }
        })
        $totalConsumed = ($skus | Measure-Object -Property ConsumedUnits -Sum).Sum
        Write-Status "  Found $($skus.Count) license SKUs ($totalConsumed assigned)" "SUCCESS"
    }
    catch {
        Write-Status "  Could not retrieve licenses: $_" "WARNING"
        $assessmentData.metadata.dataGaps += "Licensing"
    }

    # Get user counts
    try {
        # Total users
        $userCount = (Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/users/`$count" -Headers @{"ConsistencyLevel"="eventual"})
        $assessmentData.licensing.totalUsers = $userCount

        # Guest users
        $guestCount = (Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/users/`$count?`$filter=userType eq 'Guest'" -Headers @{"ConsistencyLevel"="eventual"})
        $assessmentData.licensing.guestUsers = $guestCount

        # Licensed users (members only)
        $licensedCount = (Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/users/`$count?`$filter=assignedLicenses/`$count ne 0 and userType eq 'Member'" -Headers @{"ConsistencyLevel"="eventual"})
        $assessmentData.licensing.licensedUsers = $licensedCount

        Write-Status "  Total users: $userCount (Licensed: $licensedCount, Guests: $guestCount)" "SUCCESS"
    }
    catch {
        Write-Status "  Could not retrieve user counts: $_" "WARNING"
        $assessmentData.metadata.dataGaps += "User counts"
    }

    # ── Security Score ───────────────────────────────────────────────────────

    Write-Status "Collecting Security Score..."
    try {
        $secureScores = Get-MgSecuritySecureScore -Top 1
        if ($secureScores) {
            $score = $secureScores | Select-Object -First 1
            $percentage = if ($score.MaxScore -gt 0) {
                [math]::Round(($score.CurrentScore / $score.MaxScore) * 100, 1)
            } else { 0 }

            $assessmentData.securityScore.currentScore = $score.CurrentScore
            $assessmentData.securityScore.maxScore = $score.MaxScore
            $assessmentData.securityScore.percentage = $percentage

            # Extract identity score if available
            $identityCategory = $score.ControlScores | Where-Object { $_.ControlCategory -eq "Identity" }
            if ($identityCategory) {
                $identityScore = ($identityCategory | Measure-Object -Property Score -Sum).Sum
                $identityMax = ($identityCategory | Measure-Object -Property MaxScore -Sum).Sum
                $assessmentData.securityScore.identityScore = @{
                    current = $identityScore
                    max = $identityMax
                    percentage = if ($identityMax -gt 0) { [math]::Round(($identityScore / $identityMax) * 100, 1) } else { 0 }
                }
            }

            Write-Status "  Security Score: $percentage% ($($score.CurrentScore)/$($score.MaxScore))" "SUCCESS"
        }
    }
    catch {
        Write-Status "  Could not retrieve security score: $_" "WARNING"
        $assessmentData.metadata.dataGaps += "Security Score"
    }

    # Get top recommendations
    try {
        $controlProfiles = Get-MgSecuritySecureScoreControlProfile -Top 20
        $assessmentData.securityScore.recommendations = @($controlProfiles |
            Where-Object { $_.ImplementationStatus -ne "implemented" } |
            Sort-Object -Property MaxScore -Descending |
            Select-Object -First 10 |
            ForEach-Object {
                @{
                    title = $_.Title
                    maxScore = $_.MaxScore
                    implementationStatus = $_.ImplementationStatus
                    userImpact = $_.UserImpact
                    threats = $_.Threats
                }
            })
        Write-Status "  Retrieved top 10 security recommendations" "SUCCESS"
    }
    catch {
        Write-Status "  Could not retrieve recommendations: $_" "WARNING"
    }

    # ── Identity Data ────────────────────────────────────────────────────────

    Write-Status "Collecting Identity data..."

    # Conditional Access Policies
    try {
        $caPolicies = Get-MgIdentityConditionalAccessPolicy -All
        $assessmentData.identity.conditionalAccess = @($caPolicies | ForEach-Object {
            @{
                id = $_.Id
                displayName = $_.DisplayName
                state = $_.State
                createdDateTime = if ($_.CreatedDateTime) { $_.CreatedDateTime.ToString() } else { $null }
                conditions = @{
                    users = $_.Conditions.Users
                    applications = $_.Conditions.Applications
                    locations = $_.Conditions.Locations
                    platforms = $_.Conditions.Platforms
                    signInRiskLevels = $_.Conditions.SignInRiskLevels
                    userRiskLevels = $_.Conditions.UserRiskLevels
                }
                grantControls = $_.GrantControls
                sessionControls = $_.SessionControls
            }
        })
        $enabledCount = ($caPolicies | Where-Object { $_.State -eq "enabled" }).Count
        Write-Status "  Found $($caPolicies.Count) CA policies ($enabledCount enabled)" "SUCCESS"

        # Analyse MFA enforcement from CA policies
        $mfaPolicies = @()
        $enabledCaPolicies = $caPolicies | Where-Object { $_.State -eq "enabled" }

        foreach ($policy in $enabledCaPolicies) {
            $requiresMfa = $false
            $grantControls = $policy.GrantControls

            # Check if policy requires MFA
            if ($grantControls.BuiltInControls -contains "mfa") {
                $requiresMfa = $true
            }
            # Also check for authentication strength that requires MFA
            if ($grantControls.AuthenticationStrength.Id) {
                $requiresMfa = $true
            }

            if ($requiresMfa) {
                # Determine user scope
                $userScope = "Unknown"
                $users = $policy.Conditions.Users

                if ($users.IncludeUsers -contains "All") {
                    if ($users.ExcludeUsers.Count -gt 0 -or $users.ExcludeGroups.Count -gt 0) {
                        $userScope = "All users (with exclusions)"
                    } else {
                        $userScope = "All users"
                    }
                } elseif ($users.IncludeGroups.Count -gt 0) {
                    $userScope = "Specific groups ($($users.IncludeGroups.Count) groups)"
                } elseif ($users.IncludeUsers.Count -gt 0) {
                    $userScope = "Specific users ($($users.IncludeUsers.Count) users)"
                } elseif ($users.IncludeRoles.Count -gt 0) {
                    $userScope = "Specific roles ($($users.IncludeRoles.Count) roles)"
                }

                # Determine app scope
                $appScope = "Unknown"
                $apps = $policy.Conditions.Applications

                if ($apps.IncludeApplications -contains "All") {
                    if ($apps.ExcludeApplications.Count -gt 0) {
                        $appScope = "All apps (with exclusions)"
                    } else {
                        $appScope = "All apps"
                    }
                } elseif ($apps.IncludeApplications.Count -gt 0) {
                    $appScope = "Specific apps ($($apps.IncludeApplications.Count) apps)"
                }

                # Check for conditions that limit when MFA applies
                $conditions = @()
                if ($policy.Conditions.Locations.IncludeLocations -and $policy.Conditions.Locations.IncludeLocations -notcontains "All") {
                    $conditions += "Location-based"
                }
                if ($policy.Conditions.Platforms.IncludePlatforms -and $policy.Conditions.Platforms.IncludePlatforms -notcontains "all") {
                    $conditions += "Platform-specific"
                }
                if ($policy.Conditions.SignInRiskLevels.Count -gt 0) {
                    $conditions += "Risk-based"
                }
                if ($policy.Conditions.UserRiskLevels.Count -gt 0) {
                    $conditions += "User risk-based"
                }

                $mfaPolicies += @{
                    policyName = $policy.DisplayName
                    userScope = $userScope
                    appScope = $appScope
                    conditions = if ($conditions.Count -gt 0) { $conditions -join ", " } else { "Always (no conditions)" }
                    includesAllUsers = ($users.IncludeUsers -contains "All")
                    includesAllApps = ($apps.IncludeApplications -contains "All")
                }
            }
        }

        # Check for Security Defaults
        $securityDefaultsEnabled = $false
        try {
            $securityDefaults = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/policies/identitySecurityDefaultsEnforcementPolicy" -OutputType PSObject
            $securityDefaultsEnabled = $securityDefaults.isEnabled
        } catch {
            # Security defaults check failed, assume not enabled
        }

        # Determine overall MFA enforcement status
        $hasUniversalMfa = ($mfaPolicies | Where-Object { $_.includesAllUsers -and $_.includesAllApps }).Count -gt 0

        $assessmentData.identity.mfaEnforcement = @{
            securityDefaultsEnabled = $securityDefaultsEnabled
            caPoliciesRequiringMfa = $mfaPolicies.Count
            policies = $mfaPolicies
            hasUniversalMfaPolicy = $hasUniversalMfa
            enforcementMethod = if ($securityDefaultsEnabled) {
                "Security Defaults"
            } elseif ($hasUniversalMfa) {
                "Conditional Access (all users)"
            } elseif ($mfaPolicies.Count -gt 0) {
                "Conditional Access (partial)"
            } else {
                "None detected"
            }
        }

        if ($securityDefaultsEnabled) {
            Write-Status "  MFA enforcement: Security Defaults enabled (all users)" "SUCCESS"
        } elseif ($hasUniversalMfa) {
            Write-Status "  MFA enforcement: CA policy covers all users" "SUCCESS"
        } elseif ($mfaPolicies.Count -gt 0) {
            Write-Status "  MFA enforcement: $($mfaPolicies.Count) CA policies require MFA (partial coverage)" "WARNING"
        } else {
            Write-Status "  MFA enforcement: No MFA-requiring policies detected" "WARNING"
        }
    }
    catch {
        Write-Status "  Could not retrieve CA policies: $_" "WARNING"
        $assessmentData.metadata.dataGaps += "Conditional Access"
    }

    # Authentication Methods Policy (SSPR)
    try {
        $authMethods = Get-MgPolicyAuthenticationMethodPolicy
        $assessmentData.identity.authenticationMethods = @{
            policyMigrationState = $authMethods.PolicyMigrationState
            registrationEnforcement = $authMethods.RegistrationEnforcement
        }

        # Check SSPR status from auth methods
        $assessmentData.identity.sspr = @{
            policyMigrationState = $authMethods.PolicyMigrationState
        }
        Write-Status "  Retrieved authentication methods policy" "SUCCESS"
    }
    catch {
        Write-Status "  Could not retrieve auth methods: $_" "WARNING"
        $assessmentData.metadata.dataGaps += "Authentication Methods"
    }

    # MFA Registration Status (using beta endpoint for auth method registration)
    try {
        # Try the newer authentication methods user registration details endpoint
        # Use pagination to get all results
        $allMfaUsers = @()
        $mfaUri = "https://graph.microsoft.com/beta/reports/authenticationMethods/userRegistrationDetails?`$top=999"

        do {
            $mfaReport = Invoke-MgGraphRequest -Method GET -Uri $mfaUri -OutputType PSObject
            if ($mfaReport.value) {
                $allMfaUsers += $mfaReport.value
            }
            $mfaUri = $mfaReport.'@odata.nextLink'
        } while ($mfaUri)

        if ($allMfaUsers.Count -gt 0) {
            $mfaRegistered = ($allMfaUsers | Where-Object { $_.isMfaRegistered -eq $true }).Count
            $mfaCapable = ($allMfaUsers | Where-Object { $_.isMfaCapable -eq $true }).Count
            $passwordless = ($allMfaUsers | Where-Object { $_.isPasswordlessCapable -eq $true }).Count

            # Count users with only SMS/phone as MFA method (weak MFA)
            $smsOnly = ($allMfaUsers | Where-Object {
                $_.methodsRegistered -and
                $_.methodsRegistered.Count -eq 1 -and
                ($_.methodsRegistered -contains "mobilePhone" -or $_.methodsRegistered -contains "alternateMobilePhone")
            }).Count

            # Count authentication methods
            $methodCounts = @{}
            foreach ($user in $allMfaUsers) {
                if ($user.methodsRegistered) {
                    foreach ($method in $user.methodsRegistered) {
                        if (-not $methodCounts.ContainsKey($method)) {
                            $methodCounts[$method] = 0
                        }
                        $methodCounts[$method]++
                    }
                }
            }

            $total = $allMfaUsers.Count
            $methodBreakdown = $methodCounts.GetEnumerator() | Sort-Object Value -Descending | ForEach-Object {
                @{
                    method = $_.Key
                    count = $_.Value
                    percentage = [math]::Round(($_.Value / $total) * 100, 1)
                }
            }

            $assessmentData.identity.mfaStatus = @{
                registered = $mfaRegistered
                total = $total
                percentage = if ($total -gt 0) { [math]::Round(($mfaRegistered / $total) * 100, 1) } else { 0 }
            }

            $assessmentData.userInsights.mfaDetails = @{
                capable = $mfaCapable
                registered = $mfaRegistered
                smsOnly = $smsOnly
                passwordless = $passwordless
                methods = @($methodBreakdown)
            }

            Write-Status "  MFA: $mfaRegistered/$total registered, $mfaCapable capable, $smsOnly SMS-only (weak)" "SUCCESS"
        }
    }
    catch {
        # Fallback: try to estimate from user count
        try {
            $assessmentData.identity.mfaStatus = @{
                registered = "N/A"
                total = $assessmentData.licensing.totalUsers
                percentage = "N/A"
                note = "Detailed MFA registration data requires Reports.Read.All scope"
            }
            Write-Status "  MFA registration details not available (requires Reports.Read.All)" "WARNING"
        }
        catch {
            Write-Status "  Could not retrieve MFA status: $_" "WARNING"
            $assessmentData.metadata.dataGaps += "MFA Status"
        }
    }

    # Privileged Access - Directory Roles
    try {
        $directoryRoles = Get-MgDirectoryRole -All
        $roleBreakdown = @()

        foreach ($role in $directoryRoles) {
            $members = Get-MgDirectoryRoleMember -DirectoryRoleId $role.Id -All
            if ($members.Count -gt 0) {
                $roleBreakdown += @{
                    roleName = $role.DisplayName
                    memberCount = $members.Count
                }
            }
        }

        $assessmentData.governance.adminRoles = $roleBreakdown
        $globalAdmins = $roleBreakdown | Where-Object { $_.roleName -eq "Global Administrator" }
        $gaCount = if ($globalAdmins) { $globalAdmins.memberCount } else { 0 }

        $assessmentData.identity.privilegedAccess = @{
            globalAdminCount = $gaCount
            directoryRolesActive = $roleBreakdown.Count
        }
        Write-Status "  Found $gaCount Global Administrators, $($roleBreakdown.Count) active roles" "SUCCESS"
    }
    catch {
        Write-Status "  Could not retrieve privileged access data: $_" "WARNING"
        $assessmentData.metadata.dataGaps += "Privileged Access"
    }

    # Risky Users
    try {
        $riskyUsers = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/identityProtection/riskyUsers?`$filter=riskState eq 'atRisk'" -OutputType PSObject
        $riskyCount = if ($riskyUsers.value) { $riskyUsers.value.Count } else { 0 }
        $assessmentData.identity.riskyUsers = @{
            atRisk = $riskyCount
        }
        if ($riskyCount -gt 0) {
            Write-Status "  Found $riskyCount risky users!" "WARNING"
        } else {
            Write-Status "  No risky users detected" "SUCCESS"
        }
    }
    catch {
        Write-Status "  Could not retrieve risky users (Identity Protection license may be required)" "WARNING"
        $assessmentData.identity.riskyUsers = @{ atRisk = 0; error = "Not available" }
    }

    # Named Locations
    try {
        $namedLocations = Get-MgIdentityConditionalAccessNamedLocation -All
        $assessmentData.governance.namedLocations = @($namedLocations | ForEach-Object {
            @{
                id = $_.Id
                displayName = $_.DisplayName
                type = $_.'@odata.type'
            }
        })
        Write-Status "  Found $($namedLocations.Count) named locations" "SUCCESS"
    }
    catch {
        Write-Status "  Could not retrieve named locations: $_" "WARNING"
    }

    # ── User Insights (Stale Accounts, Guest Analysis, License Waste) ────────

    Write-Status "Analysing user account health..."

    # Stale Accounts Detection (also collects data for license waste)
    try {
        $allMemberUsers = @()
        $usersUri = "https://graph.microsoft.com/beta/users?`$select=id,displayName,userPrincipalName,signInActivity,assignedLicenses&`$filter=userType eq 'Member'&`$top=999"

        do {
            $usersResponse = Invoke-MgGraphRequest -Method GET -Uri $usersUri -Headers @{"ConsistencyLevel"="eventual"} -OutputType PSObject
            if ($usersResponse.value) {
                $allMemberUsers += $usersResponse.value
            }
            $usersUri = $usersResponse.'@odata.nextLink'
        } while ($usersUri)

        $now = Get-Date
        $threshold90 = $now.AddDays(-90)
        $threshold180 = $now.AddDays(-180)
        $threshold365 = $now.AddDays(-365)

        $stale90 = 0
        $stale180 = 0
        $stale365 = 0
        $neverSignedIn = 0
        $staleWithLicenses = @()

        foreach ($user in $allMemberUsers) {
            $lastSignIn = $null
            if ($user.signInActivity.lastSignInDateTime) {
                $lastSignIn = [DateTime]$user.signInActivity.lastSignInDateTime
            }

            $hasLicense = ($user.assignedLicenses -and $user.assignedLicenses.Count -gt 0)

            if (-not $lastSignIn) {
                $neverSignedIn++
                if ($hasLicense) {
                    $staleWithLicenses += @{
                        displayName = $user.displayName
                        userPrincipalName = $user.userPrincipalName
                        lastSignIn = "Never"
                        licenseCount = $user.assignedLicenses.Count
                    }
                }
            }
            else {
                if ($lastSignIn -lt $threshold365) {
                    $stale365++
                    $stale180++
                    $stale90++
                }
                elseif ($lastSignIn -lt $threshold180) {
                    $stale180++
                    $stale90++
                }
                elseif ($lastSignIn -lt $threshold90) {
                    $stale90++
                }

                if ($hasLicense -and $lastSignIn -lt $threshold90) {
                    $staleWithLicenses += @{
                        displayName = $user.displayName
                        userPrincipalName = $user.userPrincipalName
                        lastSignIn = $lastSignIn.ToString("yyyy-MM-dd")
                        licenseCount = $user.assignedLicenses.Count
                    }
                }
            }
        }

        # Sort by most stale (never signed in first, then by date)
        $topStale = $staleWithLicenses | Sort-Object { if ($_.lastSignIn -eq "Never") { "0000-00-00" } else { $_.lastSignIn } } | Select-Object -First 20

        $assessmentData.userInsights.staleAccounts = @{
            stale90Days = $stale90
            stale180Days = $stale180
            stale365Days = $stale365
            neverSignedIn = $neverSignedIn
            totalAnalysed = $allMemberUsers.Count
            topStaleWithLicenses = @($topStale)
        }

        Write-Status "  Stale accounts: $stale90 (90d), $stale180 (180d), $stale365 (1yr), $neverSignedIn never" "SUCCESS"
    }
    catch {
        Write-Status "  Could not analyse stale accounts: $_" "WARNING"
        $assessmentData.metadata.dataGaps += "Stale Accounts"
    }

    # Guest User Analysis
    try {
        $allGuests = @()
        $guestsUri = "https://graph.microsoft.com/beta/users?`$select=id,displayName,userPrincipalName,mail,signInActivity&`$filter=userType eq 'Guest'&`$top=999"

        do {
            $guestsResponse = Invoke-MgGraphRequest -Method GET -Uri $guestsUri -Headers @{"ConsistencyLevel"="eventual"} -OutputType PSObject
            if ($guestsResponse.value) {
                $allGuests += $guestsResponse.value
            }
            $guestsUri = $guestsResponse.'@odata.nextLink'
        } while ($guestsUri)

        $activeGuests = 0
        $inactiveGuests = 0
        $guestNeverSignedIn = 0
        $domainCounts = @{}

        foreach ($guest in $allGuests) {
            # Extract external domain
            $domain = $null
            if ($guest.userPrincipalName -match '(.+)#EXT#@') {
                $externalPart = $matches[1]
                if ($externalPart -match '_([^_]+)$') {
                    $domain = $matches[1]
                }
            }
            elseif ($guest.mail) {
                $domain = ($guest.mail -split '@')[-1]
            }

            if ($domain) {
                if (-not $domainCounts.ContainsKey($domain)) {
                    $domainCounts[$domain] = 0
                }
                $domainCounts[$domain]++
            }

            $lastSignIn = $null
            if ($guest.signInActivity.lastSignInDateTime) {
                $lastSignIn = [DateTime]$guest.signInActivity.lastSignInDateTime
            }

            if (-not $lastSignIn) {
                $guestNeverSignedIn++
            }
            elseif ($lastSignIn -lt $threshold90) {
                $inactiveGuests++
            }
            else {
                $activeGuests++
            }
        }

        # Top 10 domains
        $topDomains = $domainCounts.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 10 | ForEach-Object {
            @{ domain = $_.Key; count = $_.Value }
        }

        $assessmentData.userInsights.guestAnalysis = @{
            totalGuests = $allGuests.Count
            activeGuests = $activeGuests
            inactiveGuests = $inactiveGuests
            neverSignedIn = $guestNeverSignedIn
            topDomains = @($topDomains)
        }

        Write-Status "  Guests: $($allGuests.Count) total, $activeGuests active, $inactiveGuests inactive, $guestNeverSignedIn never" "SUCCESS"
    }
    catch {
        Write-Status "  Could not analyse guest accounts: $_" "WARNING"
        $assessmentData.metadata.dataGaps += "Guest Analysis"
    }

    # License Waste Detection (uses stale accounts data)
    try {
        # Build SKU lookup
        $skuLookup = @{}
        foreach ($sku in $assessmentData.licensing.subscribedSkus) {
            $skuLookup[$sku.skuId] = $sku.skuPartNumber
        }

        # Approximate monthly costs (GBP)
        $skuCosts = @{
            "SPE_E3" = 30.00; "SPE_E5" = 50.00; "ENTERPRISEPACK" = 18.00; "ENTERPRISEPREMIUM" = 32.00
            "SPE_A3" = 0.00; "M365EDU_A3" = 0.00; "SPE_A5" = 0.00; "M365EDU_A5" = 0.00
            "AAD_PREMIUM_P1" = 5.00; "AAD_PREMIUM_P2" = 8.00
            "EMS_E3" = 8.00; "EMS_E5" = 14.00; "INTUNE_A" = 6.00
            "POWER_BI_PRO" = 8.00; "PROJECTPREMIUM" = 45.00; "VISIOCLIENT" = 12.00
        }

        $inactiveUsers = 0
        $licensesAffected = 0
        $monthlyWaste = 0.0
        $licenseBreakdown = @{}

        foreach ($user in $allMemberUsers) {
            if (-not $user.assignedLicenses -or $user.assignedLicenses.Count -eq 0) {
                continue
            }

            $lastSignIn = $null
            if ($user.signInActivity.lastSignInDateTime) {
                $lastSignIn = [DateTime]$user.signInActivity.lastSignInDateTime
            }

            $isInactive = (-not $lastSignIn) -or ($lastSignIn -lt $threshold90)

            if ($isInactive) {
                $inactiveUsers++

                foreach ($license in $user.assignedLicenses) {
                    $licensesAffected++
                    $skuName = $skuLookup[$license.skuId]
                    if (-not $skuName) { $skuName = "Unknown" }

                    if (-not $licenseBreakdown.ContainsKey($skuName)) {
                        $licenseBreakdown[$skuName] = 0
                    }
                    $licenseBreakdown[$skuName]++

                    if ($skuCosts.ContainsKey($skuName)) {
                        $monthlyWaste += $skuCosts[$skuName]
                    }
                    else {
                        $monthlyWaste += 15.00  # Default estimate
                    }
                }
            }
        }

        # Format breakdown
        $byLicense = $licenseBreakdown.GetEnumerator() | Sort-Object Value -Descending | ForEach-Object {
            $cost = if ($skuCosts.ContainsKey($_.Key)) { $skuCosts[$_.Key] } else { 15.00 }
            @{
                skuName = $_.Key
                count = $_.Value
                monthlyCost = [math]::Round($_.Value * $cost, 2)
            }
        }

        $assessmentData.userInsights.licenseWaste = @{
            inactiveUsers = $inactiveUsers
            licensesAffected = $licensesAffected
            estimatedMonthlyGBP = [math]::Round($monthlyWaste, 2)
            byLicense = @($byLicense)
        }

        Write-Status "  License waste: $inactiveUsers users, $licensesAffected licenses, ~GBP $([math]::Round($monthlyWaste, 2))/month" "WARNING"
    }
    catch {
        Write-Status "  Could not analyse license waste: $_" "WARNING"
        $assessmentData.metadata.dataGaps += "License Waste"
    }

    # ── Intune Data ──────────────────────────────────────────────────────────

    Write-Status "Collecting Intune data..."

    # Compliance Policies
    try {
        $compliancePolicies = Get-MgDeviceManagementDeviceCompliancePolicy -All
        $assessmentData.intune.compliancePolicies = @($compliancePolicies | ForEach-Object {
            @{
                id = $_.Id
                displayName = $_.DisplayName
                createdDateTime = if ($_.CreatedDateTime) { $_.CreatedDateTime.ToString() } else { $null }
            }
        })
        Write-Status "  Found $($compliancePolicies.Count) compliance policies" "SUCCESS"
    }
    catch {
        Write-Status "  Could not retrieve compliance policies (Intune license may be required)" "WARNING"
        $assessmentData.metadata.dataGaps += "Intune Compliance Policies"
    }

    # Configuration Profiles
    try {
        $configProfiles = Get-MgDeviceManagementDeviceConfiguration -All
        $assessmentData.intune.configurationProfiles = @($configProfiles | ForEach-Object {
            @{
                id = $_.Id
                displayName = $_.DisplayName
                type = $_.'@odata.type'
            }
        })
        Write-Status "  Found $($configProfiles.Count) configuration profiles" "SUCCESS"
    }
    catch {
        Write-Status "  Could not retrieve configuration profiles" "WARNING"
    }

    # Managed Devices Summary
    try {
        $devices = Get-MgDeviceManagementManagedDevice -All
        $compliantCount = ($devices | Where-Object { $_.ComplianceState -eq "compliant" }).Count
        $nonCompliantCount = ($devices | Where-Object { $_.ComplianceState -eq "noncompliant" }).Count

        $assessmentData.intune.managedDevices = @{
            total = $devices.Count
            compliant = $compliantCount
            nonCompliant = $nonCompliantCount
            complianceRate = if ($devices.Count -gt 0) { [math]::Round(($compliantCount / $devices.Count) * 100, 1) } else { 0 }
        }
        Write-Status "  Found $($devices.Count) managed devices ($compliantCount compliant)" "SUCCESS"
    }
    catch {
        Write-Status "  Could not retrieve managed devices" "WARNING"
        $assessmentData.intune.managedDevices = @{ total = 0; compliant = 0; nonCompliant = 0 }
    }

    # App Protection Policies
    try {
        $appProtectionPolicies = Get-MgDeviceAppManagementManagedAppPolicy -All
        $assessmentData.intune.appProtectionPolicies = @($appProtectionPolicies | ForEach-Object {
            @{
                id = $_.Id
                displayName = $_.DisplayName
            }
        })
        Write-Status "  Found $($appProtectionPolicies.Count) app protection policies" "SUCCESS"
    }
    catch {
        Write-Status "  Could not retrieve app protection policies" "WARNING"
    }

    # ── SharePoint Data ──────────────────────────────────────────────────────

    Write-Status "Collecting SharePoint data..."
    try {
        # Get SharePoint site usage detail report - this gives accurate site count AND storage
        # Use cross-platform temp directory (macOS doesn't have $env:TEMP)
        $tempDir = if ($env:TEMP) { $env:TEMP } elseif ($env:TMPDIR) { $env:TMPDIR } else { "/tmp" }
        $tempCsvPath = Join-Path $tempDir "sp_usage_$(Get-Random).csv"
        try {
            # Use getSharePointSiteUsageDetail for accurate site count (not Get-MgSite which only returns accessible sites)
            Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/reports/getSharePointSiteUsageDetail(period='D7')" -OutputFilePath $tempCsvPath

            if (Test-Path $tempCsvPath) {
                $csvData = Import-Csv $tempCsvPath
                if ($csvData) {
                    # Count all sites from the report
                    $assessmentData.sharepoint.siteCount = $csvData.Count

                    # Sum total storage used across all sites
                    $totalStorageBytes = ($csvData | ForEach-Object {
                        [long]($_.'Storage Used (Byte)' -replace '[^\d]', '')
                    } | Measure-Object -Sum).Sum
                    $assessmentData.sharepoint.storageUsed = $totalStorageBytes

                    # Sum allocated storage
                    $totalAllocatedBytes = ($csvData | ForEach-Object {
                        [long]($_.'Storage Allocated (Byte)' -replace '[^\d]', '')
                    } | Measure-Object -Sum).Sum
                    $assessmentData.sharepoint.storageAllocated = $totalAllocatedBytes
                }
                Remove-Item $tempCsvPath -Force -ErrorAction SilentlyContinue
            }
        }
        catch {
            Write-Status "  Could not retrieve SharePoint usage report: $_" "WARNING"
            Remove-Item $tempCsvPath -Force -ErrorAction SilentlyContinue
        }

        $storageGB = if ($assessmentData.sharepoint.storageUsed -gt 0) {
            [math]::Round($assessmentData.sharepoint.storageUsed / 1GB, 2)
        } else { 0 }
        Write-Status "  SharePoint: $($assessmentData.sharepoint.siteCount) sites, ${storageGB}GB used" "SUCCESS"
    }
    catch {
        Write-Status "  Could not retrieve SharePoint data: $_" "WARNING"
        $assessmentData.metadata.dataGaps += "SharePoint"
    }

    # ── Teams Data ───────────────────────────────────────────────────────────

    Write-Status "Collecting Teams data..."
    try {
        # Count Teams-enabled groups
        $teamsCount = (Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/groups/`$count?`$filter=resourceProvisioningOptions/Any(x:x eq 'Team')" -Headers @{"ConsistencyLevel"="eventual"})
        $assessmentData.teams.teamsCount = $teamsCount
        Write-Status "  Found $teamsCount Teams" "SUCCESS"
    }
    catch {
        Write-Status "  Could not retrieve Teams count: $_" "WARNING"
        $assessmentData.metadata.dataGaps += "Teams"
    }

    # ── Applications Data ────────────────────────────────────────────────────

    Write-Status "Collecting Applications data..."
    try {
        # Enterprise Apps (Service Principals)
        $spCount = (Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/`$count" -Headers @{"ConsistencyLevel"="eventual"})
        $assessmentData.applications.enterpriseApps = $spCount

        # App Registrations
        $appCount = (Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/applications/`$count" -Headers @{"ConsistencyLevel"="eventual"})
        $assessmentData.applications.appRegistrations = $appCount

        Write-Status "  Enterprise Apps: $spCount, App Registrations: $appCount" "SUCCESS"
    }
    catch {
        Write-Status "  Could not retrieve applications data: $_" "WARNING"
        $assessmentData.metadata.dataGaps += "Applications"
    }

    # ── Save JSON output ─────────────────────────────────────────────────────

    Write-Status "Saving assessment data..."
    $assessmentData | ConvertTo-Json -Depth 15 | Out-File -FilePath $jsonPath -Encoding UTF8
    Write-Status "JSON saved: $jsonFile" "SUCCESS"

    # ── Run Maester Security Tests ───────────────────────────────────────────

    $maesterHtmlFile = $null
    $maesterJsonFile = $null
    $maesterMdFile = $null
    $exchangeConnected = $false
    $teamsConnected = $false

    if (-not $SkipMaester) {
        Write-Status "Running Maester security tests..."
        Write-Status "This may take several minutes..." "INFO"

        # ── Connect to Microsoft Teams FIRST (to avoid assembly conflicts) ────
        # Teams module must be loaded before ExchangeOnlineManagement due to MSAL version conflicts
        Write-Status "Connecting to Microsoft Teams..."
        Write-Status "A second authentication prompt will appear" "INFO"
        try {
            Import-Module MicrosoftTeams -ErrorAction Stop
            # Use -UseDeviceAuthentication for non-interactive auth
            Connect-MicrosoftTeams -UseDeviceAuthentication -ErrorAction Stop
            Write-Status "Connected to Microsoft Teams" "SUCCESS"
            $teamsConnected = $true
        }
        catch {
            Write-Status "Could not connect to Microsoft Teams: $_" "WARNING"
            Write-Status "Teams-related Maester tests will be skipped" "INFO"
        }

        # ── Connect to Exchange Online (for Exchange-related Maester tests) ────
        Write-Status "Connecting to Exchange Online..."
        Write-Status "A third authentication prompt will appear" "INFO"
        try {
            Import-Module ExchangeOnlineManagement -ErrorAction Stop
            # Use device code flow, read-only mode (no write permissions)
            Connect-ExchangeOnline -Device -ShowBanner:$false -ErrorAction Stop
            Write-Status "Connected to Exchange Online" "SUCCESS"
            $exchangeConnected = $true
        }
        catch {
            Write-Status "Could not connect to Exchange Online: $_" "WARNING"
            Write-Status "Exchange-related Maester tests will be skipped" "INFO"
        }

        # ── Connect to Security & Compliance (for compliance-related Maester tests) ────
        Write-Status "Connecting to Security & Compliance Center..."
        Write-Status "A browser window will open for authentication" "INFO"
        try {
            # Connect-IPPSSession is part of ExchangeOnlineManagement module
            # No device code option - uses interactive browser auth
            Connect-IPPSSession -ShowBanner:$false -ErrorAction Stop
            Write-Status "Connected to Security & Compliance" "SUCCESS"
        }
        catch {
            Write-Status "Could not connect to Security & Compliance: $_" "WARNING"
            Write-Status "Security & Compliance Maester tests will be skipped" "INFO"
        }

        try {
            Import-Module Maester -ErrorAction Stop

            # Use shared Maester tests folder (not per-client)
            $maesterTestsFolder = Join-Path $OutputPath "MaesterTests"
            $versionFile = Join-Path $maesterTestsFolder ".maester-version"

            if (-not (Test-Path $maesterTestsFolder)) {
                New-Item -ItemType Directory -Path $maesterTestsFolder -Force | Out-Null
            }

            # Check if tests need to be installed/updated
            $needsInstall = $false
            $testAge = $null

            if (-not (Test-Path $versionFile)) {
                $needsInstall = $true
                Write-Status "No cached Maester tests found" "INFO"
            }
            elseif ($UpdateMaesterTests) {
                $needsInstall = $true
                Write-Status "Forced update of Maester tests requested" "INFO"
            }
            else {
                # Check age of tests
                $versionInfo = Get-Content $versionFile -Raw | ConvertFrom-Json
                $lastUpdate = [DateTime]$versionInfo.lastUpdate
                $testAge = (Get-Date) - $lastUpdate

                if ($testAge.Days -gt 30) {
                    $needsInstall = $true
                    Write-Status "Cached Maester tests are $($testAge.Days) days old (>30 days)" "WARNING"
                }
                else {
                    Write-Status "Using cached Maester tests (age: $($testAge.Days) days)" "INFO"
                }
            }

            # Install/update tests if needed
            if ($needsInstall) {
                Write-Status "Installing Maester test files..."

                # Clear existing test files
                if (Test-Path $maesterTestsFolder) {
                    Get-ChildItem -Path $maesterTestsFolder -Filter "*.ps1" -Recurse | Remove-Item -Force -ErrorAction SilentlyContinue
                    Get-ChildItem -Path $maesterTestsFolder -Directory | Where-Object { $_.Name -notin @('test-results') } | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
                }

                Install-MaesterTests -Path $maesterTestsFolder -ErrorAction Stop

                # Create version file
                $versionInfo = @{
                    lastUpdate = (Get-Date).ToString("o")
                    maesterVersion = (Get-Module Maester).Version.ToString()
                }
                $versionInfo | ConvertTo-Json | Out-File -FilePath $versionFile -Encoding UTF8
                Write-Status "Maester tests cached successfully" "SUCCESS"
            }

            # Create client-specific output folder
            $maesterOutputFolder = Join-Path $clientFolder "MaesterTests"
            if (-not (Test-Path $maesterOutputFolder)) {
                New-Item -ItemType Directory -Path $maesterOutputFolder -Force | Out-Null
            }

            # Run Maester tests - use cached tests but output to client folder
            # Use -SkipGraphConnect since we already have a valid Graph connection with required scopes
            Write-Status "Executing security tests..."
            $maesterResults = Invoke-Maester -Path $maesterTestsFolder -OutputFolder $maesterOutputFolder -OutputFolderFileName "MaesterReport" -NonInteractive -PassThru -SkipGraphConnect -ErrorAction Stop

            # Parse results
            $passed = ($maesterResults | Where-Object { $_.Result -eq 'Passed' }).Count
            $failed = ($maesterResults | Where-Object { $_.Result -eq 'Failed' }).Count
            $skipped = ($maesterResults | Where-Object { $_.Result -eq 'Skipped' }).Count
            $total = $maesterResults.Count

            $assessmentData.maester.summary = @{
                passed = $passed
                failed = $failed
                skipped = $skipped
                total = $total
                passRate = if (($total - $skipped) -gt 0) { [math]::Round($passed / ($total - $skipped) * 100, 1) } else { 0 }
            }

            # Store failed tests for AI analysis (limit to 30)
            $assessmentData.maester.testResults = @($maesterResults |
                Where-Object { $_.Result -eq 'Failed' } |
                Select-Object -First 30 |
                ForEach-Object {
                    @{
                        name = $_.Name
                        result = $_.Result
                        block = $_.Block
                        errorMessage = if ($_.ErrorRecord) { $_.ErrorRecord.ToString() } else { $null }
                    }
                })

            # Update JSON with Maester data
            $assessmentData | ConvertTo-Json -Depth 15 | Out-File -FilePath $jsonPath -Encoding UTF8

            # Find generated files (MaesterReport.html, MaesterReport.json, MaesterReport.md)
            $htmlReport = Get-ChildItem -Path $maesterOutputFolder -Filter "MaesterReport.html" -ErrorAction SilentlyContinue | Select-Object -First 1
            if (-not $htmlReport) {
                $htmlReport = Get-ChildItem -Path $maesterOutputFolder -Filter "*.html" -ErrorAction SilentlyContinue | Select-Object -First 1
            }
            if ($htmlReport) {
                $maesterHtmlFile = "$ClientName/MaesterTests/$($htmlReport.Name)"
            }

            $jsonReport = Get-ChildItem -Path $maesterOutputFolder -Filter "MaesterReport.json" -ErrorAction SilentlyContinue | Select-Object -First 1
            if (-not $jsonReport) {
                $jsonReport = Get-ChildItem -Path $maesterOutputFolder -Filter "*.json" -ErrorAction SilentlyContinue | Select-Object -First 1
            }
            if ($jsonReport) {
                $maesterJsonFile = "$ClientName/MaesterTests/$($jsonReport.Name)"
            }

            # Find the markdown report for AI analysis
            $mdReport = Get-ChildItem -Path $maesterOutputFolder -Filter "MaesterReport.md" -ErrorAction SilentlyContinue | Select-Object -First 1
            if (-not $mdReport) {
                $mdReport = Get-ChildItem -Path $maesterOutputFolder -Filter "*.md" -ErrorAction SilentlyContinue | Select-Object -First 1
            }
            $maesterMdFile = $null
            if ($mdReport) {
                $maesterMdFile = "$ClientName/MaesterTests/$($mdReport.Name)"
            }

            Write-Status "Maester: $passed passed, $failed failed, $skipped skipped ($(
                $assessmentData.maester.summary.passRate
            )% pass rate)" "SUCCESS"
        }
        catch {
            Write-Status "Maester tests failed: $_" "WARNING"
            Write-Status "The AI summary will still be generated from Graph API data" "INFO"
            $assessmentData.maester.summary = @{ error = $_.ToString() }
        }
    }
    else {
        Write-Status "Maester tests skipped (use without -SkipMaester to include)" "INFO"
    }

    # ── Output file paths for the web app ────────────────────────────────────

    Write-Host ""
    Write-Host "=== OUTPUT_FILES ==="
    Write-Host "JSON:$ClientName/$jsonFile"
    if ($maesterHtmlFile) {
        Write-Host "MAESTERHTML:$maesterHtmlFile"
    }
    if ($maesterJsonFile) {
        Write-Host "MAESTERJSON:$maesterJsonFile"
    }
    if ($maesterMdFile) {
        Write-Host "MAESTERMD:$maesterMdFile"
    }
    Write-Host "=== END_OUTPUT_FILES ==="

    Write-Status "M365 Assessment complete" "SUCCESS"

}
catch {
    Write-Status "Assessment failed: $_" "ERROR"
    Write-Status $_.ScriptStackTrace "ERROR"
    exit 1
}
finally {
    # Disconnect from all services
    Write-Status "Disconnecting from services..."
    try {
        Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
    }
    catch {}
    try {
        Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
    }
    catch {}
    try {
        Disconnect-MicrosoftTeams -ErrorAction SilentlyContinue | Out-Null
    }
    catch {}
}
