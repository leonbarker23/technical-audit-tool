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

    [switch]$SkipMaester
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
        $mfaReport = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/reports/authenticationMethods/userRegistrationDetails" -OutputType PSObject
        if ($mfaReport.value) {
            $mfaRegistered = ($mfaReport.value | Where-Object { $_.isMfaRegistered -eq $true }).Count
            $total = $mfaReport.value.Count
            $assessmentData.identity.mfaStatus = @{
                registered = $mfaRegistered
                total = $total
                percentage = if ($total -gt 0) { [math]::Round(($mfaRegistered / $total) * 100, 1) } else { 0 }
            }
            Write-Status "  MFA registration: $mfaRegistered/$total users" "SUCCESS"
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
        # Get SharePoint usage report - save to temp file then parse
        # Use cross-platform temp directory (macOS doesn't have $env:TEMP)
        $tempDir = if ($env:TEMP) { $env:TEMP } elseif ($env:TMPDIR) { $env:TMPDIR } else { "/tmp" }
        $tempCsvPath = Join-Path $tempDir "sp_usage_$(Get-Random).csv"
        try {
            Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/reports/getSharePointSiteUsageStorage(period='D7')" -OutputFilePath $tempCsvPath

            if (Test-Path $tempCsvPath) {
                $csvData = Import-Csv $tempCsvPath
                if ($csvData) {
                    # Get the most recent entry (last row)
                    $latestData = $csvData | Select-Object -Last 1
                    $storageBytes = [long]($latestData.'Storage Used (Byte)' -replace '[^\d]', '')
                    $assessmentData.sharepoint.storageUsed = $storageBytes
                }
                Remove-Item $tempCsvPath -Force -ErrorAction SilentlyContinue
            }
        }
        catch {
            Write-Status "  Could not retrieve SharePoint storage report" "WARNING"
            Remove-Item $tempCsvPath -Force -ErrorAction SilentlyContinue
        }

        # Get site count
        $sites = Get-MgSite -All -Property Id
        $assessmentData.sharepoint.siteCount = $sites.Count

        $storageGB = if ($assessmentData.sharepoint.storageUsed -gt 0) {
            [math]::Round($assessmentData.sharepoint.storageUsed / 1GB, 2)
        } else { 0 }
        Write-Status "  SharePoint: $($sites.Count) sites, ${storageGB}GB used" "SUCCESS"
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
    $assessmentData | ConvertTo-Json -Depth 15 -Compress | Out-File -FilePath $jsonPath -Encoding UTF8
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

            # Create Maester output folder
            $maesterFolder = Join-Path $clientFolder "MaesterTests"
            if (-not (Test-Path $maesterFolder)) {
                New-Item -ItemType Directory -Path $maesterFolder -Force | Out-Null
            }

            # Install Maester tests - clear folder first to avoid "not empty" warning
            Write-Status "Installing Maester test files..."
            if (Test-Path $maesterFolder) {
                # Remove existing test files but keep any reports
                Get-ChildItem -Path $maesterFolder -Filter "*.ps1" -Recurse | Remove-Item -Force -ErrorAction SilentlyContinue
                Get-ChildItem -Path $maesterFolder -Directory | Where-Object { $_.Name -notin @('test-results') } | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
            }
            Install-MaesterTests -Path $maesterFolder -ErrorAction Stop

            # Run Maester tests - use OutputFolder to generate all formats (HTML, JSON, MD)
            # Use -SkipGraphConnect since we already have a valid Graph connection with required scopes
            Write-Status "Executing security tests..."
            $maesterResults = Invoke-Maester -Path $maesterFolder -OutputFolder $maesterFolder -OutputFolderFileName "MaesterReport" -NonInteractive -PassThru -SkipGraphConnect -ErrorAction Stop

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
            $assessmentData | ConvertTo-Json -Depth 15 -Compress | Out-File -FilePath $jsonPath -Encoding UTF8

            # Find generated files (MaesterReport.html, MaesterReport.json, MaesterReport.md)
            $htmlReport = Get-ChildItem -Path $maesterFolder -Filter "MaesterReport.html" -ErrorAction SilentlyContinue | Select-Object -First 1
            if (-not $htmlReport) {
                $htmlReport = Get-ChildItem -Path $maesterFolder -Filter "*.html" -ErrorAction SilentlyContinue | Select-Object -First 1
            }
            if ($htmlReport) {
                $maesterHtmlFile = "$ClientName/MaesterTests/$($htmlReport.Name)"
            }

            $jsonReport = Get-ChildItem -Path $maesterFolder -Filter "MaesterReport.json" -ErrorAction SilentlyContinue | Select-Object -First 1
            if (-not $jsonReport) {
                $jsonReport = Get-ChildItem -Path $maesterFolder -Filter "*.json" -ErrorAction SilentlyContinue | Select-Object -First 1
            }
            if ($jsonReport) {
                $maesterJsonFile = "$ClientName/MaesterTests/$($jsonReport.Name)"
            }

            # Find the markdown report for AI analysis
            $mdReport = Get-ChildItem -Path $maesterFolder -Filter "MaesterReport.md" -ErrorAction SilentlyContinue | Select-Object -First 1
            if (-not $mdReport) {
                $mdReport = Get-ChildItem -Path $maesterFolder -Filter "*.md" -ErrorAction SilentlyContinue | Select-Object -First 1
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
