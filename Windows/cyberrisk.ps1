<#
.SYNOPSIS
    Cyber Risk Scorecard data collection script for BTR (Business & Technology Review).

.DESCRIPTION
    Collects comprehensive security configuration data from Microsoft 365 tenant
    and calculates a Cyber Risk Score (0-100%) based on:
    - MFA & Authentication (20%)
    - License Security Tier (15%)
    - Microsoft Secure Score (15%)
    - Conditional Access (15%)
    - Privileged Access (10%)
    - Device Compliance (10%)
    - Data Protection / Purview (10%)
    - External Sharing (5%)

    SECURITY WARNING: This script requires high-privilege read access including:
    - RoleManagement.Read.All (reads who controls the tenant)
    - PrivilegedAccess.Read.AzureAD (reads PIM configuration)
    - AuditLog.Read.All (reads sign-in and audit logs)

    Only run this with interactive user authentication (device code flow).
    If using an App Registration, carefully review the security implications
    of granting these permissions to a service principal.

.PARAMETER OutputPath
    Directory to save the assessment results.

.PARAMETER ClientName
    Client name for folder organisation.

.PARAMETER SkipDefenderVulnerabilities
    Skip Defender vulnerability scan (faster assessment).

.PARAMETER SkipSharePointAdmin
    Skip SharePoint admin connection (if no SPO admin access).

.PARAMETER ConfigPath
    Path to scoring configuration JSON file. Defaults to cyberrisk_config.json in script directory.

.NOTES
    Requires: PowerShell 7+, Microsoft.Graph modules, ExchangeOnlineManagement, Microsoft.Online.SharePoint.PowerShell

    Required modules should be pre-installed. Run the following to install:
    Install-Module Microsoft.Graph -Scope CurrentUser
    Install-Module ExchangeOnlineManagement -Scope CurrentUser
    Install-Module Microsoft.Online.SharePoint.PowerShell -Scope CurrentUser
#>

param(
    [Parameter(Mandatory=$true)]
    [string]$OutputPath,

    [Parameter(Mandatory=$true)]
    [string]$ClientName,

    [switch]$SkipDefenderVulnerabilities,

    [switch]$SkipSharePointAdmin,

    [string]$ConfigPath
)

$ErrorActionPreference = "Stop"

# ══════════════════════════════════════════════════════════════════════════════
# HELPER FUNCTIONS
# ══════════════════════════════════════════════════════════════════════════════

function Write-Status {
    param([string]$Message, [string]$Type = "INFO")
    $prefix = switch ($Type) {
        "INFO"    { "[*]" }
        "SUCCESS" { "[+]" }
        "WARNING" { "[!]" }
        "ERROR"   { "[!]" }
        "SCORE"   { "[S]" }
        default   { "[*]" }
    }
    Write-Host "$prefix $Message"
}

function Get-ThresholdScore {
    <#
    .SYNOPSIS
        Get score based on threshold table (highest matching threshold wins)
    #>
    param(
        [double]$Value,
        [hashtable]$Thresholds
    )
    $sortedKeys = $Thresholds.Keys | ForEach-Object { [int]$_ } | Sort-Object -Descending
    foreach ($threshold in $sortedKeys) {
        if ($Value -ge $threshold) {
            return $Thresholds["$threshold"]
        }
    }
    return 0
}

function Test-ValidClientName {
    param([string]$Name)
    # Allow alphanumeric, spaces, hyphens, underscores only
    return $Name -match '^[A-Za-z0-9 _-]+$'
}

function Get-SharePointAdminUrl {
    <#
    .SYNOPSIS
        Get SharePoint admin URL from tenant information
    #>
    try {
        $org = Get-MgOrganization
        $onmicrosoftDomain = $org.VerifiedDomains | Where-Object {
            $_.Name -like "*.onmicrosoft.com" -and $_.Name -notlike "*.mail.onmicrosoft.com"
        } | Select-Object -First 1

        if ($onmicrosoftDomain) {
            $tenantName = $onmicrosoftDomain.Name -replace '\.onmicrosoft\.com$', ''
            return "https://$tenantName-admin.sharepoint.com"
        }
        return $null
    }
    catch {
        return $null
    }
}

function ConvertTo-CaseInsensitiveHashtable {
    <#
    .SYNOPSIS
        Convert a hashtable to case-insensitive for key lookups
    #>
    param([hashtable]$Hashtable)
    $result = @{}
    foreach ($key in $Hashtable.Keys) {
        $result[$key.ToLower()] = $Hashtable[$key]
    }
    return $result
}

# ══════════════════════════════════════════════════════════════════════════════
# LOAD CONFIGURATION
# ══════════════════════════════════════════════════════════════════════════════

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $ConfigPath) {
    $ConfigPath = Join-Path $scriptDir "cyberrisk_config.json"
}

if (-not (Test-Path $ConfigPath)) {
    Write-Status "Configuration file not found: $ConfigPath" "ERROR"
    Write-Status "Please ensure cyberrisk_config.json exists in the script directory" "ERROR"
    exit 1
}

try {
    $configContent = Get-Content $ConfigPath -Raw -Encoding UTF8
    $config = $configContent | ConvertFrom-Json -AsHashtable
    Write-Status "Loaded configuration v$($config.version) from $ConfigPath" "SUCCESS"
}
catch {
    Write-Status "Failed to parse configuration file: $_" "ERROR"
    exit 1
}

# Extract configuration sections
$ScoringThresholds = $config.scoringThresholds
$LicenseScoring = $config.licenseScoring
$CapabilitySkus = $config.capabilitySkus
$FreeLicensePatterns = $config.freeLicensePatterns
$GuestInviteMapping = ConvertTo-CaseInsensitiveHashtable $config.guestInviteRestrictionMapping
$SharePointSharingMapping = $config.sharepointSharingMapping

# ══════════════════════════════════════════════════════════════════════════════
# INPUT VALIDATION
# ══════════════════════════════════════════════════════════════════════════════

Write-Status "Validating input parameters..."

# Validate ClientName
if (-not (Test-ValidClientName -Name $ClientName)) {
    Write-Status "Invalid client name. Use only letters, numbers, spaces, hyphens, and underscores." "ERROR"
    exit 1
}

# Validate OutputPath exists and is writable
if (-not (Test-Path $OutputPath)) {
    Write-Status "Output path does not exist: $OutputPath" "ERROR"
    exit 1
}

$testFile = $null
try {
    $testFile = Join-Path $OutputPath ".writetest_$(Get-Random)"
    [System.IO.File]::WriteAllText($testFile, "test")
}
catch {
    Write-Status "Output path is not writable: $OutputPath" "ERROR"
    exit 1
}
finally {
    if ($testFile -and (Test-Path $testFile)) {
        try { Remove-Item $testFile -Force -ErrorAction SilentlyContinue } catch {}
    }
}

Write-Status "Input validation passed" "SUCCESS"

# ══════════════════════════════════════════════════════════════════════════════
# CHECK PREREQUISITES
# ══════════════════════════════════════════════════════════════════════════════

Write-Status "Checking prerequisites..."

# Check PowerShell version
if ($PSVersionTable.PSVersion.Major -lt 7) {
    Write-Status "PowerShell 7+ required. Current version: $($PSVersionTable.PSVersion)" "ERROR"
    exit 1
}

# Define required modules
$requiredModules = @(
    'Microsoft.Graph.Authentication',
    'Microsoft.Graph.Users',
    'Microsoft.Graph.Identity.SignIns',
    'Microsoft.Graph.Identity.DirectoryManagement',
    'Microsoft.Graph.Reports',
    'Microsoft.Graph.Security',
    'Microsoft.Graph.Applications',
    'Microsoft.Graph.DeviceManagement',
    'Microsoft.Graph.Groups',
    'ExchangeOnlineManagement'
)

if (-not $SkipSharePointAdmin) {
    $requiredModules += 'Microsoft.Online.SharePoint.PowerShell'
}

# Check and auto-install missing modules
foreach ($module in $requiredModules) {
    $installed = Get-Module -ListAvailable -Name $module
    if (-not $installed) {
        Write-Status "Installing missing module: $module" "INFO"
        try {
            Install-Module $module -Scope CurrentUser -Force -AllowClobber -Repository PSGallery
            Write-Status "  Installed $module" "SUCCESS"
        }
        catch {
            Write-Status "Failed to install $module - $_" "ERROR"
            Write-Status "Please install manually: Install-Module $module -Scope CurrentUser" "INFO"
            exit 1
        }
    }
}

# Import Graph modules (all at once to avoid version conflicts)
$graphModules = $requiredModules | Where-Object { $_ -like 'Microsoft.Graph.*' }
Write-Status "Loading Microsoft Graph modules..."

foreach ($module in $graphModules) {
    try {
        Import-Module $module -ErrorAction Stop
    }
    catch {
        Write-Status "Failed to import $module - $_" "ERROR"
        exit 1
    }
}

Write-Status "Required modules loaded" "SUCCESS"

# ══════════════════════════════════════════════════════════════════════════════
# CREATE OUTPUT DIRECTORY
# ══════════════════════════════════════════════════════════════════════════════

$clientFolder = Join-Path $OutputPath $ClientName
if (-not (Test-Path $clientFolder)) {
    New-Item -ItemType Directory -Path $clientFolder -Force | Out-Null
}

$timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm"
$jsonFile = "cyberrisk_$timestamp.json"
$jsonPath = Join-Path $clientFolder $jsonFile

# ══════════════════════════════════════════════════════════════════════════════
# CONNECT TO MICROSOFT GRAPH
# ══════════════════════════════════════════════════════════════════════════════

Write-Status "Connecting to Microsoft Graph..."
Write-Status "A browser window will open for authentication" "INFO"
Write-Status "Sign in with Global Reader or Global Admin credentials" "INFO"

# Define scopes for cyber risk assessment
# Using validated scopes from m365assessment.ps1
$graphScopes = @(
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
    "Group.Read.All",
    "RoleEligibilitySchedule.Read.Directory",
    "RoleAssignmentSchedule.Read.Directory",
    "RoleManagement.Read.All",
    "PrivilegedAccess.Read.AzureAD"
)

try {
    Connect-MgGraph -Scopes $graphScopes -UseDeviceCode -NoWelcome -ContextScope Process
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

# ══════════════════════════════════════════════════════════════════════════════
# INITIALIZE ASSESSMENT DATA STRUCTURE
# ══════════════════════════════════════════════════════════════════════════════

# Track connection states for cleanup
$connectionState = @{
    Graph = $true
    Ipps = $false
    Spo = $false
}

# Initialize assessment data with dataCollected flags
$assessmentData = @{
    metadata = @{
        clientName = $ClientName
        assessmentDate = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        tenantId = (Get-MgContext).TenantId
        tenantName = $null
        primaryDomain = $null
        assessmentVersion = "1.0"
        configVersion = $config.version
    }
    scores = @{
        overall = 0
        grade = "At Risk"
        breakdown = @{
            mfaAuthentication = @{ score = 0; maxScore = 20; percentage = 0; dataCollected = $false }
            licenseTier = @{ score = 0; maxScore = 15; percentage = 0; dataCollected = $false }
            secureScore = @{ score = 0; maxScore = 15; percentage = 0; dataCollected = $false }
            conditionalAccess = @{ score = 0; maxScore = 15; percentage = 0; dataCollected = $false }
            privilegedAccess = @{ score = 0; maxScore = 10; percentage = 0; dataCollected = $false }
            deviceCompliance = @{ score = 0; maxScore = 10; percentage = 0; dataCollected = $false }
            dataProtection = @{ score = 0; maxScore = 10; percentage = 0; dataCollected = $false }
            externalSharing = @{ score = 0; maxScore = 5; percentage = 0; dataCollected = $false }
        }
    }
    mfaAuthentication = @{
        registrationPercentage = 0
        registeredUsers = 0
        totalUsers = 0
        mfaCapableUsers = 0
        enforcementMethod = "None detected"
        passwordlessUsers = 0
        smsOnlyUsers = 0
        securityDefaultsEnabled = $false
    }
    licenseTier = @{
        primaryLicense = "Unknown"
        primaryLicenseSku = "Unknown"
        hasDefenderP1 = $false
        hasDefenderP2 = $false
        hasIntuneP1 = $false
        hasEntraP1 = $false
        hasEntraP2 = $false
        hasPurview = $false
        allLicenses = @()
    }
    secureScore = @{
        currentScore = 0
        maxScore = 0
        percentage = 0
        topRecommendations = @()
    }
    conditionalAccess = @{
        totalPolicies = 0
        enabledPolicies = 0
        mfaPolicies = 0
        hasAllUserMfa = $false
        hasRiskBasedSignIn = $false
        hasRiskBasedUser = $false
        hasDeviceCompliance = $false
        policies = @()
    }
    privilegedAccess = @{
        globalAdminCount = 0
        totalPrivilegedUsers = 0
        pimEnabled = $false
        pimConfiguredRoles = 0
        staleAdmins = 0
        cloudOnlyAdmins = $true
        adminsMfaEnforced = $false
    }
    deviceCompliance = @{
        totalDevices = 0
        managedDevices = 0
        enrollmentPercentage = 0
        compliantDevices = 0
        compliancePercentage = 0
        defenderDeployed = $false
        vulnerableDevices = 0
        vulnerabilityPercentage = 0
        compliancePolicies = 0
    }
    dataProtection = @{
        dlpPolicies = @{
            total = 0
            enabled = 0
            testMode = 0
            workloads = @()
        }
        sensitivityLabels = @{
            total = 0
            enabled = 0
            published = 0
            autoLabeling = $false
        }
        retentionPolicies = 0
    }
    externalSharing = @{
        sharepointSharingCapability = "Unknown"
        sharepointSharingCapabilityValue = -1
        guestInviteRestriction = "Unknown"
        totalGuests = 0
        activeGuests = 0
        inactiveGuests = 0
    }
    recommendations = @()
    dataGaps = @()
}

# ══════════════════════════════════════════════════════════════════════════════
# DATA COLLECTION
# ══════════════════════════════════════════════════════════════════════════════

Write-Status "Running Cyber Risk Assessment..."
Write-Status "This may take several minutes depending on tenant size" "INFO"

try {
    # ── Get Organization Info ────────────────────────────────────────────────

    Write-Status "Getting organization info..."
    try {
        $org = Get-MgOrganization
        $assessmentData.metadata.tenantName = $org.DisplayName
        Write-Status "  Organization: $($org.DisplayName)" "SUCCESS"
    }
    catch {
        Write-Status "  Could not retrieve organization info: $_" "WARNING"
        $assessmentData.dataGaps += "Organization info"
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
        $assessmentData.dataGaps += "Domains"
    }

    # ── 1. MFA & Authentication Data ─────────────────────────────────────────
    # OPTIMIZED: Process in batches without storing all user objects

    Write-Status "Collecting MFA & Authentication data..."

    try {
        # Initialize counters for streaming aggregation
        $mfaRegistered = 0
        $mfaCapable = 0
        $totalUsers = 0
        $passwordless = 0
        $smsOnly = 0

        $mfaUri = 'https://graph.microsoft.com/beta/reports/authenticationMethods/userRegistrationDetails?$top=999'
        $pageCount = 0

        do {
            $mfaReport = Invoke-MgGraphRequest -Method GET -Uri $mfaUri -OutputType PSObject

            if ($mfaReport.value) {
                $batch = $mfaReport.value
                $totalUsers += $batch.Count

                # Process counts for this batch only - don't store the objects
                $mfaRegistered += ($batch | Where-Object { $_.isMfaRegistered -eq $true }).Count
                $mfaCapable += ($batch | Where-Object { $_.isMfaCapable -eq $true }).Count
                $passwordless += ($batch | Where-Object { $_.isPasswordlessCapable -eq $true }).Count

                # Count users with only SMS/phone as MFA method (weak MFA)
                $smsOnly += ($batch | Where-Object {
                    $_.methodsRegistered -and
                    $_.methodsRegistered.Count -eq 1 -and
                    ($_.methodsRegistered -contains "mobilePhone" -or $_.methodsRegistered -contains "alternateMobilePhone")
                }).Count

                # Clear batch reference to help GC
                $batch = $null
            }

            $mfaUri = $mfaReport.'@odata.nextLink'
            $pageCount++

            if ($pageCount % 10 -eq 0) {
                Write-Status "  Retrieved $totalUsers user records..." "INFO"
            }
        } while ($mfaUri)

        if ($totalUsers -gt 0) {
            $assessmentData.mfaAuthentication.registeredUsers = $mfaRegistered
            $assessmentData.mfaAuthentication.totalUsers = $totalUsers
            $assessmentData.mfaAuthentication.mfaCapableUsers = $mfaCapable
            $assessmentData.mfaAuthentication.registrationPercentage = [math]::Round(($mfaRegistered / $totalUsers) * 100, 1)
            $assessmentData.mfaAuthentication.passwordlessUsers = $passwordless
            $assessmentData.mfaAuthentication.smsOnlyUsers = $smsOnly
            $assessmentData.scores.breakdown.mfaAuthentication.dataCollected = $true

            Write-Status "  MFA registered: $mfaRegistered/$totalUsers ($($assessmentData.mfaAuthentication.registrationPercentage)%)" "SUCCESS"
            Write-Status "  MFA capable: $mfaCapable, Passwordless: $passwordless, SMS-only (weak): $smsOnly" "INFO"
        }
    }
    catch {
        Write-Status "  Could not retrieve MFA registration data: $_" "WARNING"
        $assessmentData.dataGaps += "MFA registration"
    }

    # Check Security Defaults
    try {
        $securityDefaults = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/policies/identitySecurityDefaultsEnforcementPolicy" -OutputType PSObject
        $assessmentData.mfaAuthentication.securityDefaultsEnabled = $securityDefaults.isEnabled
        if ($securityDefaults.isEnabled) {
            $assessmentData.mfaAuthentication.enforcementMethod = "Security Defaults"
            Write-Status "  Security Defaults: Enabled" "SUCCESS"
        }
    }
    catch {
        Write-Status "  Could not check Security Defaults: $_" "WARNING"
    }

    # ── 2. Licensing Information ─────────────────────────────────────────────

    Write-Status "Collecting licensing information..."

    try {
        $skus = Get-MgSubscribedSku

        # Filter to paid licenses only
        $paidSkus = $skus | Where-Object {
            $skuName = $_.SkuPartNumber
            -not ($FreeLicensePatterns | Where-Object { $skuName -like "*$_*" })
        }

        $assessmentData.licenseTier.allLicenses = @($paidSkus | ForEach-Object {
            @{
                skuPartNumber = $_.SkuPartNumber
                consumedUnits = $_.ConsumedUnits
                prepaidUnits = $_.PrepaidUnits.Enabled
            }
        })

        # Find primary license (highest scoring with consumed units)
        $highestScore = 0
        $primaryLicense = "Unknown"
        $primarySku = "Unknown"

        foreach ($sku in $paidSkus) {
            $skuName = $sku.SkuPartNumber
            if ($LicenseScoring.ContainsKey($skuName) -and $sku.ConsumedUnits -gt 0) {
                $scoreInfo = $LicenseScoring[$skuName]
                if (-not $scoreInfo.addon -and $scoreInfo.score -gt $highestScore) {
                    $highestScore = $scoreInfo.score
                    $primaryLicense = $scoreInfo.name
                    $primarySku = $skuName
                }
            }
        }

        $assessmentData.licenseTier.primaryLicense = $primaryLicense
        $assessmentData.licenseTier.primaryLicenseSku = $primarySku

        # Check for security add-ons using capability SKU lists from config
        $allSkuNames = $paidSkus | ForEach-Object { $_.SkuPartNumber }

        $assessmentData.licenseTier.hasDefenderP1 = ($allSkuNames | Where-Object { $_ -in $CapabilitySkus.defenderP1 }).Count -gt 0
        $assessmentData.licenseTier.hasDefenderP2 = ($allSkuNames | Where-Object { $_ -in $CapabilitySkus.defenderP2 }).Count -gt 0
        $assessmentData.licenseTier.hasIntuneP1 = ($allSkuNames | Where-Object { $_ -in $CapabilitySkus.intune }).Count -gt 0
        $assessmentData.licenseTier.hasEntraP1 = ($allSkuNames | Where-Object { $_ -in $CapabilitySkus.entraP1 }).Count -gt 0
        $assessmentData.licenseTier.hasEntraP2 = ($allSkuNames | Where-Object { $_ -in $CapabilitySkus.entraP2 }).Count -gt 0
        $assessmentData.licenseTier.hasPurview = ($allSkuNames | Where-Object { $_ -in $CapabilitySkus.purview }).Count -gt 0
        $assessmentData.scores.breakdown.licenseTier.dataCollected = $true

        Write-Status "  Primary license: $primaryLicense ($primarySku)" "SUCCESS"
        Write-Status "  Defender P1: $($assessmentData.licenseTier.hasDefenderP1), P2: $($assessmentData.licenseTier.hasDefenderP2)" "INFO"
        Write-Status "  Entra P1: $($assessmentData.licenseTier.hasEntraP1), P2: $($assessmentData.licenseTier.hasEntraP2)" "INFO"
    }
    catch {
        Write-Status "  Could not retrieve licenses: $_" "WARNING"
        $assessmentData.dataGaps += "Licensing"
    }

    # ── 3. Microsoft Secure Score ────────────────────────────────────────────

    Write-Status "Collecting Security Score..."
    try {
        $secureScores = Get-MgSecuritySecureScore -Top 1
        if ($secureScores) {
            $score = $secureScores | Select-Object -First 1
            $percentage = if ($score.MaxScore -gt 0) {
                [math]::Round(($score.CurrentScore / $score.MaxScore) * 100, 1)
            } else { 0 }

            $assessmentData.secureScore.currentScore = $score.CurrentScore
            $assessmentData.secureScore.maxScore = $score.MaxScore
            $assessmentData.secureScore.percentage = $percentage
            $assessmentData.scores.breakdown.secureScore.dataCollected = $true

            Write-Status "  Security Score: $percentage% ($($score.CurrentScore)/$($score.MaxScore))" "SUCCESS"
        }
    }
    catch {
        Write-Status "  Could not retrieve security score: $_" "WARNING"
        $assessmentData.dataGaps += "Security Score"
    }

    # Get top recommendations
    try {
        $controlProfiles = Get-MgSecuritySecureScoreControlProfile -Top 20
        $assessmentData.secureScore.topRecommendations = @($controlProfiles |
            Where-Object { $_.ImplementationStatus -ne "implemented" } |
            Sort-Object -Property MaxScore -Descending |
            Select-Object -First 5 |
            ForEach-Object {
                @{
                    title = $_.Title
                    maxScore = $_.MaxScore
                    implementationStatus = $_.ImplementationStatus
                }
            })
    }
    catch {
        Write-Status "  Could not retrieve recommendations: $_" "WARNING"
    }

    # ── 4. Conditional Access ────────────────────────────────────────────────

    Write-Status "Collecting Conditional Access data..."

    try {
        $caPolicies = Get-MgIdentityConditionalAccessPolicy -All
        $enabledPolicies = $caPolicies | Where-Object { $_.State -eq "enabled" }

        $assessmentData.conditionalAccess.totalPolicies = $caPolicies.Count
        $assessmentData.conditionalAccess.enabledPolicies = $enabledPolicies.Count

        # Analyse policies for MFA, risk-based, device compliance
        $mfaPolicyCount = 0
        $hasAllUserMfa = $false
        $hasRiskBasedSignIn = $false
        $hasRiskBasedUser = $false
        $hasDeviceCompliance = $false

        foreach ($policy in $enabledPolicies) {
            $grantControls = $policy.GrantControls
            $conditions = $policy.Conditions

            # Check for MFA requirement
            $requiresMfa = $grantControls.BuiltInControls -contains "mfa" -or $grantControls.AuthenticationStrength.Id

            if ($requiresMfa) {
                $mfaPolicyCount++

                # Check if covers all users and all apps
                $allUsers = $conditions.Users.IncludeUsers -contains "All"
                $allApps = $conditions.Applications.IncludeApplications -contains "All"

                if ($allUsers -and $allApps) {
                    $hasAllUserMfa = $true
                }
            }

            # Check for risk-based policies
            if ($conditions.SignInRiskLevels.Count -gt 0) {
                $hasRiskBasedSignIn = $true
            }
            if ($conditions.UserRiskLevels.Count -gt 0) {
                $hasRiskBasedUser = $true
            }

            # Check for device compliance requirement
            if ($grantControls.BuiltInControls -contains "compliantDevice" -or
                $grantControls.BuiltInControls -contains "domainJoinedDevice") {
                $hasDeviceCompliance = $true
            }
        }

        $assessmentData.conditionalAccess.mfaPolicies = $mfaPolicyCount
        $assessmentData.conditionalAccess.hasAllUserMfa = $hasAllUserMfa
        $assessmentData.conditionalAccess.hasRiskBasedSignIn = $hasRiskBasedSignIn
        $assessmentData.conditionalAccess.hasRiskBasedUser = $hasRiskBasedUser
        $assessmentData.conditionalAccess.hasDeviceCompliance = $hasDeviceCompliance
        $assessmentData.scores.breakdown.conditionalAccess.dataCollected = $true

        # Update MFA enforcement method based on CA analysis
        if (-not $assessmentData.mfaAuthentication.securityDefaultsEnabled) {
            if ($hasAllUserMfa) {
                $assessmentData.mfaAuthentication.enforcementMethod = "Conditional Access (all users)"
            }
            elseif ($mfaPolicyCount -gt 0) {
                $assessmentData.mfaAuthentication.enforcementMethod = "Conditional Access (partial)"
            }
        }

        # Store policy summaries
        $assessmentData.conditionalAccess.policies = @($enabledPolicies | Select-Object -First 20 | ForEach-Object {
            @{
                displayName = $_.DisplayName
                state = $_.State
            }
        })

        Write-Status "  CA Policies: $($enabledPolicies.Count) enabled, $mfaPolicyCount require MFA" "SUCCESS"
        Write-Status "  Risk-based: Sign-in=$hasRiskBasedSignIn, User=$hasRiskBasedUser" "INFO"
    }
    catch {
        Write-Status "  Could not retrieve CA policies: $_" "WARNING"
        $assessmentData.dataGaps += "Conditional Access"
    }

    # ── 5. Privileged Access ─────────────────────────────────────────────────

    Write-Status "Collecting Privileged Access data..."

    try {
        $directoryRoles = Get-MgDirectoryRole -All
        $globalAdminRole = $directoryRoles | Where-Object { $_.DisplayName -eq "Global Administrator" }

        $globalAdminCount = 0
        $totalPrivileged = 0

        if ($globalAdminRole) {
            $globalAdmins = Get-MgDirectoryRoleMember -DirectoryRoleId $globalAdminRole.Id -All
            $globalAdminCount = $globalAdmins.Count
        }

        # Count all privileged users across key roles
        $privilegedRoles = @("Global Administrator", "Security Administrator", "Exchange Administrator",
                            "SharePoint Administrator", "User Administrator", "Privileged Role Administrator")

        foreach ($role in $directoryRoles) {
            if ($role.DisplayName -in $privilegedRoles) {
                $members = Get-MgDirectoryRoleMember -DirectoryRoleId $role.Id -All
                $totalPrivileged += $members.Count
            }
        }

        $assessmentData.privilegedAccess.globalAdminCount = $globalAdminCount
        $assessmentData.privilegedAccess.totalPrivilegedUsers = $totalPrivileged
        $assessmentData.scores.breakdown.privilegedAccess.dataCollected = $true

        Write-Status "  Global Admins: $globalAdminCount, Total privileged: $totalPrivileged" "SUCCESS"
    }
    catch {
        Write-Status "  Could not retrieve privileged access data: $_" "WARNING"
        $assessmentData.dataGaps += "Privileged Access"
    }

    # Check PIM status (if P2 licensed)
    if ($assessmentData.licenseTier.hasEntraP2) {
        try {
            $pimUri = 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilitySchedules?$top=10'
            $pimRoles = Invoke-MgGraphRequest -Method GET -Uri $pimUri -OutputType PSObject
            if ($pimRoles.value -and $pimRoles.value.Count -gt 0) {
                $assessmentData.privilegedAccess.pimEnabled = $true
                $assessmentData.privilegedAccess.pimConfiguredRoles = $pimRoles.value.Count
                Write-Status "  PIM: Enabled with $($pimRoles.value.Count) eligible role assignments" "SUCCESS"
            }
            else {
                Write-Status "  PIM: Available but not configured" "WARNING"
            }
        }
        catch {
            Write-Status "  Could not check PIM status: $_" "WARNING"
        }
    }
    else {
        Write-Status "  PIM: Not available (requires Entra P2)" "INFO"
    }

    # ── 6. Device Compliance ─────────────────────────────────────────────────

    Write-Status "Collecting Device Compliance data..."

    try {
        $devices = Get-MgDeviceManagementManagedDevice -All
        $compliantCount = ($devices | Where-Object { $_.ComplianceState -eq "compliant" }).Count
        $nonCompliantCount = ($devices | Where-Object { $_.ComplianceState -eq "noncompliant" }).Count

        $assessmentData.deviceCompliance.managedDevices = $devices.Count
        $assessmentData.deviceCompliance.compliantDevices = $compliantCount
        $assessmentData.deviceCompliance.compliancePercentage = if ($devices.Count -gt 0) {
            [math]::Round(($compliantCount / $devices.Count) * 100, 1)
        } else { 0 }

        # Get compliance policies count
        $compliancePolicies = Get-MgDeviceManagementDeviceCompliancePolicy -All
        $assessmentData.deviceCompliance.compliancePolicies = $compliancePolicies.Count
        $assessmentData.scores.breakdown.deviceCompliance.dataCollected = $true

        Write-Status "  Managed devices: $($devices.Count), Compliant: $compliantCount ($($assessmentData.deviceCompliance.compliancePercentage)%)" "SUCCESS"
    }
    catch {
        Write-Status "  Could not retrieve device compliance (Intune license may be required): $_" "WARNING"
        $assessmentData.dataGaps += "Device Compliance"
    }

    # Get total device count for enrollment percentage
    try {
        $allDevicesUri = 'https://graph.microsoft.com/v1.0/devices/$count'
        $allDevices = Invoke-MgGraphRequest -Method GET -Uri $allDevicesUri -Headers @{"ConsistencyLevel"="eventual"}
        $assessmentData.deviceCompliance.totalDevices = [int]$allDevices
        if ($allDevices -gt 0) {
            $assessmentData.deviceCompliance.enrollmentPercentage = [math]::Round(($assessmentData.deviceCompliance.managedDevices / $allDevices) * 100, 1)
        }
        Write-Status "  Total devices: $allDevices, Enrollment: $($assessmentData.deviceCompliance.enrollmentPercentage)%" "INFO"
    }
    catch {
        Write-Status "  Could not retrieve total device count: $_" "WARNING"
    }

    # Check Defender deployment
    if ($assessmentData.licenseTier.hasDefenderP1 -or $assessmentData.licenseTier.hasDefenderP2) {
        $assessmentData.deviceCompliance.defenderDeployed = $true
        Write-Status "  Defender for Endpoint: Licensed" "SUCCESS"
    }

    # ── 7. Data Protection / Purview ─────────────────────────────────────────

    Write-Status "Collecting Data Protection data..."
    Write-Status "Connecting to Security & Compliance Center..." "INFO"

    try {
        Import-Module ExchangeOnlineManagement -ErrorAction Stop
        # Connect-IPPSSession uses interactive browser auth (no device code option available)
        Connect-IPPSSession -ShowBanner:$false -ErrorAction Stop
        $connectionState.Ipps = $true
        Write-Status "Connected to Security & Compliance" "SUCCESS"
    }
    catch {
        Write-Status "Could not connect to Security & Compliance: $_" "WARNING"
        Write-Status "DLP and sensitivity label data will not be collected" "INFO"
        $assessmentData.dataGaps += "Security & Compliance connection"
    }

    if ($connectionState.Ipps) {
        # DLP Policies
        try {
            $dlpPolicies = Get-DlpCompliancePolicy -ErrorAction Stop
            $enabledDlp = $dlpPolicies | Where-Object { $_.Enabled -eq $true }
            $testModeDlp = $dlpPolicies | Where-Object { $_.Mode -eq "TestWithNotifications" -or $_.Mode -eq "TestWithoutNotifications" }

            $assessmentData.dataProtection.dlpPolicies.total = $dlpPolicies.Count
            $assessmentData.dataProtection.dlpPolicies.enabled = $enabledDlp.Count
            $assessmentData.dataProtection.dlpPolicies.testMode = $testModeDlp.Count

            # Get workloads covered
            $workloads = @()
            foreach ($policy in $enabledDlp) {
                if ($policy.ExchangeLocation) { $workloads += "Exchange" }
                if ($policy.SharePointLocation) { $workloads += "SharePoint" }
                if ($policy.OneDriveLocation) { $workloads += "OneDrive" }
                if ($policy.TeamsLocation) { $workloads += "Teams" }
            }
            $assessmentData.dataProtection.dlpPolicies.workloads = @($workloads | Select-Object -Unique)
            $assessmentData.scores.breakdown.dataProtection.dataCollected = $true

            Write-Status "  DLP Policies: $($enabledDlp.Count) enabled, $($testModeDlp.Count) in test mode" "SUCCESS"
        }
        catch {
            Write-Status "  Could not retrieve DLP policies: $_" "WARNING"
            $assessmentData.dataGaps += "DLP Policies"
        }

        # Sensitivity Labels
        try {
            $labels = Get-Label -ErrorAction Stop
            $enabledLabels = $labels | Where-Object { $_.Disabled -eq $false }

            $assessmentData.dataProtection.sensitivityLabels.total = $labels.Count
            $assessmentData.dataProtection.sensitivityLabels.enabled = $enabledLabels.Count

            # Check for published labels
            try {
                $labelPolicies = Get-LabelPolicy -ErrorAction Stop
                $publishedLabels = ($labelPolicies | Where-Object { $_.Enabled -eq $true }).Count
                $assessmentData.dataProtection.sensitivityLabels.published = $publishedLabels
            }
            catch {
                Write-Status "  Could not retrieve label policies: $_" "WARNING"
            }

            # Check for auto-labeling
            $autoLabelPolicies = $labels | Where-Object { $_.ApplyContentMarkingFooterEnabled -or $_.ApplyContentMarkingHeaderEnabled }
            $assessmentData.dataProtection.sensitivityLabels.autoLabeling = $autoLabelPolicies.Count -gt 0

            Write-Status "  Sensitivity Labels: $($enabledLabels.Count) enabled, $($assessmentData.dataProtection.sensitivityLabels.published) published" "SUCCESS"
        }
        catch {
            Write-Status "  Could not retrieve sensitivity labels: $_" "WARNING"
            $assessmentData.dataGaps += "Sensitivity Labels"
        }

        # Retention Policies
        try {
            $retentionPolicies = Get-RetentionCompliancePolicy -ErrorAction Stop
            $assessmentData.dataProtection.retentionPolicies = ($retentionPolicies | Where-Object { $_.Enabled -eq $true }).Count
            Write-Status "  Retention Policies: $($assessmentData.dataProtection.retentionPolicies) enabled" "SUCCESS"
        }
        catch {
            Write-Status "  Could not retrieve retention policies: $_" "WARNING"
        }
    }

    # ── 8. External Sharing ──────────────────────────────────────────────────

    Write-Status "Collecting External Sharing data..."

    # Guest users
    try {
        $guestCountUri = 'https://graph.microsoft.com/v1.0/users/$count?$filter=userType eq ''Guest'''
        $guestCount = (Invoke-MgGraphRequest -Method GET -Uri $guestCountUri -Headers @{"ConsistencyLevel"="eventual"})
        $assessmentData.externalSharing.totalGuests = [int]$guestCount
        Write-Status "  Total guest users: $guestCount" "SUCCESS"
    }
    catch {
        Write-Status "  Could not retrieve guest count: $_" "WARNING"
        $assessmentData.dataGaps += "Guest count"
    }

    # Guest invitation settings
    try {
        $authPolicy = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/policies/authorizationPolicy" -OutputType PSObject
        $assessmentData.externalSharing.guestInviteRestriction = $authPolicy.allowInvitesFrom
        $assessmentData.scores.breakdown.externalSharing.dataCollected = $true
        Write-Status "  Guest invite restriction: $($authPolicy.allowInvitesFrom)" "SUCCESS"
    }
    catch {
        Write-Status "  Could not retrieve guest invitation settings: $_" "WARNING"
        $assessmentData.dataGaps += "Guest invitation settings"
    }

    # SharePoint sharing settings
    if (-not $SkipSharePointAdmin) {
        Write-Status "Connecting to SharePoint Online..."
        Write-Status "A browser window will open for SharePoint authentication" "INFO"
        try {
            Import-Module Microsoft.Online.SharePoint.PowerShell -ErrorAction Stop

            # Get admin URL properly
            $spoAdminUrl = Get-SharePointAdminUrl

            if (-not $spoAdminUrl) {
                throw "Could not determine SharePoint admin URL"
            }

            Write-Status "  SharePoint Admin URL: $spoAdminUrl" "INFO"
            # Note: Connect-SPOService uses browser-based auth (no device code option)
            Connect-SPOService -Url $spoAdminUrl -ErrorAction Stop
            $connectionState.Spo = $true
            Write-Status "Connected to SharePoint Online" "SUCCESS"

            $spoTenant = Get-SPOTenant
            $sharingCapability = $spoTenant.SharingCapability.ToString()
            $assessmentData.externalSharing.sharepointSharingCapability = $sharingCapability

            # Map sharing capability to score value using config
            if ($SharePointSharingMapping.ContainsKey($sharingCapability)) {
                $assessmentData.externalSharing.sharepointSharingCapabilityValue = $SharePointSharingMapping[$sharingCapability]
            }

            Write-Status "  SharePoint sharing: $sharingCapability" "SUCCESS"
        }
        catch {
            Write-Status "  Could not connect to SharePoint Online: $_" "WARNING"
            Write-Status "  SharePoint sharing settings will not be scored" "INFO"
            $assessmentData.dataGaps += "SharePoint sharing settings"
        }
    }
    else {
        Write-Status "  SharePoint admin connection skipped" "INFO"
        $assessmentData.dataGaps += "SharePoint sharing settings (skipped)"
    }

    # ══════════════════════════════════════════════════════════════════════════
    # CALCULATE SCORES
    # ══════════════════════════════════════════════════════════════════════════

    Write-Status "Calculating Cyber Risk Score..."

    # 1. MFA & Authentication Score (20 points max)
    $mfaScore = 0

    # Registration (8 points)
    $mfaScore += Get-ThresholdScore -Value $assessmentData.mfaAuthentication.registrationPercentage -Thresholds $ScoringThresholds.mfaRegistration

    # Enforcement (8 points)
    $enforcement = $assessmentData.mfaAuthentication.enforcementMethod
    if ($ScoringThresholds.mfaEnforcement.ContainsKey($enforcement)) {
        $mfaScore += $ScoringThresholds.mfaEnforcement[$enforcement]
    }

    # Authentication strength (4 points)
    $totalUsers = $assessmentData.mfaAuthentication.totalUsers
    if ($totalUsers -gt 0) {
        $passwordlessPct = ($assessmentData.mfaAuthentication.passwordlessUsers / $totalUsers) * 100
        $smsOnlyPct = ($assessmentData.mfaAuthentication.smsOnlyUsers / $totalUsers) * 100

        $passwordlessPoints = Get-ThresholdScore -Value $passwordlessPct -Thresholds $ScoringThresholds.passwordless
        if ($passwordlessPoints -gt 0) {
            $mfaScore += $passwordlessPoints
        }
        elseif ($smsOnlyPct -lt $ScoringThresholds.smsOnlyThreshold) {
            $mfaScore += 1
        }
    }

    $assessmentData.scores.breakdown.mfaAuthentication.score = $mfaScore
    $assessmentData.scores.breakdown.mfaAuthentication.percentage = [math]::Round(($mfaScore / 20) * 100, 0)

    # 2. License Tier Score (15 points max)
    $licenseScore = 0
    $primarySku = $assessmentData.licenseTier.primaryLicenseSku

    if ($LicenseScoring.ContainsKey($primarySku)) {
        $licenseScore = [math]::Min($LicenseScoring[$primarySku].score, 15)
    }

    # Add bonus for security add-ons (up to 15 total)
    if ($assessmentData.licenseTier.hasDefenderP2 -and $licenseScore -lt 15) {
        $licenseScore = [math]::Min($licenseScore + 3, 15)
    }
    elseif ($assessmentData.licenseTier.hasDefenderP1 -and $licenseScore -lt 13) {
        $licenseScore = [math]::Min($licenseScore + 2, 13)
    }

    $assessmentData.scores.breakdown.licenseTier.score = $licenseScore
    $assessmentData.scores.breakdown.licenseTier.percentage = [math]::Round(($licenseScore / 15) * 100, 0)

    # 3. Secure Score (15 points max)
    $secureScorePoints = Get-ThresholdScore -Value $assessmentData.secureScore.percentage -Thresholds $ScoringThresholds.secureScore

    $assessmentData.scores.breakdown.secureScore.score = $secureScorePoints
    $assessmentData.scores.breakdown.secureScore.percentage = [math]::Round(($secureScorePoints / 15) * 100, 0)

    # 4. Conditional Access Score (15 points max)
    $caScore = 0

    # Policy count (6 points)
    $caScore += Get-ThresholdScore -Value $assessmentData.conditionalAccess.enabledPolicies -Thresholds $ScoringThresholds.caPolicyCount

    # MFA enforcement via CA (4 points)
    if ($assessmentData.conditionalAccess.hasAllUserMfa) { $caScore += 4 }
    elseif ($assessmentData.conditionalAccess.mfaPolicies -gt 0) { $caScore += 2 }

    # Risk-based policies (3 points)
    if ($assessmentData.conditionalAccess.hasRiskBasedSignIn -and $assessmentData.conditionalAccess.hasRiskBasedUser) {
        $caScore += 3
    }
    elseif ($assessmentData.conditionalAccess.hasRiskBasedSignIn) { $caScore += 2 }
    elseif ($assessmentData.conditionalAccess.hasRiskBasedUser) { $caScore += 1 }

    # Device compliance (2 points)
    if ($assessmentData.conditionalAccess.hasDeviceCompliance) { $caScore += 2 }

    $assessmentData.scores.breakdown.conditionalAccess.score = $caScore
    $assessmentData.scores.breakdown.conditionalAccess.percentage = [math]::Round(($caScore / 15) * 100, 0)

    # 5. Privileged Access Score (10 points max)
    $privScore = 0

    # Global Admin count (4 points)
    $gaCount = $assessmentData.privilegedAccess.globalAdminCount
    $gaConfig = $ScoringThresholds.globalAdminCount

    if ($gaCount -ge $gaConfig.optimal[0] -and $gaCount -le $gaConfig.optimal[1]) {
        $privScore += 4
    }
    elseif ($gaCount -ge $gaConfig.acceptable[0] -and $gaCount -le $gaConfig.acceptable[1]) {
        $privScore += 3
    }
    elseif ($gaCount -eq $gaConfig.single) {
        $privScore += 2
    }
    elseif ($gaCount -ge $gaConfig.high[0] -and $gaCount -le $gaConfig.high[1]) {
        $privScore += 1
    }
    # >10 = 0 points

    # PIM usage (3 points)
    if ($assessmentData.privilegedAccess.pimEnabled) {
        $privScore += 3
    }
    elseif ($assessmentData.licenseTier.hasEntraP2) {
        $privScore += 1  # Available but not configured
    }

    # Admin hygiene (3 points) - simplified
    if ($assessmentData.conditionalAccess.hasAllUserMfa) {
        $privScore += 2  # Assume admins are covered by MFA
    }
    $privScore += 1  # Assume cloud-only for now

    $assessmentData.scores.breakdown.privilegedAccess.score = [math]::Min($privScore, 10)
    $assessmentData.scores.breakdown.privilegedAccess.percentage = [math]::Round(([math]::Min($privScore, 10) / 10) * 100, 0)

    # 6. Device Compliance Score (10 points max)
    $deviceScore = 0

    # Enrollment (4 points)
    $deviceScore += Get-ThresholdScore -Value $assessmentData.deviceCompliance.enrollmentPercentage -Thresholds $ScoringThresholds.deviceEnrollment

    # Compliance rate (3 points)
    $deviceScore += Get-ThresholdScore -Value $assessmentData.deviceCompliance.compliancePercentage -Thresholds $ScoringThresholds.deviceCompliance

    # Defender deployment (3 points)
    if ($assessmentData.deviceCompliance.defenderDeployed) {
        $deviceScore += 3
    }

    $assessmentData.scores.breakdown.deviceCompliance.score = $deviceScore
    $assessmentData.scores.breakdown.deviceCompliance.percentage = [math]::Round(($deviceScore / 10) * 100, 0)

    # 7. Data Protection Score (10 points max)
    $dataScore = 0

    # DLP policies (4 points)
    $dlpEnabled = $assessmentData.dataProtection.dlpPolicies.enabled
    if ($dlpEnabled -ge 3) { $dataScore += 4 }
    elseif ($dlpEnabled -ge 1) { $dataScore += 3 }
    elseif ($assessmentData.dataProtection.dlpPolicies.testMode -gt 0) { $dataScore += 1 }

    # Sensitivity labels (4 points)
    $labelsPublished = $assessmentData.dataProtection.sensitivityLabels.published
    if ($labelsPublished -gt 0 -and $assessmentData.dataProtection.sensitivityLabels.autoLabeling) {
        $dataScore += 4
    }
    elseif ($labelsPublished -gt 0) { $dataScore += 3 }
    elseif ($assessmentData.dataProtection.sensitivityLabels.enabled -gt 0) { $dataScore += 1 }

    # Retention policies (2 points)
    if ($assessmentData.dataProtection.retentionPolicies -gt 0) { $dataScore += 2 }

    $assessmentData.scores.breakdown.dataProtection.score = $dataScore
    $assessmentData.scores.breakdown.dataProtection.percentage = [math]::Round(($dataScore / 10) * 100, 0)

    # 8. External Sharing Score (5 points max)
    $extScore = 0

    # SharePoint sharing (3 points)
    $sharingValue = $assessmentData.externalSharing.sharepointSharingCapabilityValue
    if ($sharingValue -ge 0) {
        $extScore += $sharingValue
    }
    else {
        $extScore += 1  # Unknown, give partial credit
    }

    # Guest invitation restrictions (2 points) - case-insensitive lookup
    $guestRestriction = $assessmentData.externalSharing.guestInviteRestriction
    if ($guestRestriction -and $GuestInviteMapping.ContainsKey($guestRestriction.ToLower())) {
        $extScore += $GuestInviteMapping[$guestRestriction.ToLower()]
    }

    $assessmentData.scores.breakdown.externalSharing.score = $extScore
    $assessmentData.scores.breakdown.externalSharing.percentage = [math]::Round(($extScore / 5) * 100, 0)

    # Calculate Overall Score
    $overallScore = $mfaScore + $licenseScore + $secureScorePoints + $caScore +
                    [math]::Min($privScore, 10) + $deviceScore + $dataScore + $extScore

    $assessmentData.scores.overall = $overallScore

    # Determine grade using thresholds from config
    $grades = $ScoringThresholds.grades
    if ($overallScore -ge $grades.Excellent) { $assessmentData.scores.grade = "Excellent" }
    elseif ($overallScore -ge $grades.Good) { $assessmentData.scores.grade = "Good" }
    elseif ($overallScore -ge $grades.NeedsImprovement) { $assessmentData.scores.grade = "Needs Improvement" }
    else { $assessmentData.scores.grade = "At Risk" }

    Write-Status "" "INFO"
    Write-Status "========================================" "SCORE"
    Write-Status "CYBER RISK SCORE: $overallScore% - $($assessmentData.scores.grade)" "SCORE"
    Write-Status "========================================" "SCORE"
    Write-Status "  MFA & Authentication:  $mfaScore/20" "SCORE"
    Write-Status "  License Security Tier: $licenseScore/15" "SCORE"
    Write-Status "  Microsoft Secure Score: $secureScorePoints/15" "SCORE"
    Write-Status "  Conditional Access:    $caScore/15" "SCORE"
    Write-Status "  Privileged Access:     $([math]::Min($privScore, 10))/10" "SCORE"
    Write-Status "  Device Compliance:     $deviceScore/10" "SCORE"
    Write-Status "  Data Protection:       $dataScore/10" "SCORE"
    Write-Status "  External Sharing:      $extScore/5" "SCORE"
    Write-Status "========================================" "SCORE"

    # ══════════════════════════════════════════════════════════════════════════
    # GENERATE RECOMMENDATIONS
    # ══════════════════════════════════════════════════════════════════════════

    $recommendations = @()

    # MFA recommendations
    if ($assessmentData.mfaAuthentication.registrationPercentage -lt 100) {
        $currentMfaPoints = Get-ThresholdScore -Value $assessmentData.mfaAuthentication.registrationPercentage -Thresholds $ScoringThresholds.mfaRegistration
        $potentialGain = [math]::Max(0, 8 - $currentMfaPoints)
        $recommendations += @{
            priority = "High"
            category = "MFA & Authentication"
            finding = "MFA registration at $($assessmentData.mfaAuthentication.registrationPercentage)%"
            recommendation = "Ensure all users register for MFA"
            impact = "+$potentialGain points"
        }
    }

    if ($assessmentData.mfaAuthentication.enforcementMethod -eq "None detected") {
        $recommendations += @{
            priority = "Critical"
            category = "MFA & Authentication"
            finding = "No MFA enforcement detected"
            recommendation = "Enable Security Defaults or configure Conditional Access to require MFA"
            impact = "+8 points"
        }
    }

    # License recommendations
    if ($licenseScore -lt 10) {
        $recommendations += @{
            priority = "High"
            category = "License Security Tier"
            finding = "Current license ($($assessmentData.licenseTier.primaryLicense)) lacks advanced security"
            recommendation = "Consider upgrading to Microsoft 365 Business Premium or E3/E5"
            impact = "+$([math]::Max(0, 12 - $licenseScore)) points"
        }
    }

    # Secure Score recommendations
    if ($assessmentData.secureScore.percentage -lt 60) {
        $recommendations += @{
            priority = "Medium"
            category = "Microsoft Secure Score"
            finding = "Secure Score at $($assessmentData.secureScore.percentage)%"
            recommendation = "Review and implement Microsoft Secure Score recommendations"
            impact = "+$([math]::Max(0, 10 - $secureScorePoints)) points"
        }
    }

    # CA recommendations
    if (-not $assessmentData.conditionalAccess.hasRiskBasedSignIn) {
        $recommendations += @{
            priority = "Medium"
            category = "Conditional Access"
            finding = "No sign-in risk-based CA policy"
            recommendation = "Configure CA policy to block or require MFA for risky sign-ins"
            impact = "+2 points"
        }
    }

    # Privileged Access recommendations
    if ($assessmentData.privilegedAccess.globalAdminCount -gt 6) {
        $recommendations += @{
            priority = "High"
            category = "Privileged Access"
            finding = "$($assessmentData.privilegedAccess.globalAdminCount) Global Administrators"
            recommendation = "Reduce Global Admin count to 2-4 users"
            impact = "+3 points"
        }
    }

    if ($assessmentData.licenseTier.hasEntraP2 -and -not $assessmentData.privilegedAccess.pimEnabled) {
        $recommendations += @{
            priority = "High"
            category = "Privileged Access"
            finding = "PIM available but not configured"
            recommendation = "Enable Privileged Identity Management for just-in-time admin access"
            impact = "+2 points"
        }
    }

    # Data Protection recommendations
    if ($assessmentData.dataProtection.dlpPolicies.enabled -eq 0) {
        $recommendations += @{
            priority = "High"
            category = "Data Protection"
            finding = "No DLP policies enabled"
            recommendation = "Configure DLP policies to protect sensitive data"
            impact = "+4 points"
        }
    }

    if ($assessmentData.dataProtection.sensitivityLabels.published -eq 0) {
        $recommendations += @{
            priority = "High"
            category = "Data Protection"
            finding = "No sensitivity labels published"
            recommendation = "Create and publish sensitivity labels for data classification"
            impact = "+4 points"
        }
    }

    # External Sharing recommendations
    if ($assessmentData.externalSharing.sharepointSharingCapability -eq "ExternalUserAndGuestSharing") {
        $recommendations += @{
            priority = "Medium"
            category = "External Sharing"
            finding = "SharePoint allows anonymous sharing links"
            recommendation = "Restrict SharePoint sharing to 'Existing guests' or 'Only people in your organization'"
            impact = "+2 points"
        }
    }

    # Sort by priority
    $priorityOrder = @{ "Critical" = 0; "High" = 1; "Medium" = 2; "Low" = 3 }
    $assessmentData.recommendations = @($recommendations | Sort-Object { $priorityOrder[$_.priority] })

    # ══════════════════════════════════════════════════════════════════════════
    # SAVE JSON OUTPUT
    # ══════════════════════════════════════════════════════════════════════════

    Write-Status "Saving assessment data..."
    $assessmentData | ConvertTo-Json -Depth 15 | Out-File -FilePath $jsonPath -Encoding UTF8
    Write-Status "JSON saved: $jsonFile" "SUCCESS"

    # Output file paths for the web app
    Write-Host ""
    Write-Host "=== OUTPUT_FILES ==="
    Write-Host "JSON:$ClientName/$jsonFile"
    Write-Host "=== END_OUTPUT_FILES ==="

    Write-Status "Cyber Risk Assessment complete" "SUCCESS"

}
catch {
    Write-Status "Assessment failed: $_" "ERROR"
    Write-Status $_.ScriptStackTrace "ERROR"
    exit 1
}
finally {
    # Disconnect from all services
    Write-Status "Disconnecting from services..."

    if ($connectionState.Graph) {
        try { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null } catch {}
    }

    if ($connectionState.Ipps) {
        try { Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue | Out-Null } catch {}
    }

    if ($connectionState.Spo) {
        try { Disconnect-SPOService -ErrorAction SilentlyContinue | Out-Null } catch {}
    }
}
