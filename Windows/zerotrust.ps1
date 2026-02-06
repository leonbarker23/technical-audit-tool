<#
.SYNOPSIS
    Zero Trust Assessment data collection script for Technical Audit Tool.

.DESCRIPTION
    Connects to Microsoft Graph and collects Zero Trust relevant configuration data
    for analysis by the web application.

.PARAMETER OutputPath
    Directory to save the assessment results.

.PARAMETER ClientName
    Client name for folder organisation.

.NOTES
    Requires: PowerShell 7+, Microsoft.Graph module
#>

param(
    [Parameter(Mandatory=$true)]
    [string]$OutputPath,

    [Parameter(Mandatory=$true)]
    [string]$ClientName
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
    'Microsoft.Graph.Identity.SignIns',
    'Microsoft.Graph.Identity.DirectoryManagement',
    'Microsoft.Graph.DeviceManagement',
    'Microsoft.Graph.Applications',
    'Microsoft.Graph.Security',
    'ZeroTrustAssessment'
)

foreach ($module in $requiredModules) {
    if (-not (Get-Module -ListAvailable -Name $module)) {
        Write-Status "Installing $module..." "INFO"
        try {
            Install-Module $module -Scope CurrentUser -Force -AllowClobber -Repository PSGallery
        }
        catch {
            Write-Status "Failed to install $module - $_" "WARNING"
        }
    }
}

Write-Status "Required modules available" "SUCCESS"

# ── Create output directory ──────────────────────────────────────────────────

$clientFolder = Join-Path $OutputPath $ClientName
if (-not (Test-Path $clientFolder)) {
    New-Item -ItemType Directory -Path $clientFolder -Force | Out-Null
}

$timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm"
$jsonFile = "zerotrust_$timestamp.json"
$jsonPath = Join-Path $clientFolder $jsonFile

# ── Connect to Microsoft Graph ───────────────────────────────────────────────

Write-Status "Connecting to Microsoft Graph..."
Write-Status "A browser window will open for authentication" "INFO"
Write-Status "Sign in with Global Reader or Global Admin credentials" "INFO"

# Define required scopes for Zero Trust assessment
$scopes = @(
    "Policy.Read.All",
    "Directory.Read.All",
    "DeviceManagementConfiguration.Read.All",
    "DeviceManagementManagedDevices.Read.All",
    "Application.Read.All",
    "SecurityEvents.Read.All"
)

try {
    # Use device code flow for non-interactive terminals
    # ContextScope Process ensures token persists across cmdlet calls (fixes null reference errors)
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

Write-Status "Running Zero Trust Assessment..."
Write-Status "This may take several minutes depending on tenant size" "INFO"

try {
    # Initialize assessment data structure
    $assessmentData = @{
        metadata = @{
            clientName = $ClientName
            assessmentDate = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
            tenantId = (Get-MgContext).TenantId
            tenantName = $null
        }
        identity = @{
            conditionalAccess = @()
            authenticationMethods = @{}
            privilegedAccess = @{}
        }
        devices = @{
            compliancePolicies = @()
            summary = @{}
        }
        applications = @{
            enterpriseApps = @{}
            appProtection = @()
        }
        network = @{
            namedLocations = @()
        }
        data = @{
            sensitivityLabels = @()
        }
        securityScore = @{}
    }

    # ── Get Organization Info ────────────────────────────────────────────────

    Write-Status "Getting organization info..."
    try {
        $org = Get-MgOrganization
        $assessmentData.metadata.tenantName = $org.DisplayName
        Write-Status "  Organization: $($org.DisplayName)" "SUCCESS"
    }
    catch {
        Write-Status "  Could not retrieve organization info: $_" "WARNING"
    }

    # ── Collect Identity data ────────────────────────────────────────────────

    Write-Status "Collecting Identity pillar data..."

    try {
        # Conditional Access Policies
        $caPolicies = Get-MgIdentityConditionalAccessPolicy -All
        $assessmentData.identity.conditionalAccess = @($caPolicies | ForEach-Object {
            @{
                id = $_.Id
                displayName = $_.DisplayName
                state = $_.State
                createdDateTime = if ($_.CreatedDateTime) { $_.CreatedDateTime.ToString() } else { $null }
                modifiedDateTime = if ($_.ModifiedDateTime) { $_.ModifiedDateTime.ToString() } else { $null }
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
        Write-Status "  Found $($caPolicies.Count) Conditional Access policies" "SUCCESS"
    }
    catch {
        Write-Status "  Could not retrieve CA policies: $_" "WARNING"
    }

    try {
        # Authentication Methods Policy
        $authMethods = Get-MgPolicyAuthenticationMethodPolicy
        $assessmentData.identity.authenticationMethods = @{
            policyMigrationState = $authMethods.PolicyMigrationState
            registrationEnforcement = $authMethods.RegistrationEnforcement
        }
        Write-Status "  Retrieved authentication methods policy" "SUCCESS"
    }
    catch {
        Write-Status "  Could not retrieve auth methods: $_" "WARNING"
    }

    try {
        # Directory Roles and Global Admins
        $directoryRoles = Get-MgDirectoryRole -All
        $globalAdminRole = $directoryRoles | Where-Object { $_.DisplayName -eq "Global Administrator" }

        $globalAdminCount = 0
        if ($globalAdminRole) {
            $globalAdmins = Get-MgDirectoryRoleMember -DirectoryRoleId $globalAdminRole.Id -All
            $globalAdminCount = $globalAdmins.Count
        }

        $assessmentData.identity.privilegedAccess = @{
            globalAdminCount = $globalAdminCount
            directoryRolesCount = $directoryRoles.Count
        }
        Write-Status "  Found $globalAdminCount Global Administrators" "SUCCESS"
    }
    catch {
        Write-Status "  Could not retrieve privileged access data: $_" "WARNING"
    }

    # ── Collect Device data ──────────────────────────────────────────────────

    Write-Status "Collecting Devices pillar data..."

    try {
        # Device Compliance Policies (requires Intune)
        $compliancePolicies = Get-MgDeviceManagementDeviceCompliancePolicy -All
        $assessmentData.devices.compliancePolicies = @($compliancePolicies | ForEach-Object {
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
        $assessmentData.devices.compliancePolicies = @()
    }

    try {
        # Managed Devices summary
        $devices = Get-MgDeviceManagementManagedDevice -All
        $compliantCount = ($devices | Where-Object { $_.ComplianceState -eq "compliant" }).Count
        $nonCompliantCount = ($devices | Where-Object { $_.ComplianceState -eq "noncompliant" }).Count

        $assessmentData.devices.summary = @{
            totalDevices = $devices.Count
            compliant = $compliantCount
            nonCompliant = $nonCompliantCount
        }
        Write-Status "  Found $($devices.Count) managed devices ($compliantCount compliant)" "SUCCESS"
    }
    catch {
        Write-Status "  Could not retrieve managed devices" "WARNING"
        $assessmentData.devices.summary = @{ totalDevices = 0; compliant = 0; nonCompliant = 0 }
    }

    # ── Collect Application data ─────────────────────────────────────────────

    Write-Status "Collecting Applications pillar data..."

    try {
        # Count enterprise applications (limit to avoid timeout)
        $servicePrincipals = Get-MgServicePrincipal -Top 999
        $assessmentData.applications.enterpriseApps = @{
            total = $servicePrincipals.Count
        }
        Write-Status "  Found $($servicePrincipals.Count) enterprise applications" "SUCCESS"
    }
    catch {
        Write-Status "  Could not retrieve enterprise applications: $_" "WARNING"
        $assessmentData.applications.enterpriseApps = @{ total = 0 }
    }

    try {
        # App Protection Policies (Intune MAM)
        $appProtectionPolicies = Get-MgDeviceAppManagementManagedAppPolicy -All
        $assessmentData.applications.appProtection = @($appProtectionPolicies | ForEach-Object {
            @{
                id = $_.Id
                displayName = $_.DisplayName
            }
        })
        Write-Status "  Found $($appProtectionPolicies.Count) app protection policies" "SUCCESS"
    }
    catch {
        Write-Status "  Could not retrieve app protection policies" "WARNING"
        $assessmentData.applications.appProtection = @()
    }

    # ── Collect Network data ─────────────────────────────────────────────────

    Write-Status "Collecting Network pillar data..."

    try {
        # Named Locations
        $namedLocations = Get-MgIdentityConditionalAccessNamedLocation -All
        $assessmentData.network.namedLocations = @($namedLocations | ForEach-Object {
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
        $assessmentData.network.namedLocations = @()
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

            $assessmentData.securityScore = @{
                currentScore = $score.CurrentScore
                maxScore = $score.MaxScore
                percentage = $percentage
                createdDateTime = if ($score.CreatedDateTime) { $score.CreatedDateTime.ToString() } else { $null }
            }
            Write-Status "  Security Score: $percentage% ($($score.CurrentScore)/$($score.MaxScore))" "SUCCESS"
        }
    }
    catch {
        Write-Status "  Could not retrieve security score: $_" "WARNING"
        $assessmentData.securityScore = @{ currentScore = 0; maxScore = 0; percentage = 0 }
    }

    # ── Save JSON output ─────────────────────────────────────────────────────

    Write-Status "Saving assessment data..."
    $assessmentData | ConvertTo-Json -Depth 10 -Compress | Out-File -FilePath $jsonPath -Encoding UTF8
    Write-Status "JSON saved: $jsonFile" "SUCCESS"

    # ── Run Microsoft Zero Trust Assessment for HTML report ──────────────────

    $htmlFile = $null
    $ztJsonFile = $null
    Write-Status "Generating Microsoft Zero Trust HTML report..."
    Write-Status "This may take several minutes..." "INFO"
    try {
        # Import the module
        Import-Module ZeroTrustAssessment -ErrorAction Stop

        # Output path for the ZT report
        $ztReportFolder = Join-Path $clientFolder "ZeroTrustReport"

        # Run assessment - catch the browser open error but continue
        try {
            Invoke-ZtAssessment -Path $ztReportFolder -ErrorAction Stop
        }
        catch {
            # Ignore "Operation not permitted" error from browser open attempt
            if ($_.Exception.Message -notmatch "Operation not permitted") {
                throw
            }
        }

        # Find the generated HTML file
        $generatedHtml = Get-ChildItem -Path $ztReportFolder -Filter "*.html" -ErrorAction SilentlyContinue |
                         Select-Object -First 1

        if ($generatedHtml) {
            $htmlFile = "$ClientName/ZeroTrustReport/$($generatedHtml.Name)"
            Write-Status "HTML report saved: ZeroTrustReport/$($generatedHtml.Name)" "SUCCESS"
        }

        # Find the detailed JSON report in zt-export for AI analysis
        $ztExportJson = Join-Path $ztReportFolder "zt-export/ZeroTrustAssessmentReport.json"
        if (Test-Path $ztExportJson) {
            $ztJsonFile = "$ClientName/ZeroTrustReport/zt-export/ZeroTrustAssessmentReport.json"
            Write-Status "Detailed assessment data available for AI analysis" "SUCCESS"
        }
    }
    catch {
        Write-Status "Could not generate Microsoft ZT report: $_" "WARNING"
        Write-Status "The AI summary will still be generated from basic data" "INFO"
    }

    # ── Output file paths for the web app ────────────────────────────────────

    Write-Host ""
    Write-Host "=== OUTPUT_FILES ==="
    Write-Host "JSON:$ClientName/$jsonFile"
    if ($ztJsonFile) {
        Write-Host "ZTJSON:$ztJsonFile"
    }
    if ($htmlFile) {
        Write-Host "HTML:$htmlFile"
    }
    Write-Host "=== END_OUTPUT_FILES ==="

    Write-Status "Zero Trust Assessment complete" "SUCCESS"

}
catch {
    Write-Status "Assessment failed: $_" "ERROR"
    Write-Status $_.ScriptStackTrace "ERROR"
    exit 1
}
finally {
    # Disconnect from Graph
    try {
        Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
    }
    catch {}
}
