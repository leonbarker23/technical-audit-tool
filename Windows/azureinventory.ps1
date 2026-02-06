<#
.SYNOPSIS
    Azure Resource Inventory data collection script for Technical Audit Tool.

.DESCRIPTION
    Runs Microsoft's Azure Resource Inventory (ARI) module and extracts summary
    data to JSON for AI analysis.

.PARAMETER OutputPath
    Directory to save the assessment results.

.PARAMETER ClientName
    Client name for folder organisation.

.PARAMETER IncludeSecurityCenter
    Include Azure Security Center/Defender recommendations.

.PARAMETER SkipDiagram
    Skip network topology diagram generation.

.NOTES
    Requires: PowerShell 7+, AzureResourceInventory module
#>

param(
    [Parameter(Mandatory=$true)]
    [string]$OutputPath,

    [Parameter(Mandatory=$true)]
    [string]$ClientName,

    [switch]$IncludeSecurityCenter,

    [switch]$SkipDiagram
)

$ErrorActionPreference = "Stop"

# Disable ANSI color codes in output (cleaner for web streaming)
$PSStyle.OutputRendering = 'PlainText'
$env:NO_COLOR = "1"

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
    'Az.Accounts',
    'Az.ResourceGraph',
    'AzureResourceInventory',
    'ImportExcel'
)

foreach ($module in $requiredModules) {
    if (-not (Get-Module -ListAvailable -Name $module)) {
        Write-Status "Installing $module..." "INFO"
        try {
            Install-Module $module -Scope CurrentUser -Force -AllowClobber -Repository PSGallery
            Write-Status "Installed $module" "SUCCESS"
        }
        catch {
            Write-Status "Failed to install $module - $_" "ERROR"
            exit 1
        }
    }
}

Write-Status "Required modules available" "SUCCESS"

# ── Create output directory ──────────────────────────────────────────────────

$clientFolder = Join-Path $OutputPath $ClientName
$ariFolder = Join-Path $clientFolder "AzureInventory"
if (-not (Test-Path $ariFolder)) {
    New-Item -ItemType Directory -Path $ariFolder -Force | Out-Null
}

$timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm"
$jsonFile = "azureinventory_$timestamp.json"
$jsonPath = Join-Path $ariFolder $jsonFile

# ── Connect to Azure ─────────────────────────────────────────────────────────

Write-Status "Connecting to Azure..."
Write-Status "A browser window will open for authentication" "INFO"
Write-Status "Sign in with an account that has Reader access to subscriptions" "INFO"

try {
    # Disable the interactive subscription/tenant selection prompt
    # This is the key setting that prevents the [1] [2] picker
    Update-AzConfig -LoginExperienceV2 Off -ErrorAction SilentlyContinue | Out-Null

    Write-Status "Authenticating with device code..." "INFO"

    # Connect without the new interactive experience
    $connectResult = Connect-AzAccount -UseDeviceAuthentication -WarningAction SilentlyContinue

    if (-not $connectResult) {
        Write-Status "Authentication may have failed" "WARNING"
    }

    Write-Status "Connected to Azure" "SUCCESS"

    # Get all available subscriptions
    $subscriptions = Get-AzSubscription -WarningAction SilentlyContinue -ErrorAction SilentlyContinue
    if ($subscriptions) {
        Write-Status "Found $($subscriptions.Count) subscription(s):" "SUCCESS"
        foreach ($sub in $subscriptions) {
            Write-Status "  - $($sub.Name) ($($sub.Id))" "INFO"
        }
    } else {
        Write-Status "No subscriptions found - check permissions" "WARNING"
    }

    $context = Get-AzContext
    if (-not $context) {
        Write-Status "Failed to establish Azure context after authentication" "ERROR"
        exit 1
    }
    Write-Status "Tenant: $($context.Tenant.Id)" "INFO"
    Write-Status "Account: $($context.Account.Id)" "INFO"
}
catch {
    Write-Status "Authentication failed: $_" "ERROR"
    exit 1
}

# ── Run Azure Resource Inventory ─────────────────────────────────────────────

Write-Status "Running Azure Resource Inventory..."
Write-Status "This may take several minutes depending on environment size" "INFO"

try {
    # Build ARI parameters
    $ariParams = @{
        ReportDir = $ariFolder
        SkipAdvisory = $true  # Skip Azure Advisor for faster execution
        Lite = $true  # Lighter Excel format (less formatting)
    }

    if ($IncludeSecurityCenter) {
        $ariParams.SecurityCenter = $true
        Write-Status "Including Security Center recommendations" "INFO"
    }

    if ($SkipDiagram) {
        $ariParams.SkipDiagram = $true
        Write-Status "Skipping network diagram generation" "INFO"
    } else {
        $ariParams.DiagramFullEnvironment = $true
        Write-Status "Generating full network topology diagram" "INFO"
    }

    # Run ARI - catch Excel formatting errors on macOS (missing mono-libgdiplus)
    # but continue if the report was still generated
    $ariError = $null
    try {
        Invoke-ARI @ariParams -ErrorAction Stop
    }
    catch {
        $ariError = $_
        # Check if it's just an Excel formatting error - report may still exist
        if ($_.Exception.Message -match "HorizontalAlignment|Auto-fitting|Cannot Autosize") {
            Write-Status "Excel formatting error (install mono-libgdiplus for full formatting)" "WARNING"
            Write-Status "Checking if report was generated anyway..." "INFO"
        } else {
            throw
        }
    }

    # Check if Excel file exists even after error
    $checkExcel = Get-ChildItem -Path $ariFolder -Filter "AzureResourceInventory_Report_*.xlsx" -ErrorAction SilentlyContinue |
                  Sort-Object LastWriteTime -Descending |
                  Select-Object -First 1

    if ($checkExcel) {
        Write-Status "Azure Resource Inventory complete" "SUCCESS"
    } elseif ($ariError) {
        throw $ariError
    }
}
catch {
    Write-Status "ARI execution failed: $_" "ERROR"
    Write-Status $_.ScriptStackTrace "ERROR"
    exit 1
}

# ── Find generated files ─────────────────────────────────────────────────────

Write-Status "Processing inventory data..."

# Find the Excel report
$excelFile = Get-ChildItem -Path $ariFolder -Filter "AzureResourceInventory_Report_*.xlsx" -ErrorAction SilentlyContinue |
             Sort-Object LastWriteTime -Descending |
             Select-Object -First 1

if (-not $excelFile) {
    Write-Status "No Excel report found" "ERROR"
    exit 1
}

Write-Status "Found Excel report: $($excelFile.Name)" "SUCCESS"

# Find the diagram if generated
$diagramFile = $null
if (-not $SkipDiagram) {
    $diagramFile = Get-ChildItem -Path $ariFolder -Filter "*.xml" -ErrorAction SilentlyContinue |
                   Sort-Object LastWriteTime -Descending |
                   Select-Object -First 1
    if ($diagramFile) {
        Write-Status "Found network diagram: $($diagramFile.Name)" "SUCCESS"
    }
}

# ── Extract summary data from Excel ──────────────────────────────────────────

Write-Status "Extracting summary data for AI analysis..."

try {
    Import-Module ImportExcel -ErrorAction Stop

    # Initialize summary data structure
    $summaryData = @{
        metadata = @{
            clientName = $ClientName
            assessmentDate = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
            tenantId = (Get-AzContext).Tenant.Id
            accountId = (Get-AzContext).Account.Id
            excelReport = $excelFile.Name
            diagramFile = if ($diagramFile) { $diagramFile.Name } else { $null }
        }
        summary = @{
            totalResources = 0
            subscriptionCount = 0
            resourcesByType = @{}
            resourcesByLocation = @{}
        }
        subscriptions = @()
        compute = @{
            virtualMachines = @()
            vmScaleSets = @()
            appServices = @()
            functions = @()
            aks = @()
        }
        networking = @{
            virtualNetworks = @()
            networkSecurityGroups = @()
            loadBalancers = @()
            applicationGateways = @()
            publicIPs = @()
        }
        storage = @{
            storageAccounts = @()
        }
        databases = @{
            sqlServers = @()
            sqlDatabases = @()
            cosmosDbAccounts = @()
            mySqlServers = @()
            postgreSqlServers = @()
        }
        security = @{
            keyVaults = @()
            recommendations = @()
        }
    }

    # Get worksheet names
    $worksheets = Get-ExcelSheetInfo -Path $excelFile.FullName

    Write-Status "Found $($worksheets.Count) worksheets in Excel report" "INFO"

    # Process each worksheet
    foreach ($ws in $worksheets) {
        $sheetName = $ws.Name
        Write-Status "  Processing: $sheetName" "INFO"

        try {
            $data = Import-Excel -Path $excelFile.FullName -WorksheetName $sheetName -ErrorAction SilentlyContinue

            if (-not $data -or $data.Count -eq 0) {
                continue
            }

            # Track resources by type
            $summaryData.summary.totalResources += $data.Count

            switch -Wildcard ($sheetName) {
                "Subscriptions*" {
                    $summaryData.subscriptions = @($data | ForEach-Object {
                        @{
                            name = $_.Name
                            id = $_.Id
                            state = $_.State
                        }
                    })
                    $summaryData.summary.subscriptionCount = $data.Count
                }
                "Virtual Machines*" {
                    $summaryData.compute.virtualMachines = @($data | Select-Object -First 50 | ForEach-Object {
                        @{
                            name = $_.Name
                            resourceGroup = $_.'Resource Group'
                            location = $_.Location
                            vmSize = $_.'VM Size'
                            osType = $_.'OS Type'
                            powerState = $_.'Power State'
                            subscription = $_.Subscription
                        }
                    })
                    # Track by location
                    $data | Group-Object Location | ForEach-Object {
                        $loc = $_.Name
                        if ($loc) {
                            if (-not $summaryData.summary.resourcesByLocation[$loc]) {
                                $summaryData.summary.resourcesByLocation[$loc] = 0
                            }
                            $summaryData.summary.resourcesByLocation[$loc] += $_.Count
                        }
                    }
                }
                "VMSS*" {
                    $summaryData.compute.vmScaleSets = @($data | Select-Object -First 20 | ForEach-Object {
                        @{
                            name = $_.Name
                            resourceGroup = $_.'Resource Group'
                            location = $_.Location
                            capacity = $_.Capacity
                            subscription = $_.Subscription
                        }
                    })
                }
                "App Service*" {
                    $summaryData.compute.appServices = @($data | Select-Object -First 30 | ForEach-Object {
                        @{
                            name = $_.Name
                            resourceGroup = $_.'Resource Group'
                            location = $_.Location
                            kind = $_.Kind
                            state = $_.State
                            subscription = $_.Subscription
                        }
                    })
                }
                "Function App*" {
                    $summaryData.compute.functions = @($data | Select-Object -First 30 | ForEach-Object {
                        @{
                            name = $_.Name
                            resourceGroup = $_.'Resource Group'
                            location = $_.Location
                            subscription = $_.Subscription
                        }
                    })
                }
                "AKS*" {
                    $summaryData.compute.aks = @($data | Select-Object -First 10 | ForEach-Object {
                        @{
                            name = $_.Name
                            resourceGroup = $_.'Resource Group'
                            location = $_.Location
                            kubernetesVersion = $_.'Kubernetes Version'
                            nodeCount = $_.'Node Count'
                            subscription = $_.Subscription
                        }
                    })
                }
                "Virtual Network*" {
                    $summaryData.networking.virtualNetworks = @($data | Select-Object -First 30 | ForEach-Object {
                        @{
                            name = $_.Name
                            resourceGroup = $_.'Resource Group'
                            location = $_.Location
                            addressSpace = $_.'Address Space'
                            subscription = $_.Subscription
                        }
                    })
                }
                "Network Security Group*" {
                    $summaryData.networking.networkSecurityGroups = @($data | Select-Object -First 30 | ForEach-Object {
                        @{
                            name = $_.Name
                            resourceGroup = $_.'Resource Group'
                            location = $_.Location
                            subscription = $_.Subscription
                        }
                    })
                }
                "Load Balancer*" {
                    $summaryData.networking.loadBalancers = @($data | Select-Object -First 20 | ForEach-Object {
                        @{
                            name = $_.Name
                            resourceGroup = $_.'Resource Group'
                            location = $_.Location
                            sku = $_.SKU
                            subscription = $_.Subscription
                        }
                    })
                }
                "Application Gateway*" {
                    $summaryData.networking.applicationGateways = @($data | Select-Object -First 10 | ForEach-Object {
                        @{
                            name = $_.Name
                            resourceGroup = $_.'Resource Group'
                            location = $_.Location
                            tier = $_.Tier
                            subscription = $_.Subscription
                        }
                    })
                }
                "Public IP*" {
                    $summaryData.networking.publicIPs = @($data | Select-Object -First 30 | ForEach-Object {
                        @{
                            name = $_.Name
                            resourceGroup = $_.'Resource Group'
                            location = $_.Location
                            ipAddress = $_.'IP Address'
                            subscription = $_.Subscription
                        }
                    })
                }
                "Storage Account*" {
                    $summaryData.storage.storageAccounts = @($data | Select-Object -First 30 | ForEach-Object {
                        @{
                            name = $_.Name
                            resourceGroup = $_.'Resource Group'
                            location = $_.Location
                            kind = $_.Kind
                            sku = $_.SKU
                            accessTier = $_.'Access Tier'
                            subscription = $_.Subscription
                        }
                    })
                }
                "SQL Server*" {
                    $summaryData.databases.sqlServers = @($data | Select-Object -First 20 | ForEach-Object {
                        @{
                            name = $_.Name
                            resourceGroup = $_.'Resource Group'
                            location = $_.Location
                            version = $_.Version
                            subscription = $_.Subscription
                        }
                    })
                }
                "SQL Database*" {
                    $summaryData.databases.sqlDatabases = @($data | Select-Object -First 30 | ForEach-Object {
                        @{
                            name = $_.Name
                            resourceGroup = $_.'Resource Group'
                            location = $_.Location
                            edition = $_.Edition
                            subscription = $_.Subscription
                        }
                    })
                }
                "Cosmos*" {
                    $summaryData.databases.cosmosDbAccounts = @($data | Select-Object -First 10 | ForEach-Object {
                        @{
                            name = $_.Name
                            resourceGroup = $_.'Resource Group'
                            location = $_.Location
                            subscription = $_.Subscription
                        }
                    })
                }
                "Key Vault*" {
                    $summaryData.security.keyVaults = @($data | Select-Object -First 20 | ForEach-Object {
                        @{
                            name = $_.Name
                            resourceGroup = $_.'Resource Group'
                            location = $_.Location
                            subscription = $_.Subscription
                        }
                    })
                }
                "Security*" {
                    if ($IncludeSecurityCenter -and $data) {
                        $summaryData.security.recommendations = @($data | Select-Object -First 50 | ForEach-Object {
                            @{
                                recommendation = $_.Recommendation
                                severity = $_.Severity
                                resource = $_.Resource
                                subscription = $_.Subscription
                            }
                        })
                    }
                }
            }

            # Track resource types
            if (-not $summaryData.summary.resourcesByType[$sheetName]) {
                $summaryData.summary.resourcesByType[$sheetName] = 0
            }
            $summaryData.summary.resourcesByType[$sheetName] = $data.Count

        }
        catch {
            Write-Status "  Could not process $sheetName - $_" "WARNING"
        }
    }

    # Save JSON summary
    $summaryData | ConvertTo-Json -Depth 10 -Compress | Out-File -FilePath $jsonPath -Encoding UTF8
    Write-Status "JSON summary saved: $jsonFile" "SUCCESS"

}
catch {
    Write-Status "Failed to extract summary data: $_" "ERROR"
    Write-Status $_.ScriptStackTrace "ERROR"
    exit 1
}

# ── Output file paths for the web app ────────────────────────────────────────

Write-Host ""
Write-Host "=== OUTPUT_FILES ==="
Write-Host "JSON:$ClientName/AzureInventory/$jsonFile"
Write-Host "EXCEL:$ClientName/AzureInventory/$($excelFile.Name)"
if ($diagramFile) {
    Write-Host "DIAGRAM:$ClientName/AzureInventory/$($diagramFile.Name)"
}
Write-Host "=== END_OUTPUT_FILES ==="

Write-Status "Azure Resource Inventory complete" "SUCCESS"

# ── Cleanup ──────────────────────────────────────────────────────────────────

try {
    Disconnect-AzAccount -ErrorAction SilentlyContinue | Out-Null
}
catch {}
