# Cyber Risk Scorecard - Implementation Plan

## Overview

A new standalone assessment tool for generating a Cyber Risk Score (0-100%) for the BTR (Business & Technology Review) slide deck. This will be a separate tab in the Technical Audit Tool alongside the existing M365 Assessment, Zero Trust Assessment, etc.

---

## Score Categories & Weights

| Category | Weight | Max Points | Description |
|----------|--------|------------|-------------|
| **MFA & Authentication** | 20% | 20 | MFA registration, enforcement method, weak MFA (SMS-only) |
| **License Security Tier** | 15% | 15 | License type determines available security features |
| **Microsoft Secure Score** | 15% | 15 | Official Microsoft security posture metric |
| **Conditional Access** | 15% | 15 | CA policy count, coverage, risk-based policies |
| **Privileged Access** | 10% | 10 | Global Admin count, PIM usage, role hygiene |
| **Device Compliance** | 10% | 10 | Intune enrollment, compliance rate, Defender status |
| **Data Protection (Purview)** | 10% | 10 | DLP policies, sensitivity labels, information barriers |
| **External Sharing & Collaboration** | 5% | 5 | SharePoint sharing settings, guest access controls |

**Total: 100 points = 100%**

---

## Score Thresholds

| Score Range | Grade | Colour | Description |
|-------------|-------|--------|-------------|
| 85-100% | Excellent | Green (#3fb950) | Strong security posture, minor improvements possible |
| 70-84% | Good | Light Green (#56d364) | Solid foundation, some gaps to address |
| 50-69% | Needs Improvement | Yellow/Amber (#d29922) | Significant gaps requiring attention |
| 0-49% | At Risk | Red (#f85149) | Critical security gaps, immediate action required |

---

## Detailed Scoring Breakdown

### 1. MFA & Authentication (20 points)

**MFA Registration (8 points)**
| Registration % | Points |
|----------------|--------|
| 100% | 8 |
| 95-99% | 7 |
| 90-94% | 6 |
| 80-89% | 5 |
| 70-79% | 3 |
| 50-69% | 2 |
| <50% | 0 |

**MFA Enforcement Method (8 points)**
| Enforcement | Points |
|-------------|--------|
| CA Policy (all users, all apps) | 8 |
| Security Defaults | 6 |
| CA Policy (partial coverage) | 4 |
| Per-user MFA (legacy) | 2 |
| None detected | 0 |

**Authentication Strength (4 points)**
| Factor | Points |
|--------|--------|
| Passwordless users >50% | 4 |
| Passwordless users 20-50% | 3 |
| Passwordless users 10-20% | 2 |
| SMS-only users <10% | 1 |
| SMS-only users >10% | 0 |

---

### 2. License Security Tier (15 points)

**Primary License Scoring**
| License Type | Points | Security Features |
|--------------|--------|-------------------|
| Microsoft 365 E5 | 15 | Full Defender suite, Purview, eDiscovery Premium |
| Microsoft 365 E5 Security add-on | 14 | Defender suite on E3 base |
| Microsoft 365 E3 + Defender P2 | 13 | E3 with advanced threat protection |
| Microsoft 365 E3 + Defender P1 | 12 | E3 with basic threat protection |
| Microsoft 365 E3 | 10 | Good baseline, limited Defender |
| Microsoft 365 Business Premium | 12 | SMB sweet spot - Defender P1, Intune, CA |
| Microsoft 365 Business Standard | 5 | Basic productivity, no advanced security |
| Microsoft 365 Business Basic | 3 | Minimal security features |
| Office 365 E3/E1 | 4 | Legacy, no modern security |
| No qualifying license | 0 | Critical gap |

**SKU Detection Logic**
```
E5: SPE_E5, ENTERPRISEPREMIUM, M365_E5
E3: SPE_E3, ENTERPRISEPACK, M365_E3
Business Premium: SPB, M365_BUSINESS_PREMIUM
Business Standard: O365_BUSINESS_PREMIUM, M365_BUSINESS_STANDARD
Business Basic: O365_BUSINESS_ESSENTIALS, M365_BUSINESS_BASIC
Defender P1: ATP_ENTERPRISE, DEFENDER_ENDPOINT_P1
Defender P2: DEFENDER_ENDPOINT_P2, MDATP_XPLAT
```

---

### 3. Microsoft Secure Score (15 points)

**Direct Percentage Mapping**
| Secure Score % | Points |
|----------------|--------|
| 80%+ | 15 |
| 70-79% | 13 |
| 60-69% | 10 |
| 50-59% | 7 |
| 40-49% | 4 |
| <40% | 0 |

---

### 4. Conditional Access (15 points)

**Policy Count & State (6 points)**
| Enabled CA Policies | Points |
|---------------------|--------|
| 10+ | 6 |
| 7-9 | 5 |
| 5-6 | 4 |
| 3-4 | 3 |
| 1-2 | 1 |
| 0 | 0 |

**MFA Enforcement via CA (4 points)**
| Coverage | Points |
|----------|--------|
| All users + all apps | 4 |
| All users + critical apps | 3 |
| Specific groups | 2 |
| Admins only | 1 |
| None | 0 |

**Risk-Based Policies (3 points)**
| Configuration | Points |
|---------------|--------|
| Sign-in risk + User risk policies enabled | 3 |
| Sign-in risk only | 2 |
| User risk only | 1 |
| No risk-based policies | 0 |

**Device Compliance Requirement (2 points)**
| Configuration | Points |
|---------------|--------|
| CA requires compliant/hybrid joined device | 2 |
| CA requires managed device | 1 |
| No device requirements | 0 |

---

### 5. Privileged Access (10 points)

**Global Admin Count (4 points)**
| Count | Points | Rationale |
|-------|--------|-----------|
| 2-4 | 4 | Optimal - redundancy without excess |
| 5-6 | 3 | Acceptable |
| 1 | 2 | Risk - no break-glass redundancy |
| 7-10 | 1 | Too many privileged accounts |
| >10 | 0 | Excessive risk |

**PIM Usage (3 points)**
| Configuration | Points |
|---------------|--------|
| PIM enabled for all privileged roles | 3 |
| PIM enabled for Global Admin only | 2 |
| PIM available but not configured | 1 |
| No PIM (no P2 license) | 0 |

**Admin Account Hygiene (3 points)**
| Factor | Points |
|--------|--------|
| Cloud-only admin accounts | 1 |
| No stale privileged accounts (90+ days) | 1 |
| MFA enforced on all admins | 1 |

---

### 6. Device Compliance (10 points)

**Intune Enrollment (4 points)**
| Enrollment % | Points |
|--------------|--------|
| 90%+ | 4 |
| 75-89% | 3 |
| 50-74% | 2 |
| 25-49% | 1 |
| <25% or no Intune | 0 |

**Compliance Rate (3 points)**
| Compliance % | Points |
|--------------|--------|
| 95%+ | 3 |
| 85-94% | 2 |
| 70-84% | 1 |
| <70% | 0 |

**Defender for Endpoint Status (3 points)**
| Status | Points |
|--------|--------|
| Defender deployed, <5% vulnerable devices | 3 |
| Defender deployed, 5-15% vulnerable | 2 |
| Defender deployed, >15% vulnerable | 1 |
| No Defender for Endpoint | 0 |

---

### 7. Data Protection / Purview (10 points)

**DLP Policies (4 points)**
| Configuration | Points |
|---------------|--------|
| 3+ active DLP policies across workloads | 4 |
| 1-2 active DLP policies | 3 |
| DLP policies in test mode only | 1 |
| No DLP policies | 0 |

**Sensitivity Labels (4 points)**
| Configuration | Points |
|---------------|--------|
| Labels published + auto-labeling configured | 4 |
| Labels published to all users | 3 |
| Labels published to some users | 2 |
| Labels created but not published | 1 |
| No sensitivity labels | 0 |

**Data Governance (2 points)**
| Configuration | Points |
|---------------|--------|
| Retention policies configured | 1 |
| Information barriers (if applicable) | 1 |

---

### 8. External Sharing & Collaboration (5 points)

**SharePoint External Sharing Level (3 points)**
| Setting | Points |
|---------|--------|
| Only people in your organization | 3 |
| Existing guests | 2 |
| New and existing guests | 1 |
| Anyone (anonymous links) | 0 |

**Guest Access Controls (2 points)**
| Configuration | Points |
|---------------|--------|
| Guest invite restrictions + access reviews | 2 |
| Guest invite restricted to admins/specific users | 1 |
| Anyone can invite guests | 0 |

---

## New Data Collection Requirements

### New PowerShell Script: `cyberrisk.ps1`

**Required Modules:**
- Microsoft.Graph.Authentication
- Microsoft.Graph.Identity.SignIns
- Microsoft.Graph.Identity.DirectoryManagement
- Microsoft.Graph.Security
- Microsoft.Graph.DeviceManagement
- ExchangeOnlineManagement (for S&C PowerShell)
- Microsoft.Online.SharePoint.PowerShell (for SPO settings)

**Required Graph API Scopes:**
```
# Existing scopes from m365assessment.ps1
Directory.Read.All
Organization.Read.All
User.Read.All
UserAuthenticationMethod.Read.All
Policy.Read.All
SecurityEvents.Read.All
DeviceManagementConfiguration.Read.All
DeviceManagementManagedDevices.Read.All
Reports.Read.All

# New scopes for Cyber Risk
InformationProtectionPolicy.Read.All  # Sensitivity labels
SecurityActions.Read.All              # Defender alerts
ThreatHunting.Read.All               # Defender vulnerabilities
```

**New Data to Collect:**

### 1. SharePoint Tenant Sharing Settings
```powershell
# Requires SharePoint Online Management Shell
Connect-SPOService -Url "https://<tenant>-admin.sharepoint.com"
$spoTenant = Get-SPOTenant
$sharingData = @{
    sharingCapability = $spoTenant.SharingCapability  # Disabled/ExternalUserSharingOnly/ExternalUserAndGuestSharing/ExistingExternalUserSharingOnly
    defaultSharingLinkType = $spoTenant.DefaultSharingLinkType
    preventExternalUsersFromResharing = $spoTenant.PreventExternalUsersFromResharing
    requireAcceptingAccountMatchInvitedAccount = $spoTenant.RequireAcceptingAccountMatchInvitedAccount
}
```

### 2. DLP Policies (via Security & Compliance)
```powershell
# Requires Connect-IPPSSession (already in m365assessment.ps1)
$dlpPolicies = Get-DlpCompliancePolicy | Select-Object Name, Enabled, Mode, Workload
$dlpData = @{
    totalPolicies = $dlpPolicies.Count
    enabledPolicies = ($dlpPolicies | Where-Object { $_.Enabled -eq $true }).Count
    testModePolicies = ($dlpPolicies | Where-Object { $_.Mode -eq "TestWithNotifications" -or $_.Mode -eq "TestWithoutNotifications" }).Count
    workloads = ($dlpPolicies | Select-Object -ExpandProperty Workload -Unique)
}
```

### 3. Sensitivity Labels
```powershell
# Requires Connect-IPPSSession
$labels = Get-Label | Select-Object Name, DisplayName, Enabled, LabelActions
$labelPolicies = Get-LabelPolicy | Select-Object Name, Enabled, Labels
$labelData = @{
    totalLabels = $labels.Count
    enabledLabels = ($labels | Where-Object { $_.Enabled -eq $true }).Count
    publishedLabels = ($labelPolicies | Where-Object { $_.Enabled -eq $true } | Select-Object -ExpandProperty Labels -Unique).Count
    autoLabelingConfigured = ($labels | Where-Object { $_.LabelActions -contains "AutoLabel" }).Count -gt 0
}
```

### 4. Defender for Endpoint Vulnerability Data
```powershell
# Via Microsoft Graph Security API
$vulnerabilities = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/security/microsoft.graph.security.runHuntingQuery" -Body @{
    Query = "DeviceTvmSoftwareVulnerabilities | summarize VulnCount=count() by DeviceId | summarize TotalDevices=count(), VulnerableDevices=countif(VulnCount > 0)"
}

# Or via simpler approach - Defender recommendations
$defenderRecommendations = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/security/secureScoreControlProfiles" |
    Where-Object { $_.vendorInformation.provider -eq "Microsoft Defender" }
```

### 5. Defender Alerts Summary
```powershell
# Active security alerts
$alerts = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/security/alerts_v2?`$filter=status eq 'new' or status eq 'inProgress'&`$top=100"
$alertSummary = @{
    totalActive = $alerts.value.Count
    highSeverity = ($alerts.value | Where-Object { $_.severity -eq "high" }).Count
    mediumSeverity = ($alerts.value | Where-Object { $_.severity -eq "medium" }).Count
    lowSeverity = ($alerts.value | Where-Object { $_.severity -eq "low" }).Count
}
```

### 6. Guest Invitation Settings
```powershell
# Already partially collected - need to add authorization policy
$authPolicy = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/policies/authorizationPolicy"
$guestSettings = @{
    allowInvitesFrom = $authPolicy.allowInvitesFrom  # "everyone", "adminsAndGuestInviters", "adminsGuestInvitersAndAllMembers", "none"
    guestUserRoleId = $authPolicy.guestUserRoleId
    allowedToCreateApps = $authPolicy.defaultUserRolePermissions.allowedToCreateApps
}
```

### 7. PIM Status (if P2 licensed)
```powershell
# Check if PIM is configured
try {
    $pimRoles = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilitySchedules?`$filter=principalId ne null"
    $pimEnabled = $true
    $pimRoleCount = $pimRoles.value.Count
} catch {
    $pimEnabled = $false
    $pimRoleCount = 0
}
```

---

## JSON Output Structure

```json
{
    "metadata": {
        "clientName": "Example Corp",
        "assessmentDate": "2026-02-12 14:30:00",
        "tenantId": "xxx-xxx-xxx",
        "tenantName": "Example Corp",
        "primaryDomain": "example.com"
    },
    "scores": {
        "overall": 72,
        "grade": "Good",
        "breakdown": {
            "mfaAuthentication": { "score": 16, "maxScore": 20, "percentage": 80 },
            "licenseTier": { "score": 12, "maxScore": 15, "percentage": 80 },
            "secureScore": { "score": 10, "maxScore": 15, "percentage": 67 },
            "conditionalAccess": { "score": 12, "maxScore": 15, "percentage": 80 },
            "privilegedAccess": { "score": 7, "maxScore": 10, "percentage": 70 },
            "deviceCompliance": { "score": 8, "maxScore": 10, "percentage": 80 },
            "dataProtection": { "score": 5, "maxScore": 10, "percentage": 50 },
            "externalSharing": { "score": 2, "maxScore": 5, "percentage": 40 }
        }
    },
    "mfaAuthentication": {
        "registrationPercentage": 87.5,
        "registeredUsers": 140,
        "totalUsers": 160,
        "enforcementMethod": "Conditional Access (all users)",
        "passwordlessUsers": 25,
        "smsOnlyUsers": 8,
        "details": { ... }
    },
    "licenseTier": {
        "primaryLicense": "Microsoft 365 Business Premium",
        "primaryLicenseSku": "SPB",
        "hasDefenderP1": true,
        "hasDefenderP2": false,
        "hasIntuneP1": true,
        "hasEntraP1": true,
        "hasEntraP2": false,
        "hasPurview": false,
        "allLicenses": [ ... ]
    },
    "secureScore": {
        "currentScore": 52.3,
        "maxScore": 78.0,
        "percentage": 67.1,
        "topRecommendations": [ ... ]
    },
    "conditionalAccess": {
        "totalPolicies": 8,
        "enabledPolicies": 7,
        "mfaPolicies": 3,
        "hasAllUserMfa": true,
        "hasRiskBasedSignIn": true,
        "hasRiskBasedUser": false,
        "hasDeviceCompliance": true,
        "policies": [ ... ]
    },
    "privilegedAccess": {
        "globalAdminCount": 4,
        "totalPrivilegedUsers": 12,
        "pimEnabled": true,
        "pimConfiguredRoles": 5,
        "staleAdmins": 0,
        "cloudOnlyAdmins": true,
        "adminsMfaEnforced": true
    },
    "deviceCompliance": {
        "totalDevices": 145,
        "managedDevices": 138,
        "enrollmentPercentage": 95.2,
        "compliantDevices": 130,
        "compliancePercentage": 94.2,
        "defenderDeployed": true,
        "vulnerableDevices": 12,
        "vulnerabilityPercentage": 8.7
    },
    "dataProtection": {
        "dlpPolicies": {
            "total": 2,
            "enabled": 2,
            "testMode": 0,
            "workloads": ["Exchange", "SharePoint", "OneDrive"]
        },
        "sensitivityLabels": {
            "total": 5,
            "enabled": 5,
            "published": 5,
            "autoLabeling": false
        },
        "retentionPolicies": 3
    },
    "externalSharing": {
        "sharepointSharingCapability": "ExternalUserAndGuestSharing",
        "guestInviteRestriction": "adminsAndGuestInviters",
        "totalGuests": 45,
        "activeGuests": 32,
        "inactiveGuests": 13
    },
    "recommendations": [
        {
            "priority": "High",
            "category": "Data Protection",
            "finding": "No DLP policies configured",
            "recommendation": "Implement DLP policies to protect sensitive data",
            "impact": "+4 points"
        },
        ...
    ]
}
```

---

## UI Implementation

### New Tab: "Cyber Risk"

**Tab Icon:** Shield with percentage (or similar security icon)

**Input Fields:**
- Client Name (required)
- Options:
  - [ ] Include Defender vulnerability scan (adds 2-3 min)
  - [ ] Skip SharePoint admin connection (if no SPO admin access)

**Output:**
- Left panel: Live log of data collection
- Right panel: HTML report with:
  - Large circular gauge showing overall score
  - Category breakdown with progress bars
  - Traffic light indicators for each area
  - Recommendations table
  - Export options

### Report Design

```
+----------------------------------------------------------+
|          CYBER RISK SCORECARD                             |
|          Example Corp - 12 Feb 2026                       |
+----------------------------------------------------------+
|                                                           |
|     [====== 72% ======]     GOOD                         |
|         Overall Score        Status                       |
|                                                           |
+----------------------------------------------------------+
| CATEGORY BREAKDOWN                                        |
+----------------------------------------------------------+
| MFA & Authentication      [========--] 80%    16/20 pts  |
| License Security Tier     [========--] 80%    12/15 pts  |
| Microsoft Secure Score    [======----] 67%    10/15 pts  |
| Conditional Access        [========--] 80%    12/15 pts  |
| Privileged Access         [=======---] 70%     7/10 pts  |
| Device Compliance         [========--] 80%     8/10 pts  |
| Data Protection           [=====-----] 50%     5/10 pts  |
| External Sharing          [====------] 40%     2/5 pts   |
+----------------------------------------------------------+
| TOP RECOMMENDATIONS                                       |
+----------------------------------------------------------+
| ! HIGH   | Enable DLP policies                   | +4 pts |
| ! HIGH   | Configure sensitivity labels          | +4 pts |
| ! MEDIUM | Restrict SharePoint external sharing  | +2 pts |
| ! MEDIUM | Enable user risk-based CA policy      | +1 pt  |
+----------------------------------------------------------+
```

---

## File Structure

```
Technical Audit Analysis/
├── Mac/
│   ├── cyberrisk.ps1           # NEW - PowerShell data collection
│   ├── app.py                  # ADD - /cyberrisk route
│   ├── report_templates.py     # ADD - CyberRiskTemplatedReport class
│   └── templates/
│       └── index.html          # ADD - Cyber Risk tab
├── Windows/
│   ├── cyberrisk.ps1           # NEW - Copy of Mac version
│   ├── app.py                  # ADD - /cyberrisk route
│   ├── report_templates.py     # ADD - CyberRiskTemplatedReport class
│   └── templates/
│       └── index.html          # ADD - Cyber Risk tab
└── claude.md                   # UPDATE - Document new tab
```

---

## Implementation Steps

### Phase 1: PowerShell Script
1. Create `cyberrisk.ps1` based on m365assessment.ps1 structure
2. Remove unnecessary data collection (Teams count, SharePoint storage, etc.)
3. Add new data collection:
   - SharePoint tenant sharing settings
   - DLP policies
   - Sensitivity labels
   - Defender vulnerability data
   - Guest invitation settings
   - PIM status
4. Implement score calculation in PowerShell (so JSON includes pre-calculated scores)
5. Test on sample tenants

### Phase 2: Python Report Template
1. Create `CyberRiskTemplatedReport` class in report_templates.py
2. Implement circular gauge visualisation
3. Implement category progress bars
4. Implement recommendations table with priority sorting
5. Apply existing dark theme styling

### Phase 3: Flask Integration
1. Add `/cyberrisk` route to app.py
2. Add SSE streaming for progress updates
3. Add file output handling
4. Add stop button support

### Phase 4: UI Integration
1. Add "Cyber Risk" tab to index.html
2. Add form inputs (client name, options)
3. Add report display area
4. Add download bar for generated files

### Phase 5: Testing & Documentation
1. Test on multiple tenant configurations
2. Validate scoring accuracy
3. Update claude.md with new tab documentation
4. Mirror to Windows folder

---

## Authentication Flow

The script will require **4 authentication prompts** (similar to M365 Assessment):

1. **Microsoft Graph** (device code) - Core data collection
2. **Exchange Online** (device code) - For DLP policies, sensitivity labels
3. **Security & Compliance** (browser) - For compliance center data
4. **SharePoint Online** (browser) - For tenant sharing settings

---

## Estimated Duration

- Small tenants (<100 users): 3-5 minutes
- Medium tenants (100-500 users): 5-8 minutes
- Large tenants (500+ users): 8-12 minutes

The Defender vulnerability query may add 1-2 minutes if enabled.

---

## Implementation Progress

### Completed

#### Phase 1: PowerShell Script - COMPLETE

**Files Created:**
- `Mac/cyberrisk.ps1` - Full PowerShell data collection script
- `Mac/cyberrisk_config.json` - External configuration file for scoring thresholds and SKU mappings

**Key Features Implemented:**
1. **External Configuration File** (`cyberrisk_config.json`)
   - All scoring thresholds defined externally for easy tuning
   - License SKU mappings in JSON (easily updatable as Microsoft renames SKUs)
   - Capability SKU lists (Defender P1/P2, Entra P1/P2, Intune, Purview)
   - Guest invitation mapping (case-insensitive)
   - SharePoint sharing capability mapping

2. **Memory-Efficient MFA Collection**
   - Processes user batches in-place without storing all objects
   - Counts calculated per-batch, then discarded
   - Handles large tenants (50k+ users) without memory issues

3. **Robust Input Validation**
   - Client name validation (alphanumeric, spaces, hyphens, underscores only)
   - Output path existence and writability checks
   - Test file cleanup in `finally` block

4. **Proper SharePoint Admin URL Detection**
   - Gets onmicrosoft.com domain from verified domains
   - Handles custom primary domains correctly

5. **Connection State Tracking**
   - Tracks Graph, IPPS (Security & Compliance), and SPO connections
   - Proper disconnection in `finally` block for all connected services

6. **dataCollected Flags**
   - Each score breakdown includes `dataCollected: true/false`
   - Distinguishes between "genuinely zero" vs "data not available"

7. **Security Warning in Documentation**
   - Clear warning about high-privilege scopes required
   - Recommendation against using with App Registration/Service Principal

8. **All 8 Scoring Categories Implemented:**
   - MFA & Authentication (20 pts)
   - License Security Tier (15 pts)
   - Microsoft Secure Score (15 pts)
   - Conditional Access (15 pts)
   - Privileged Access (10 pts)
   - Device Compliance (10 pts)
   - Data Protection/Purview (10 pts)
   - External Sharing (5 pts)

9. **Automatic Recommendations Generation**
   - Priority-sorted (Critical > High > Medium > Low)
   - Impact points calculated per recommendation

---

#### Phase 2: Python Report Template - COMPLETE
- [x] Create `CyberRiskTemplatedReport` class in `report_templates.py`
- [x] Implement circular gauge visualisation for overall score (SVG-based)
- [x] Implement category progress bars
- [x] Implement recommendations table with priority sorting
- [x] Apply existing dark theme styling

#### Phase 3: Flask Integration - COMPLETE
- [x] Add `/cyberrisk` route to `app.py`
- [x] Add SSE streaming for progress updates
- [x] Add file output handling
- [x] Add stop button support

#### Phase 4: UI Integration - COMPLETE
- [x] Add "Cyber Risk" tab to `index.html`
- [x] Add form inputs (client name, options checkboxes)
- [x] Add report display area
- [x] Add download bar for generated files

#### Phase 5: Testing & Documentation - PARTIAL
- [ ] Test on multiple tenant configurations
- [ ] Validate scoring accuracy
- [x] Mirror to Windows folder (copy `cyberrisk.ps1` and `cyberrisk_config.json`)
- [ ] Update `CLAUDE.md` with new tab documentation

---

## Required Modules (Auto-installed)

The script will automatically install missing modules:

```powershell
# Required modules (auto-installed by cyberrisk.ps1 if missing)
Microsoft.Graph.* (Authentication, Users, Identity.SignIns, etc.)
ExchangeOnlineManagement
Microsoft.Online.SharePoint.PowerShell
```

On Windows, `run.bat` also pre-installs these modules during setup.

---

## Authentication Prompts

The script requires **3 authentication prompts**:

1. **Microsoft Graph** (device code) - Core data collection
2. **Security & Compliance** (browser) - DLP, sensitivity labels, retention (Connect-IPPSSession has no device code option)
3. **SharePoint Online** (browser) - Tenant sharing settings (Connect-SPOService has no device code option)

Note: Exchange Online connection is NOT needed separately - Security & Compliance PowerShell (`Connect-IPPSSession`) handles the compliance cmdlets.
