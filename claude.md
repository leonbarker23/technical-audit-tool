# AAG Technical Audit Tool

A comprehensive assessment suite for MSP technical consultants performing IT audits and reviews.

**Branding**: AAG-IT branded with gradient colors (#e81f63 pink, #7b1fa2 purple, #039be5 blue)

---

## Current Tabs

| Tab | Status | Description |
|-----|--------|-------------|
| **Network Discovery** | Implemented | Network vulnerability scanning with nmap, live log output, AI-generated reports |
| **M365 Assessment** | Implemented | Microsoft 365 tenant assessment with Maester security tests and Graph API data |
| **Azure Inventory (ARI)** | Implemented | Azure Resource Inventory with Excel reports, network diagrams, AI analysis |
| **Zero Trust Assessment** | Implemented | Microsoft 365 Zero Trust security assessment with ~168 tests |

---

## Platform Versions

| Platform | Location | How to Run |
|----------|----------|------------|
| **macOS** | `Mac/` folder | `cd Mac && sudo venv/bin/python app.py` |
| **Windows** | `Windows/` folder | Right-click `run.bat` → "Run as administrator" |

---

## Architecture

Both Mac and Windows versions share identical functionality. The table below shows the Mac paths; Windows equivalents are in `Windows/`.

| File | Role |
|------|------|
| `scan.py` | Network scanning engine — nmap wrapper, XML parser, LLM prompts |
| `app.py` | Flask web server — SSE streaming, routes for all assessments |
| `templates/index.html` | Single-page UI with tabbed interface |
| `m365assessment.ps1` | PowerShell script for M365 data collection via Graph API + Maester |
| `zerotrust.ps1` | PowerShell script for Zero Trust data collection via Microsoft Graph |
| `azureinventory.ps1` | PowerShell script for Azure Resource Inventory via ARI module |
| `requirements.txt` | Python dependencies (`flask`, `ollama`) |

---

## Features

### Stop Button
All tabs have a stop button that appears during active scans/assessments. The backend tracks active processes by session ID and kills them on request.

### Parallel Execution
Assessments can run in parallel — you can run a Zero Trust assessment while also running a Network Discovery scan. Flask runs with `threaded=True` to support concurrent requests.

---

## Network Discovery

### How it works
1. User enters client name, target (IP/CIDR/hostname), and scan depth
2. nmap runs as subprocess, output streamed via SSE
3. XML parsed into structured data
4. AI (Ollama) generates security assessment report
5. Files saved to client folder

### Scan Depth Profiles

| Depth | Flags | Description |
|-------|-------|-------------|
| **Deep** | `-sV -O -sC -T4` | Full service/OS detection + scripts |
| **Medium** | `-sV -O -T4 --min-rate 500` | Version/OS detection, no scripts |
| **Fast** | `-T5 --top-ports 100 --min-rate 1000` | Top 100 ports only |

### Files Generated
- `<client>_<target>_<timestamp>.json` — Raw scan data
- `<client>_<target>_<timestamp>.md` — AI-generated report

---

## M365 Assessment

### Prerequisites
- **PowerShell 7** — Install on Mac: `brew install powershell`
- **Microsoft.Graph modules** — Auto-installed:
  - Microsoft.Graph.Authentication
  - Microsoft.Graph.Users
  - Microsoft.Graph.Identity.SignIns
  - Microsoft.Graph.Identity.DirectoryManagement
  - Microsoft.Graph.Reports
  - Microsoft.Graph.Security
  - Microsoft.Graph.Applications
  - Microsoft.Graph.DeviceManagement
  - Microsoft.Graph.Sites
  - Microsoft.Graph.Groups
- **Maester module** — Auto-installed from PSGallery
- **ExchangeOnlineManagement module** — Auto-installed (for Exchange and S&C tests)
- **MicrosoftTeams module** — Auto-installed (for Teams tests)
- **Microsoft 365 credentials** — Global Reader or Global Admin

### How it works
1. User enters client name and optionally skips Maester tests
2. Flask executes `m365assessment.ps1` via PowerShell 7
3. **Authentication (4 prompts when Maester enabled)**:
   - Microsoft Graph (device code) — all Graph API scopes including PIM
   - Microsoft Teams (device code) — loaded first to avoid MSAL conflicts
   - Exchange Online (device code) — for Exchange-related tests
   - Security & Compliance (browser) — for compliance tests
4. **Graph API data collection**:
   - Licensing: Subscribed SKUs, user counts, guest users
   - Security Score: Current/max score, percentage, top 10 recommendations
   - Identity: CA policies, MFA status, SSPR, privileged access, risky users
   - Intune: Compliance policies, configuration profiles, managed devices, app protection
   - SharePoint: Storage usage, site count
   - Teams: Team count
   - Applications: Enterprise apps, app registrations
   - Governance: Admin role breakdown, named locations
5. **Maester security tests** (optional):
   - Runs comprehensive M365 security tests across all connected services
   - Generates interactive HTML report
   - Exports detailed JSON and Markdown results
6. AI (Ollama) analyses all data INCLUDING the Maester markdown report
7. Report focuses on MSP value: project opportunities, license upsells, managed services

### Options
- **Skip Maester Tests** — Skips Maester security tests (unchecked by default, Maester runs)

### Duration
- Small tenants (<100 users): 8-12 minutes (with all connections)
- Medium tenants (100-1000 users): 12-18 minutes
- Large tenants (1000+ users): 18-25 minutes

### Files Generated
- `m365assessment_YYYY-MM-DD_HH-MM.json` — Raw Graph API assessment data
- `m365assessment_report_YYYY-MM-DD_HH-MM.md` — AI-generated summary report
- `MaesterTests/MaesterReport.html` — Interactive Maester security test report
- `MaesterTests/MaesterReport.json` — Raw Maester test results
- `MaesterTests/MaesterReport.md` — Markdown report (used by AI for analysis)

---

## Azure Resource Inventory (ARI)

### Prerequisites
- **PowerShell 7** — Install on Mac: `brew install powershell`
- **AzureResourceInventory module** — Auto-installed from PSGallery
- **ImportExcel module** — Auto-installed for Excel parsing
- **Az.Accounts module** — Auto-installed for Azure authentication
- **Azure credentials** — Reader access to subscriptions

### How it works
1. User enters client name and configures options
2. Flask executes `azureinventory.ps1` via PowerShell 7
3. Script uses **device code authentication** — outputs URL and code for browser
4. **ARI module** (`Invoke-ARI`) collects Azure resource data:
   - Scans all accessible subscriptions
   - Collects VMs, networking, storage, databases, security resources
   - Generates Excel workbook with multiple worksheets
   - Optionally generates network topology diagram (Draw.io XML)
5. PowerShell extracts summary data from Excel to JSON
6. AI (Ollama) analyses JSON and generates infrastructure report
7. Report streams to UI in real-time

### Options
- **Include Security Center** — Adds Azure Defender recommendations
- **Skip Diagram** — Skips network topology generation (faster)

### Duration
- Small environments (<100 resources): 5-8 minutes
- Medium environments (100-500 resources): 8-15 minutes
- Large environments (500+ resources): 15-20+ minutes

### Files Generated
- `azureinventory_YYYY-MM-DD_HH-MM.json` — Summary data for AI
- `azureinventory_report_YYYY-MM-DD_HH-MM.md` — AI-generated report
- `AzureResourceInventory_Report_*.xlsx` — Full Excel inventory
- `AzureResourceInventory_Diagram_*.xml` — Network topology (Draw.io)

---

## Zero Trust Assessment

### Prerequisites
- **PowerShell 7** — Install on Mac: `brew install powershell`
- **Microsoft.Graph modules** — Auto-installed:
  - Microsoft.Graph.Authentication
  - Microsoft.Graph.Identity.SignIns
  - Microsoft.Graph.Identity.DirectoryManagement
  - Microsoft.Graph.DeviceManagement
  - Microsoft.Graph.Applications
  - Microsoft.Graph.Security
- **ZeroTrustAssessment module** — Auto-installed from PSGallery
- **Microsoft 365 credentials** — Global Reader or Global Admin

### How it works
1. User enters client name and clicks "Run Assessment"
2. Flask executes `zerotrust.ps1` via PowerShell 7
3. Script uses **device code authentication** — outputs URL and code for browser
4. **Phase 1** — Custom data collection from Microsoft Graph:
   - Conditional Access policies
   - Authentication methods policy
   - Privileged access (Global Admins, directory roles)
   - Device compliance policies and managed devices
   - Enterprise applications count
   - App protection policies
   - Named locations
   - Microsoft Secure Score
5. **Phase 2** — Microsoft ZeroTrustAssessment module runs ~168 security tests:
   - Identity pillar (access control, credentials, privileged access)
   - Devices pillar (compliance, MDM, data protection)
   - Generates interactive HTML report with charts
   - Exports detailed JSON with all test results
6. AI (Ollama) analyses test results and generates structured report
7. Report streams to UI in real-time

### Duration
- Small tenants (<100 users): 5-7 minutes
- Medium tenants (100-1000 users): 7-10 minutes
- Large tenants (1000+ users): 10-15 minutes

### Files Generated
- `zerotrust_YYYY-MM-DD_HH-MM.json` — Raw Graph API data
- `zerotrust_report_YYYY-MM-DD_HH-MM.md` — AI-generated report
- `ZeroTrustReport/ZeroTrustAssessmentReport.html` — Microsoft interactive HTML report
- `ZeroTrustReport/zt-export/ZeroTrustAssessmentReport.json` — Detailed test results

---

## LLM Integration

- **Model:** `qwen2.5:14b` on macOS, `qwen2.5:7b` on Windows (via Ollama)
- **Streaming:** Token-by-token via SSE for real-time rendering
- **Prompt design:** Strict output templates with anti-hallucination instructions

---

## Input Validation & Security

- **Target field:** Regex-gated to prevent injection
- **Client name:** Regex-gated for safe folder names
- **nmap invoked via list** (no shell injection)
- **File downloads** use `send_from_directory` (no path traversal)
- **Privilege requirement:** Root (macOS) or Administrator (Windows) for nmap `-O`

---

## UI Layout

- Dark theme with AAG gradient branding
- Tabbed interface with 4 assessment types
- Two-panel layout: live log (left) + AI report (right)
- Real-time Markdown rendering with severity colour-coding
- Download bar with links to generated files

---

## Dependencies

### macOS

#### System Dependencies (via Homebrew)
```bash
brew install nmap
brew install powershell
brew install mono-libgdiplus
```

| Package | Purpose |
|---------|---------|
| `nmap` | Network scanning for Network Discovery tab |
| `powershell` | PowerShell 7 for Azure Inventory, M365 Assessment, and Zero Trust scripts |
| `mono-libgdiplus` | GDI+ library for Excel column auto-sizing in ImportExcel module |

#### Ollama (AI)
```bash
# Install Ollama
curl -fsSL https://ollama.com/install.sh | sh

# Pull the model
ollama pull qwen2.5:14b
```

#### Python Dependencies
```bash
cd Mac
python3 -m venv venv
venv/bin/pip install -r requirements.txt
```

See `Mac/requirements.txt` for Python packages (`flask`, `ollama`).

### Windows

**Zero friction setup** — just run `run.bat` as Administrator. All dependencies are auto-installed:

| Dependency | Installation Method |
|------------|---------------------|
| Python 3 | winget or direct download from python.org |
| pip packages | `pip install flask ollama` |
| nmap | winget (`Insecure.Nmap`) |
| Ollama | Direct download of OllamaSetup.exe |
| qwen2.5:7b model | `ollama pull qwen2.5:7b` |
| PowerShell 7 | winget (`Microsoft.PowerShell`) |

See `Windows/requirements.txt` for Python packages.

---

## Known Limitations

- `qwen2.5:14b` needs ~10 GB RAM; Windows uses smaller `qwen2.5:7b`
- Network scans are unauthenticated discovery only

---

## Changelog

### 2026-02-09 (Update 5)
- **Added User Account Health insights** — New section analyzing stale accounts, guest hygiene, license waste, and MFA methods
  - **Stale Accounts**: Identifies users inactive for 90/180/365 days or never signed in
    - Risk assessment based on percentage of workforce
    - Lists top stale accounts with licenses (cleanup priority)
  - **Guest Analysis**: Active vs inactive guests, external domain breakdown
    - Identifies guests who have never signed in
    - Shows top external domains for business context
  - **License Waste Detection**: Calculates cost of licenses assigned to inactive users
    - Monthly and annual waste estimates in GBP
    - Breakdown by license SKU
    - Priority levels based on waste amount
  - **Enhanced MFA Analysis**: Detailed MFA method breakdown
    - Detects weak MFA (SMS-only users)
    - Passwordless capability tracking
    - Authentication method adoption rates
  - **Architecture**: Python does all analysis and risk assessment, LLM receives pre-formatted sections
  - New `userInsights` field in JSON with raw counts and lists
  - All analysis (risk levels, percentages, recommendations) calculated in Python via `_format_user_insights()` function
  - Report now has 8 sections (added "User Account Health" as section 5)

### 2026-02-09 (Update 4)
- **Added MFA enforcement analysis** — Now distinguishes between MFA registration and enforcement
  - Scans CA policies to detect which ones require MFA
  - Checks for Security Defaults status
  - Determines enforcement scope: all users, specific groups, roles, or apps
  - Identifies conditions: location-based, platform-specific, risk-based
  - New `mfaEnforcement` field in JSON output with:
    - `securityDefaultsEnabled`: boolean
    - `caPoliciesRequiringMfa`: count of policies requiring MFA
    - `hasUniversalMfaPolicy`: true if a policy covers all users + all apps
    - `enforcementMethod`: "Security Defaults", "Conditional Access (all users)", "Conditional Access (partial)", or "None detected"
    - `policies`: array of MFA-requiring policies with scope details
  - LLM prompt updated to provide gap analysis (registration vs enforcement)

### 2026-02-09 (Update 3)
- **Restructured M365 assessment report format** — New 7-section structure:
  1. **Executive Summary** — High-level security posture overview
  2. **Licensing Overview** — All paid licenses with exact counts and SKU translations
  3. **Identity & Access Management** — MFA status, CA policies, Global Admin count with risk levels
  4. **Microsoft Secure Score** — Score percentage + all 10 recommendations with point values
  5. **Security Test Findings** — Maester themes/patterns grouped by category
  6. **Project Recommendations** — Immediate (0-30d), Short-term (1-3m), Strategic (3-12m)
  7. **Discussion Points** — Sales angle, license optimisation, compliance considerations
  8. **Conclusion** — Top 3 priorities and next steps
- **Formatted JSON output** — Removed `-Compress` flag so JSON files are human-readable

### 2026-02-09 (Update 2)
- **Fixed SharePoint site count** — Now uses `getSharePointSiteUsageDetail` report for accurate tenant-wide site count
  - Previously used `Get-MgSite` which only returned sites accessible to the authenticated user
  - Site count now matches the storage report data source
- **Fixed license type confusion (A3 vs E3)** — Added explicit SKU-to-name mapping in LLM prompt
  - LLM now instructed to report EXACT SKU names and not confuse Education (A3/A5) with Enterprise (E3/E5)
  - Added common SKU mappings: SPE_A3, M365EDU_A3, SPE_E3, ENTERPRISEPACK, etc.

### 2026-02-09
- **Filtered free licenses from M365 report** — Free/trial licenses no longer clutter the AI analysis
  - Filters out: Power BI Free, Flow Free, Teams Exploratory, PowerApps Viral, etc.
  - LLM prompt now explicitly notes that only paid licenses are included
- **Improved Maester report handling**
  - Increased character limit from 15k to 20k for fuller report inclusion
  - Clearer prompt instructions emphasising Maester as PRIMARY source for security findings
  - Fixed UTF-8 encoding error when reading Maester markdown on Windows
- **Fixed Microsoft Graph module version conflicts**
  - Detects version mismatches between Graph modules before connecting
  - Auto-updates mismatched modules to get them in sync
  - Force-imports all Graph modules upfront to avoid assembly conflicts
- **Fixed MFA registration pagination warning**
  - Added proper pagination handling for userRegistrationDetails endpoint
  - Now returns accurate MFA counts for large tenants (1000+ users)

### 2026-02-06 (Update 5)
- **M365 Assessment mirrored to Windows** — Full implementation now available on both platforms
  - Added `m365assessment.ps1` to Windows folder
  - Added `/m365assessment` route and `_m365assessment_prompt()` to Windows `app.py`
  - Replaced placeholder M365 tab with full UI implementation
  - Windows uses `qwen2.5:7b` model (smaller than macOS `qwen2.5:14b`)
- **Changed Azure Inventory tab icon** — Now uses 📊 (chart) instead of ☁️ (cloud) to differentiate from M365 Assessment
- **Updated run.bat** — PowerShell 7 requirement message now includes M365 Assessment

### 2026-02-06 (Update 4)
- **Added Security & Compliance connection** — Enables compliance-related Maester tests via `Connect-IPPSSession`
- **Fixed Teams module assembly conflict** — Teams module now loads BEFORE Exchange to avoid MSAL version conflicts
- **Added RoleEligibilitySchedule.ReadWrite.Directory scope** — Enables PIM eligible role queries for global admin tests
- **LLM now reads Maester markdown report** — Full security test report included in AI analysis
- **Revised LLM prompt for MSP focus** — Now emphasises:
  - Project opportunities and remediation work
  - License upsell recommendations
  - Managed services value proposition
  - Themes and patterns instead of listing individual test results
- Four authentication prompts: Graph API, Teams, Exchange, Security & Compliance

### 2026-02-06 (Update 3)
- **Added Exchange Online and Teams modules for Maester** — Enables Exchange and Teams security tests
  - Three authentication prompts: Graph API, Exchange Online, Teams
  - All connections are read-only (no write permissions)
  - Modules auto-install if missing
- **Proper service disconnection** — Now disconnects from all three services on completion

### 2026-02-06 (Update 2)
- **Fixed M365 Assessment Maester permission errors** — Now uses `Connect-MgGraph` with all Maester-required scopes upfront, then runs `Invoke-Maester -SkipGraphConnect` to use the existing connection
- **Fixed SharePoint data collection on macOS** — The script now uses cross-platform temp directory detection (`$env:TMPDIR` or `/tmp` on macOS instead of `$env:TEMP`)
- **Fixed Maester test folder conflict** — Clears existing test files before installing fresh ones

### 2026-02-06
- **M365 Assessment tab implemented** — Graph API + Maester hybrid approach
  - Collects licensing, Secure Score, CA policies, MFA status, Intune, SharePoint, Teams data
  - Optional Maester security tests with HTML/JSON reports
  - AI-generated comprehensive tenant analysis
- Fixed Windows `run.bat` batch file syntax error (nested if statements in Ollama section)
- Added browser auto-launch with 5-second delay fallback
- All 4 tabs now fully functional on both Mac and Windows
