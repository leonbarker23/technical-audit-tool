"""
Python-templated report generators for instant structured reports.

This module provides template-based report generation without LLM dependencies.
All risk assessment and analysis is done in pure Python for speed and consistency.
Reports are generated as HTML for clean web UI rendering.

Available report generators:
- M365TemplatedReport: Microsoft 365 tenant assessment
- NetworkTemplatedReport: Network discovery scan results
- AzureTemplatedReport: Azure Resource Inventory assessment
"""

from datetime import datetime
from typing import Dict, List, Tuple, Optional


class ReportSection:
    """Base class for report sections with common formatting utilities."""

    def __init__(self, assessment_data: dict):
        self.assessment_data = assessment_data

    @staticmethod
    def format_risk_level(value: float, thresholds: Dict[str, float]) -> str:
        """
        Assign risk level based on thresholds.

        Args:
            value: Numeric value to assess
            thresholds: Dict with keys 'critical', 'high', 'medium' and their threshold values

        Returns:
            Risk level string: "Critical", "High", "Medium", or "Low"
        """
        if value >= thresholds.get("critical", float('inf')):
            return "Critical"
        elif value >= thresholds.get("high", float('inf')):
            return "High"
        elif value >= thresholds.get("medium", float('inf')):
            return "Medium"
        else:
            return "Low"

    @staticmethod
    def format_currency(amount: float, currency: str = "GBP") -> str:
        """Format currency with thousand separators."""
        return f"{currency} {amount:,.2f}"

    @staticmethod
    def format_percentage(value: float, decimals: int = 1) -> str:
        """Format percentage with specified decimals."""
        return f"{value:.{decimals}f}%"

    @staticmethod
    def risk_badge(level: str) -> str:
        """Generate HTML badge for risk level."""
        colors = {
            "Critical": "#f85149",
            "High": "#f85149",
            "Medium": "#d29922",
            "Low": "#3fb950"
        }
        bg_colors = {
            "Critical": "rgba(248, 81, 73, 0.15)",
            "High": "rgba(248, 81, 73, 0.1)",
            "Medium": "rgba(210, 153, 34, 0.15)",
            "Low": "rgba(63, 185, 80, 0.15)"
        }
        color = colors.get(level, "#7d8590")
        bg = bg_colors.get(level, "rgba(125, 133, 144, 0.1)")
        return f'<span style="display:inline-block;background:{bg};color:{color};font-weight:600;padding:2px 8px;border-radius:4px;font-size:0.85em;">{level}</span>'

    @staticmethod
    def format_table(headers: List[str], rows: List[List[str]], highlight_col: int = None) -> str:
        """
        Format an HTML table.

        Args:
            headers: List of column headers
            rows: List of rows, each row is a list of cell values
            highlight_col: Column index to apply risk coloring (optional)

        Returns:
            Formatted HTML table string
        """
        if not headers or not rows:
            return ""

        html = ['<table style="width:100%;border-collapse:collapse;margin:12px 0;font-size:0.85rem;">']

        # Header row
        html.append('<thead><tr>')
        for h in headers:
            html.append(f'<th style="background:#161b22;color:#7d8590;text-align:left;padding:10px 12px;border-bottom:2px solid #30363d;font-weight:600;">{h}</th>')
        html.append('</tr></thead>')

        # Data rows
        html.append('<tbody>')
        for row in rows:
            html.append('<tr style="border-bottom:1px solid #30363d;">')
            for i, cell in enumerate(row):
                cell_style = "padding:10px 12px;color:#c9d1d9;"
                # Apply risk coloring if this is the highlight column
                if highlight_col is not None and i == highlight_col:
                    cell_str = str(cell)
                    if "Critical" in cell_str:
                        cell_style += "color:#f85149;font-weight:600;"
                    elif "High" in cell_str:
                        cell_style += "color:#f85149;font-weight:600;"
                    elif "Medium" in cell_str:
                        cell_style += "color:#d29922;font-weight:600;"
                    elif "Low" in cell_str:
                        cell_style += "color:#3fb950;font-weight:600;"
                html.append(f'<td style="{cell_style}">{cell}</td>')
            html.append('</tr>')
        html.append('</tbody></table>')

        return "\n".join(html)

    @staticmethod
    def format_bullet_list(items: List[str]) -> str:
        """Format an HTML bullet list."""
        if not items:
            return ""
        html = ['<ul style="margin:8px 0 16px 24px;padding:0;">']
        for item in items:
            html.append(f'<li style="color:#c9d1d9;line-height:1.8;margin-bottom:6px;">{item}</li>')
        html.append('</ul>')
        return "\n".join(html)

    @staticmethod
    def info_row(label: str, value: str, risk: str = None) -> str:
        """Generate a styled info row."""
        risk_html = ""
        if risk:
            risk_html = f' {ReportSection.risk_badge(risk)}'
        return f'<p style="margin:6px 0;color:#c9d1d9;"><strong style="color:#7d8590;">{label}:</strong> {value}{risk_html}</p>'


class M365TemplatedReport(ReportSection):
    """Python-templated Microsoft 365 assessment report generator (HTML output)."""

    def generate(self, standalone: bool = True) -> str:
        """Generate complete M365 assessment report as HTML.

        Args:
            standalone: If True, wrap in full HTML document with styling.
                       If False, return just the body content (for web UI embedding).
        """
        sections = [
            self._header(),
            self._section_1_executive_summary(),
            self._section_2_licensing(),
            self._section_3_identity_access(),
            self._section_4_secure_score(),
            self._section_5_user_account_health(),
            self._section_6_device_management(),
            self._section_7_recommendations(),
            self._section_8_conclusion()
        ]

        body_content = "\n\n".join([s for s in sections if s])

        if not standalone:
            return body_content

        # Wrap in full HTML document with dark theme
        metadata = self.assessment_data.get("metadata", {})
        client_name = metadata.get('clientName', 'Unknown')

        return f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>M365 Assessment - {client_name}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background: #0a0b0e;
            color: #c9d1d9;
            line-height: 1.6;
            padding: 40px;
            max-width: 1200px;
            margin: 0 auto;
        }}
        a {{ color: #039be5; text-decoration: none; }}
        a:hover {{ text-decoration: underline; }}
        code {{
            background: #1c2128;
            border: 1px solid #30363d;
            padding: 2px 6px;
            border-radius: 4px;
            font-size: 0.85em;
            color: #f0883e;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 12px 0;
            font-size: 0.85rem;
        }}
        th {{
            background: #161b22;
            color: #7d8590;
            text-align: left;
            padding: 10px 12px;
            border-bottom: 2px solid #30363d;
            font-weight: 600;
        }}
        td {{
            padding: 10px 12px;
            border-bottom: 1px solid #30363d;
            color: #c9d1d9;
        }}
        tr:hover td {{
            background: rgba(88, 166, 255, 0.06);
        }}
        @media print {{
            body {{
                background: #fff;
                color: #1a1a1a;
                padding: 20px;
            }}
            h1, h2, h3 {{ color: #1a1a1a !important; }}
            p, li, td {{ color: #333 !important; }}
            th {{ background: #f0f0f0 !important; color: #333 !important; }}
            div[style*="background:#161b22"], div[style*="background:#0d1117"] {{
                background: #f5f5f5 !important;
                border-color: #ddd !important;
            }}
        }}
    </style>
</head>
<body>
{body_content}
</body>
</html>'''

    def _header(self) -> str:
        """Generate report header."""
        metadata = self.assessment_data.get("metadata", {})

        return f'''<h1 style="color:#fff;font-size:1.6rem;margin:0 0 16px;border-bottom:2px solid #7b1fa2;padding-bottom:12px;">Microsoft 365 Assessment Report</h1>

<div style="background:#161b22;border:1px solid #30363d;border-radius:8px;padding:16px 20px;margin-bottom:20px;">
    <p style="margin:4px 0;color:#c9d1d9;"><strong style="color:#039be5;">Client:</strong> {metadata.get('clientName', 'Unknown')}</p>
    <p style="margin:4px 0;color:#c9d1d9;"><strong style="color:#039be5;">Tenant:</strong> {metadata.get('tenantName', 'Unknown')}</p>
    <p style="margin:4px 0;color:#c9d1d9;"><strong style="color:#039be5;">Primary Domain:</strong> {metadata.get('primaryDomain', 'Unknown')}</p>
    <p style="margin:4px 0;color:#c9d1d9;"><strong style="color:#039be5;">Assessment Date:</strong> {metadata.get('assessmentDate', 'Unknown')}</p>
</div>'''

    def _section_1_executive_summary(self) -> str:
        """Generate executive summary with risk assessment."""
        data = self.assessment_data
        licensing = data.get("licensing", {})
        identity = data.get("identity", {})
        security_score = data.get("securityScore", {})

        # Calculate key metrics
        total_users = int(licensing.get("totalUsers", 0) or 0)
        mfa_pct = identity.get("mfaStatus", {}).get("percentage", 0)
        secure_score_pct = security_score.get("percentage", 0)
        global_admins = identity.get("privilegedAccess", {}).get("globalAdminCount", 0)

        # Risk assessments
        mfa_risk, mfa_rec = self._assess_mfa_risk(
            mfa_pct,
            identity.get("mfaEnforcement", {}).get("enforcementMethod", "None detected")
        )
        score_risk = self._assess_secure_score_risk(secure_score_pct)
        admin_risk, admin_rec = self._assess_global_admin_risk(global_admins, total_users)

        # Overall risk (highest of the three)
        risk_levels = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
        overall_risk = max([mfa_risk, score_risk, admin_risk], key=lambda x: risk_levels.get(x, 0))

        # Build findings table
        findings_table = self.format_table(
            ["Area", "Status", "Risk Level"],
            [
                ["MFA Registration", f"{mfa_pct}% registered", mfa_risk],
                ["Microsoft Secure Score", f"{secure_score_pct}%", score_risk],
                ["Privileged Access", f"{global_admins} Global Admins", admin_risk]
            ],
            highlight_col=2
        )

        return f'''<h2 style="color:#fff;font-size:1.25rem;margin:24px 0 16px;padding-bottom:8px;border-bottom:1px solid #30363d;">1. Executive Summary</h2>

<div style="background:rgba(248, 81, 73, 0.1);border:1px solid #f85149;border-radius:8px;padding:16px 20px;margin-bottom:16px;">
    <p style="margin:0;color:#fff;font-size:1.1rem;"><strong>Overall Security Posture:</strong> {self.risk_badge(overall_risk)} Risk</p>
</div>

<div style="display:flex;gap:20px;margin-bottom:16px;flex-wrap:wrap;">
    <div style="background:#161b22;border:1px solid #30363d;border-radius:6px;padding:12px 16px;flex:1;min-width:120px;text-align:center;">
        <p style="margin:0;color:#7d8590;font-size:0.8rem;">Total Users</p>
        <p style="margin:4px 0 0;color:#fff;font-size:1.4rem;font-weight:600;">{total_users:,}</p>
    </div>
    <div style="background:#161b22;border:1px solid #30363d;border-radius:6px;padding:12px 16px;flex:1;min-width:120px;text-align:center;">
        <p style="margin:0;color:#7d8590;font-size:0.8rem;">Licensed Users</p>
        <p style="margin:4px 0 0;color:#fff;font-size:1.4rem;font-weight:600;">{licensing.get('licensedUsers', 0):,}</p>
    </div>
    <div style="background:#161b22;border:1px solid #30363d;border-radius:6px;padding:12px 16px;flex:1;min-width:120px;text-align:center;">
        <p style="margin:0;color:#7d8590;font-size:0.8rem;">Guest Users</p>
        <p style="margin:4px 0 0;color:#fff;font-size:1.4rem;font-weight:600;">{licensing.get('guestUsers', 0):,}</p>
    </div>
</div>

<h3 style="color:#bc8cff;font-size:1rem;margin:20px 0 12px;">Key Findings</h3>
{findings_table}

<h3 style="color:#bc8cff;font-size:1rem;margin:20px 0 12px;">Top Priorities</h3>
<ol style="margin:8px 0 16px 24px;padding:0;">
    <li style="color:#c9d1d9;line-height:1.8;margin-bottom:8px;"><strong style="color:#039be5;">MFA:</strong> {mfa_rec}</li>
    <li style="color:#c9d1d9;line-height:1.8;margin-bottom:8px;"><strong style="color:#039be5;">Privileged Access:</strong> {admin_rec}</li>
    <li style="color:#c9d1d9;line-height:1.8;margin-bottom:8px;"><strong style="color:#039be5;">Security Score:</strong> Improve score from current {secure_score_pct}% by implementing top recommendations</li>
</ol>

<h3 style="color:#bc8cff;font-size:1rem;margin:20px 0 12px;">Assessment Scope</h3>
<ul style="margin:8px 0 16px 24px;padding:0;">
    <li style="color:#c9d1d9;line-height:1.8;margin-bottom:4px;">Identity & Access Management (MFA, Conditional Access, privileged accounts)</li>
    <li style="color:#c9d1d9;line-height:1.8;margin-bottom:4px;">Microsoft Secure Score & security recommendations</li>
    <li style="color:#c9d1d9;line-height:1.8;margin-bottom:4px;">Device management via Microsoft Intune</li>
    <li style="color:#c9d1d9;line-height:1.8;margin-bottom:4px;">License utilization & waste detection</li>
    <li style="color:#c9d1d9;line-height:1.8;margin-bottom:4px;">User account hygiene (stale accounts, guest access)</li>
    <li style="color:#c9d1d9;line-height:1.8;margin-bottom:4px;">Security test results (Maester framework)</li>
</ul>'''

    def _section_2_licensing(self) -> str:
        """Generate licensing overview section."""
        licensing = self.assessment_data.get("licensing", {})
        skus = licensing.get("subscribedSkus", [])

        # Filter out free/trial licenses
        free_license_patterns = [
            "FREE", "FLOW_FREE", "POWER_BI_STANDARD", "POWER_AUTOMATE_FREE",
            "POWERAPPS_VIRAL", "TEAMS_EXPLORATORY", "RIGHTSMANAGEMENT_ADHOC",
            "WINDOWS_STORE", "STREAM", "MICROSOFT_BUSINESS_CENTER",
            "CCIBOTS_PRIVPREV_VIRAL", "FORMS_PRO", "PROJECT_MADEIRA_PREVIEW_IW",
            "CDS_O365_P1", "CDS_O365_P2", "CDS_O365_P3", "PBI_AZURE_UNAVAILABLE"
        ]
        paid_skus = [s for s in skus if not any(
            pattern in (s.get('skuPartNumber', '') or '').upper()
            for pattern in free_license_patterns
        )]

        if not paid_skus:
            return '''<h2 style="color:#fff;font-size:1.25rem;margin:24px 0 16px;padding-bottom:8px;border-bottom:1px solid #30363d;">2. Licensing Overview</h2>
<p style="color:#7d8590;">No paid license information available.</p>'''

        # Build license table
        license_rows = []
        total_assigned = 0
        total_available = 0

        for sku in paid_skus[:15]:  # Limit to top 15
            sku_name = sku.get('skuPartNumber', 'Unknown')
            consumed = sku.get('consumedUnits', 0)
            prepaid = sku.get('prepaidUnits', 0)
            utilization = round((consumed / prepaid) * 100, 1) if prepaid > 0 else 0

            # Color code utilization
            if utilization > 95:
                util_color = "#f85149"
            elif utilization > 85:
                util_color = "#d29922"
            elif utilization < 50:
                util_color = "#039be5"
            else:
                util_color = "#3fb950"

            license_rows.append([
                f'<code style="background:#1c2128;padding:2px 6px;border-radius:3px;color:#f0883e;">{sku_name}</code>',
                str(consumed),
                str(prepaid),
                f'<span style="color:{util_color};font-weight:600;">{utilization}%</span>'
            ])
            total_assigned += consumed
            total_available += prepaid

        license_table = self.format_table(
            ["License SKU", "Assigned", "Available", "Utilization"],
            license_rows
        )

        overall_utilization = round((total_assigned / total_available) * 100, 1) if total_available > 0 else 0

        # Utilization assessment
        if overall_utilization > 95:
            util_status = f'{self.risk_badge("High")} License capacity nearly exhausted, consider purchasing more'
        elif overall_utilization > 85:
            util_status = f'{self.risk_badge("Medium")} License utilization high, monitor closely'
        elif overall_utilization < 50:
            util_status = f'{self.risk_badge("Low")} Underutilized licenses, consider reducing for cost optimization'
        else:
            util_status = f'{self.risk_badge("Low")} License utilization healthy'

        return f'''<h2 style="color:#fff;font-size:1.25rem;margin:24px 0 16px;padding-bottom:8px;border-bottom:1px solid #30363d;">2. Licensing Overview</h2>

<h3 style="color:#bc8cff;font-size:1rem;margin:16px 0 12px;">Subscribed Licenses (Paid Only)</h3>
{license_table}

<div style="background:#161b22;border:1px solid #30363d;border-radius:6px;padding:12px 16px;margin:16px 0;">
    <p style="margin:0 0 8px;color:#c9d1d9;"><strong>Total:</strong> {total_assigned:,} assigned / {total_available:,} available ({overall_utilization}% utilization)</p>
    <p style="margin:0;color:#c9d1d9;"><strong>Status:</strong> {util_status}</p>
</div>

<h3 style="color:#bc8cff;font-size:1rem;margin:20px 0 12px;">License SKU Reference</h3>
<div style="background:#0d1117;border:1px solid #30363d;border-radius:6px;padding:12px 16px;font-size:0.85rem;">
    <p style="margin:4px 0;color:#7d8590;"><code style="color:#f0883e;">SPB</code> = Microsoft 365 Business Premium</p>
    <p style="margin:4px 0;color:#7d8590;"><code style="color:#f0883e;">O365_BUSINESS_ESSENTIALS</code> = Microsoft 365 Business Basic</p>
    <p style="margin:4px 0;color:#7d8590;"><code style="color:#f0883e;">O365_BUSINESS_PREMIUM</code> = Microsoft 365 Business Standard</p>
    <p style="margin:4px 0;color:#7d8590;"><code style="color:#f0883e;">SPE_E3</code> = Microsoft 365 E3</p>
    <p style="margin:4px 0;color:#7d8590;"><code style="color:#f0883e;">SPE_E5</code> = Microsoft 365 E5</p>
    <p style="margin:4px 0;color:#7d8590;"><code style="color:#f0883e;">SPE_A3 / M365EDU_A3</code> = Microsoft 365 A3 (Education)</p>
    <p style="margin:4px 0;color:#7d8590;"><code style="color:#f0883e;">ENTERPRISEPACK</code> = Office 365 E3</p>
    <p style="margin:4px 0;color:#7d8590;"><code style="color:#f0883e;">AAD_PREMIUM_P1 / P2</code> = Entra ID P1 / P2</p>
    <p style="margin:4px 0;color:#7d8590;"><code style="color:#f0883e;">INTUNE_A</code> = Microsoft Intune</p>
</div>'''

    def _section_3_identity_access(self) -> str:
        """Generate Identity & Access Management section."""
        identity = self.assessment_data.get("identity", {})
        governance = self.assessment_data.get("governance", {})

        sections = []

        # MFA Status
        mfa_section = self._build_mfa_subsection(identity)
        if mfa_section:
            sections.append(mfa_section)

        # Conditional Access
        ca_section = self._build_conditional_access_subsection(identity)
        if ca_section:
            sections.append(ca_section)

        # Privileged Access
        priv_section = self._build_privileged_access_subsection(identity, governance)
        if priv_section:
            sections.append(priv_section)

        if not sections:
            return ""

        return f'''<h2 style="color:#fff;font-size:1.25rem;margin:24px 0 16px;padding-bottom:8px;border-bottom:1px solid #30363d;">3. Identity & Access Management</h2>

{"".join(sections)}'''

    def _build_mfa_subsection(self, identity: dict) -> str:
        """Build MFA status subsection."""
        mfa_status = identity.get("mfaStatus", {})
        mfa_enforcement = identity.get("mfaEnforcement", {})

        if not mfa_status:
            return ""

        total = mfa_status.get("total", 0)
        registered = mfa_status.get("registered", 0)
        pct = mfa_status.get("percentage", 0)
        enforcement_method = mfa_enforcement.get("enforcementMethod", "None detected")

        risk, rec = self._assess_mfa_risk(pct, enforcement_method)

        # Gap analysis
        if pct >= 80 and enforcement_method in ["Security Defaults", "Conditional Access (all users)"]:
            gap_icon = "✅"
            gap_status = "Good - High registration + strong enforcement"
            gap_color = "#3fb950"
        elif pct >= 80 and enforcement_method == "Conditional Access (partial)":
            gap_icon = "⚠️"
            gap_status = "Medium - Users ready but enforcement incomplete"
            gap_color = "#d29922"
        elif pct < 80 and enforcement_method in ["Security Defaults", "Conditional Access (all users)"]:
            gap_icon = "⚠️"
            gap_status = "Medium - Strong enforcement will prompt registration at next sign-in"
            gap_color = "#d29922"
        else:
            gap_icon = "❌"
            gap_status = "Critical Gap - Low registration and weak enforcement"
            gap_color = "#f85149"

        # Policy details
        policy_html = ""
        if enforcement_method == "Conditional Access (partial)":
            policies = mfa_enforcement.get("policies", [])
            if policies:
                policy_html = '<div style="margin-top:12px;"><p style="color:#7d8590;font-size:0.9rem;margin-bottom:8px;"><strong>MFA-Requiring Policies:</strong></p><ul style="margin:0 0 0 20px;">'
                for policy in policies[:5]:
                    policy_html += f'<li style="color:#c9d1d9;font-size:0.85rem;">{policy.get("displayName", "Unknown")}: {policy.get("userScope", "Unknown")} / {policy.get("appScope", "Unknown")}</li>'
                policy_html += '</ul></div>'

        return f'''<h3 style="color:#bc8cff;font-size:1rem;margin:20px 0 12px;">MFA Status</h3>
<div style="background:#161b22;border:1px solid #30363d;border-radius:8px;padding:16px 20px;margin-bottom:16px;">
    {self.info_row("Registration", f"{registered:,} / {total:,} users ({pct}%) have registered an MFA method")}
    {self.info_row("Enforcement Method", enforcement_method)}
    <p style="margin:8px 0;color:#c9d1d9;"><strong style="color:#7d8590;">Gap Analysis:</strong> <span style="color:{gap_color};">{gap_icon} {gap_status}</span></p>
    {self.info_row("Risk Level", "", risk)}
    {self.info_row("Recommendation", rec)}
    {policy_html}
</div>'''

    def _build_conditional_access_subsection(self, identity: dict) -> str:
        """Build Conditional Access subsection."""
        ca_policies = identity.get("conditionalAccess", [])

        if not ca_policies:
            return '''<h3 style="color:#bc8cff;font-size:1rem;margin:20px 0 12px;">Conditional Access</h3>
<div style="background:#161b22;border:1px solid #30363d;border-radius:8px;padding:16px 20px;margin-bottom:16px;">
    <p style="color:#f85149;"><strong>⚠️ No Conditional Access policies found.</strong></p>
    <p style="color:#7d8590;font-size:0.9rem;margin-top:8px;">Conditional Access is essential for Zero Trust security. Consider implementing policies for MFA enforcement, device compliance, and location-based access.</p>
</div>'''

        enabled = [p for p in ca_policies if p.get("state") == "enabled"]
        enabled_count = len(enabled)
        total_count = len(ca_policies)

        # Risk assessment
        if enabled_count == 0:
            risk = "Critical"
            rec = "Implement Conditional Access policies immediately for zero trust security"
        elif enabled_count < 3:
            risk = "High"
            rec = "Expand CA policy coverage - minimum 5 policies recommended"
        elif enabled_count < 5:
            risk = "Medium"
            rec = "Good coverage, consider adding more granular policies"
        else:
            risk = "Low"
            rec = "Strong CA policy coverage, continue monitoring and updating"

        return f'''<h3 style="color:#bc8cff;font-size:1rem;margin:20px 0 12px;">Conditional Access</h3>
<div style="background:#161b22;border:1px solid #30363d;border-radius:8px;padding:16px 20px;margin-bottom:16px;">
    {self.info_row("Total Policies", str(total_count))}
    {self.info_row("Enabled Policies", str(enabled_count))}
    {self.info_row("Risk Level", "", risk)}
    {self.info_row("Recommendation", rec)}
    <p style="margin-top:12px;padding:10px;background:#0d1117;border-radius:4px;color:#7d8590;font-size:0.85rem;">
        <strong style="color:#039be5;">Best Practice:</strong> Minimum 5 CA policies recommended covering MFA, device compliance, location-based access, high-risk sign-ins, and privileged accounts.
    </p>
</div>'''

    def _build_privileged_access_subsection(self, identity: dict, governance: dict) -> str:
        """Build privileged access subsection."""
        priv_access = identity.get("privilegedAccess", {})
        global_admins = priv_access.get("globalAdminCount", 0)
        active_roles = priv_access.get("directoryRolesActive", 0)

        total_users = int(self.assessment_data.get("licensing", {}).get("totalUsers", 0) or 0)
        risk, rec = self._assess_global_admin_risk(global_admins, total_users)

        # Admin roles
        admin_roles = governance.get("adminRoles", [])
        roles_html = ""
        if admin_roles:
            roles_html = '<div style="margin-top:12px;"><p style="color:#7d8590;font-size:0.9rem;margin-bottom:8px;"><strong>Top Admin Roles:</strong></p>'
            roles_html += '<div style="display:flex;flex-wrap:wrap;gap:8px;">'
            for role in sorted(admin_roles, key=lambda x: -x.get('memberCount', 0))[:8]:
                roles_html += f'<span style="background:#0d1117;border:1px solid #30363d;padding:4px 10px;border-radius:4px;font-size:0.8rem;color:#c9d1d9;">{role.get("roleName", "Unknown")}: <strong style="color:#039be5;">{role.get("memberCount", 0)}</strong></span>'
            roles_html += '</div></div>'

        return f'''<h3 style="color:#bc8cff;font-size:1rem;margin:20px 0 12px;">Privileged Access</h3>
<div style="background:#161b22;border:1px solid #30363d;border-radius:8px;padding:16px 20px;margin-bottom:16px;">
    {self.info_row("Global Administrators", str(global_admins))}
    {self.info_row("Active Directory Roles", str(active_roles))}
    {self.info_row("Risk Level", "", risk)}
    {self.info_row("Recommendation", rec)}
    {roles_html}
</div>'''

    def _section_4_secure_score(self) -> str:
        """Generate Microsoft Secure Score section."""
        security_score = self.assessment_data.get("securityScore", {})

        current = security_score.get("currentScore", 0)
        maximum = security_score.get("maxScore", 0)
        pct = security_score.get("percentage", 0)
        identity_pct = security_score.get("identityScore", {}).get("percentage", 0)

        risk = self._assess_secure_score_risk(pct)

        # Score gauge color
        if pct >= 80:
            gauge_color = "#3fb950"
            assessment = "✅ Excellent security posture"
        elif pct >= 60:
            gauge_color = "#039be5"
            assessment = "✅ Good security posture, room for improvement"
        elif pct >= 40:
            gauge_color = "#d29922"
            assessment = "⚠️ Below average security posture, prioritize improvements"
        else:
            gauge_color = "#f85149"
            assessment = "❌ Poor security posture, immediate action required"

        recommendations = security_score.get("recommendations", [])[:10]
        rec_html = ""
        if recommendations:
            rec_html = '<h3 style="color:#bc8cff;font-size:1rem;margin:20px 0 12px;">Top 10 Security Recommendations</h3><ol style="margin:0 0 0 24px;padding:0;">'
            for rec in recommendations:
                title = rec.get("title", "Unknown")
                max_score = rec.get("maxScore", 0)
                rec_html += f'<li style="color:#c9d1d9;line-height:1.8;margin-bottom:6px;"><strong>{title}</strong> <span style="color:#3fb950;font-size:0.85rem;">(+{max_score} points)</span></li>'
            rec_html += '</ol>'

        return f'''<h2 style="color:#fff;font-size:1.25rem;margin:24px 0 16px;padding-bottom:8px;border-bottom:1px solid #30363d;">4. Microsoft Secure Score</h2>

<div style="display:flex;gap:20px;margin-bottom:16px;flex-wrap:wrap;">
    <div style="background:#161b22;border:1px solid #30363d;border-radius:8px;padding:20px;flex:1;min-width:200px;text-align:center;">
        <p style="margin:0;color:#7d8590;font-size:0.85rem;">Current Score</p>
        <p style="margin:8px 0 4px;font-size:2rem;font-weight:700;color:{gauge_color};">{pct}%</p>
        <p style="margin:0;color:#7d8590;font-size:0.85rem;">{current} / {maximum} points</p>
    </div>
    <div style="background:#161b22;border:1px solid #30363d;border-radius:8px;padding:20px;flex:1;min-width:200px;text-align:center;">
        <p style="margin:0;color:#7d8590;font-size:0.85rem;">Identity Score</p>
        <p style="margin:8px 0 4px;font-size:2rem;font-weight:700;color:#039be5;">{identity_pct}%</p>
        <p style="margin:0;color:#7d8590;font-size:0.85rem;">Identity pillar</p>
    </div>
    <div style="background:#161b22;border:1px solid #30363d;border-radius:8px;padding:20px;flex:1;min-width:200px;text-align:center;">
        <p style="margin:0;color:#7d8590;font-size:0.85rem;">Risk Level</p>
        <p style="margin:12px 0;">{self.risk_badge(risk)}</p>
    </div>
</div>

<div style="background:#0d1117;border:1px solid #30363d;border-radius:6px;padding:12px 16px;margin-bottom:16px;">
    <p style="margin:0;color:#c9d1d9;">{assessment}</p>
</div>

{rec_html}'''

    def _section_5_user_account_health(self) -> str:
        """Generate User Account Health section."""
        insights = self.assessment_data.get("userInsights", {})
        licensing = self.assessment_data.get("licensing", {})
        total_users = int(licensing.get("totalUsers", 1) or 1)

        # Adjust detail level based on tenant size
        if total_users < 100:
            max_stale_users = 10
            max_domains = 5
        elif total_users < 1000:
            max_stale_users = 8
            max_domains = 5
        else:
            max_stale_users = 5
            max_domains = 3

        sections = []

        # Stale Accounts
        stale = insights.get("staleAccounts", {})
        if stale and stale.get("totalAnalysed", 0) > 0:
            stale_90 = stale.get("stale90Days", 0)
            stale_180 = stale.get("stale180Days", 0)
            stale_365 = stale.get("stale365Days", 0)
            never = stale.get("neverSignedIn", 0)
            analysed = stale.get("totalAnalysed", 0)
            stale_pct = round((stale_90 / analysed) * 100, 1) if analysed > 0 else 0

            # Risk assessment
            if stale_pct > 30:
                risk = "Critical"
                recommendation = "Urgent cleanup required - over 30% of accounts are stale"
            elif stale_pct > 20:
                risk = "High"
                recommendation = "Immediate review needed - significant number of stale accounts"
            elif stale_pct > 10:
                risk = "Medium"
                recommendation = "Schedule quarterly access review"
            else:
                risk = "Low"
                recommendation = "Continue regular access reviews"

            stale_users_html = ""
            top_stale = stale.get("topStaleWithLicenses", [])
            if top_stale:
                stale_users_html = '<div style="margin-top:12px;"><p style="color:#7d8590;font-size:0.9rem;margin-bottom:8px;"><strong>Top stale accounts with licenses (priority for cleanup):</strong></p><div style="max-height:200px;overflow-y:auto;">'
                for user in top_stale[:max_stale_users]:
                    stale_users_html += f'<p style="margin:4px 0;padding:6px 10px;background:#0d1117;border-radius:4px;font-size:0.85rem;color:#c9d1d9;">{user.get("displayName", "Unknown")} <span style="color:#7d8590;">- Last: {user.get("lastSignIn", "Never")}, Licenses: {user.get("licenseCount", 0)}</span></p>'
                stale_users_html += '</div></div>'

            sections.append(f'''<h3 style="color:#bc8cff;font-size:1rem;margin:20px 0 12px;">Stale Accounts</h3>
<div style="background:#161b22;border:1px solid #30363d;border-radius:8px;padding:16px 20px;margin-bottom:16px;">
    {self.info_row("90+ days inactive", f"{stale_90} users ({stale_pct}% of workforce)")}
    {self.info_row("Breakdown", f"180+ days: {stale_180} | 365+ days: {stale_365} | Never signed in: {never}")}
    {self.info_row("Risk Level", "", risk)}
    {self.info_row("Recommendation", recommendation)}
    {stale_users_html}
</div>''')

        # MFA Method Analysis
        mfa = insights.get("mfaDetails", {})
        if mfa and mfa.get("registered", 0) > 0:
            capable = mfa.get("capable", 0)
            registered = mfa.get("registered", 0)
            sms_only = mfa.get("smsOnly", 0)
            passwordless = mfa.get("passwordless", 0)

            # Risk assessment for SMS-only
            if sms_only > 0:
                sms_pct = round((sms_only / registered) * 100, 1) if registered > 0 else 0
                if sms_pct > 30:
                    mfa_risk = "High"
                    mfa_rec = "Migrate users from SMS to authenticator app - SMS is vulnerable to SIM swapping"
                elif sms_pct > 10:
                    mfa_risk = "Medium"
                    mfa_rec = "Plan phased migration from SMS to stronger MFA methods"
                else:
                    mfa_risk = "Low"
                    mfa_rec = "Continue encouraging stronger MFA methods"
            else:
                mfa_risk = "Low"
                mfa_rec = "No SMS-only users detected"

            methods_html = ""
            methods = mfa.get("methodBreakdown", [])
            if methods:
                methods_html = '<div style="margin-top:12px;display:flex;flex-wrap:wrap;gap:8px;">'
                for method in methods[:8]:
                    methods_html += f'<span style="background:#0d1117;border:1px solid #30363d;padding:4px 10px;border-radius:4px;font-size:0.8rem;color:#c9d1d9;">{method.get("method", "Unknown")}: <strong style="color:#039be5;">{method.get("count", 0)}</strong></span>'
                methods_html += '</div>'

            sections.append(f'''<h3 style="color:#bc8cff;font-size:1rem;margin:20px 0 12px;">MFA Method Analysis</h3>
<div style="background:#161b22;border:1px solid #30363d;border-radius:8px;padding:16px 20px;margin-bottom:16px;">
    {self.info_row("MFA Capable", f"{capable} users")}
    {self.info_row("MFA Registered", f"{registered} users")}
    {self.info_row("SMS-Only (weak MFA)", f"{sms_only} users")}
    {self.info_row("Passwordless Capable", f"{passwordless} users")}
    {self.info_row("Risk Level", "", mfa_risk)}
    {self.info_row("Recommendation", mfa_rec)}
    {methods_html}
</div>''')

        if not sections:
            return ""

        return f'''<h2 style="color:#fff;font-size:1.25rem;margin:24px 0 16px;padding-bottom:8px;border-bottom:1px solid #30363d;">5. User Account Health</h2>

{"".join(sections)}'''

    def _section_6_device_management(self) -> str:
        """Generate Device Management (Intune) section."""
        intune = self.assessment_data.get("intune", {})
        devices = intune.get("managedDevices", {})

        if not devices or devices.get("total", 0) == 0:
            return '''<h2 style="color:#fff;font-size:1.25rem;margin:24px 0 16px;padding-bottom:8px;border-bottom:1px solid #30363d;">6. Device Management (Intune)</h2>
<div style="background:#161b22;border:1px solid #30363d;border-radius:8px;padding:16px 20px;">
    <p style="color:#7d8590;">Intune data not available (license may be required).</p>
</div>'''

        total = devices.get("total", 0)
        compliant = devices.get("compliant", 0)
        non_compliant = devices.get("nonCompliant", 0)
        compliance_rate = devices.get("complianceRate", 0)

        # Risk assessment
        if compliance_rate < 70:
            risk = "Critical"
            rec = f"Only {compliance_rate}% compliant - immediate remediation required"
        elif compliance_rate < 85:
            risk = "High"
            rec = "Below best practice compliance rate of 95%"
        elif compliance_rate < 95:
            risk = "Medium"
            rec = "Good compliance, target 95%+ for best practice"
        else:
            risk = "Low"
            rec = "Excellent device compliance"

        # Gauge color
        if compliance_rate >= 95:
            gauge_color = "#3fb950"
        elif compliance_rate >= 85:
            gauge_color = "#039be5"
        elif compliance_rate >= 70:
            gauge_color = "#d29922"
        else:
            gauge_color = "#f85149"

        compliance_policies = intune.get("compliancePolicies", [])
        config_profiles = intune.get("configurationProfiles", [])
        app_protection = intune.get("appProtectionPolicies", [])

        return f'''<h2 style="color:#fff;font-size:1.25rem;margin:24px 0 16px;padding-bottom:8px;border-bottom:1px solid #30363d;">6. Device Management (Intune)</h2>

<div style="display:flex;gap:20px;margin-bottom:16px;flex-wrap:wrap;">
    <div style="background:#161b22;border:1px solid #30363d;border-radius:8px;padding:20px;flex:1;min-width:150px;text-align:center;">
        <p style="margin:0;color:#7d8590;font-size:0.85rem;">Total Devices</p>
        <p style="margin:8px 0;font-size:1.8rem;font-weight:700;color:#fff;">{total:,}</p>
    </div>
    <div style="background:#161b22;border:1px solid #30363d;border-radius:8px;padding:20px;flex:1;min-width:150px;text-align:center;">
        <p style="margin:0;color:#7d8590;font-size:0.85rem;">Compliance Rate</p>
        <p style="margin:8px 0;font-size:1.8rem;font-weight:700;color:{gauge_color};">{compliance_rate}%</p>
    </div>
    <div style="background:#161b22;border:1px solid #30363d;border-radius:8px;padding:20px;flex:1;min-width:150px;text-align:center;">
        <p style="margin:0;color:#7d8590;font-size:0.85rem;">Non-Compliant</p>
        <p style="margin:8px 0;font-size:1.8rem;font-weight:700;color:#f85149;">{non_compliant:,}</p>
    </div>
</div>

<div style="background:#161b22;border:1px solid #30363d;border-radius:8px;padding:16px 20px;margin-bottom:16px;">
    {self.info_row("Risk Level", "", risk)}
    {self.info_row("Recommendation", rec)}
</div>

<h3 style="color:#bc8cff;font-size:1rem;margin:16px 0 12px;">Policies & Profiles</h3>
<div style="display:flex;gap:12px;flex-wrap:wrap;">
    <div style="background:#0d1117;border:1px solid #30363d;border-radius:6px;padding:10px 16px;text-align:center;">
        <p style="margin:0;color:#7d8590;font-size:0.8rem;">Compliance Policies</p>
        <p style="margin:4px 0 0;color:#039be5;font-size:1.2rem;font-weight:600;">{len(compliance_policies)}</p>
    </div>
    <div style="background:#0d1117;border:1px solid #30363d;border-radius:6px;padding:10px 16px;text-align:center;">
        <p style="margin:0;color:#7d8590;font-size:0.8rem;">Config Profiles</p>
        <p style="margin:4px 0 0;color:#039be5;font-size:1.2rem;font-weight:600;">{len(config_profiles)}</p>
    </div>
    <div style="background:#0d1117;border:1px solid #30363d;border-radius:6px;padding:10px 16px;text-align:center;">
        <p style="margin:0;color:#7d8590;font-size:0.8rem;">App Protection</p>
        <p style="margin:4px 0 0;color:#039be5;font-size:1.2rem;font-weight:600;">{len(app_protection)}</p>
    </div>
</div>'''

    def _section_7_recommendations(self) -> str:
        """Generate Project Recommendations section."""
        # Gather all risks from previous sections
        immediate = []
        short_term = []
        strategic = []

        # Analyze and categorize based on data
        data = self.assessment_data
        identity = data.get("identity", {})
        security_score = data.get("securityScore", {})
        insights = data.get("userInsights", {})

        # MFA issues
        mfa_pct = identity.get("mfaStatus", {}).get("percentage", 0)
        enforcement = identity.get("mfaEnforcement", {}).get("enforcementMethod", "None detected")
        if mfa_pct < 80 or enforcement == "None detected":
            immediate.append("Implement MFA enforcement via Conditional Access policies covering all users and applications")

        # Secure Score
        score_pct = security_score.get("percentage", 0)
        if score_pct < 60:
            immediate.append(f"Improve Secure Score from {score_pct}% by implementing top 5 recommendations")

        # Global Admins
        total_users = int(data.get("licensing", {}).get("totalUsers", 0) or 0)
        global_admins = identity.get("privilegedAccess", {}).get("globalAdminCount", 0)
        if global_admins > 5 or (total_users > 0 and (global_admins / total_users) > 0.05):
            immediate.append(f"Reduce Global Admin count from {global_admins} to 3-5 users maximum")

        # CA Policies
        ca_policies = identity.get("conditionalAccess", [])
        enabled_ca = [p for p in ca_policies if p.get("state") == "enabled"]
        if len(enabled_ca) < 5:
            short_term.append("Expand Conditional Access policies - implement minimum 5 policies covering MFA, device compliance, location-based access, high-risk sign-ins, and privileged accounts")

        # Stale accounts
        stale = insights.get("staleAccounts", {})
        if stale and stale.get("stale90Days", 0) > 0:
            stale_pct = round((stale.get("stale90Days", 0) / stale.get("totalAnalysed", 1)) * 100, 1)
            if stale_pct > 20:
                immediate.append(f"Cleanup stale accounts - {stale.get('stale90Days', 0)} users inactive 90+ days ({stale_pct}% of workforce)")

        # License waste
        waste = insights.get("licenseWaste", {})
        if waste and waste.get("estimatedMonthlyGBP", 0) > 500:
            monthly = waste.get("estimatedMonthlyGBP", 0)
            annual = monthly * 12
            immediate.append(f"Reclaim wasted licenses - £{monthly:,.2f}/month waste identified (potential annual savings: £{annual:,.2f})")

        # Intune
        intune = data.get("intune", {})
        devices = intune.get("managedDevices", {})
        if devices.get("complianceRate", 0) < 85:
            short_term.append(f"Improve device compliance - current rate {devices.get('complianceRate', 0)}%, target 95%+")

        # Strategic recommendations
        strategic.append("Implement Zero Trust architecture - layered security with identity verification, device compliance, and least-privilege access")
        strategic.append("Deploy Microsoft Defender for Endpoint - advanced threat protection and EDR capabilities")
        strategic.append("Establish Security Operations Center (SOC) - 24/7 monitoring and incident response")

        # Build section
        sections = []

        if immediate:
            items_html = "".join([f'<li style="color:#c9d1d9;line-height:1.8;margin-bottom:8px;">{item}</li>' for item in immediate])
            sections.append(f'''<h3 style="color:#f85149;font-size:1rem;margin:16px 0 12px;">🚨 Immediate Actions (0-30 days)</h3>
<ul style="margin:0 0 16px 24px;padding:0;">{items_html}</ul>''')

        if short_term:
            items_html = "".join([f'<li style="color:#c9d1d9;line-height:1.8;margin-bottom:8px;">{item}</li>' for item in short_term])
            sections.append(f'''<h3 style="color:#d29922;font-size:1rem;margin:16px 0 12px;">⚠️ Short-term Improvements (1-3 months)</h3>
<ul style="margin:0 0 16px 24px;padding:0;">{items_html}</ul>''')

        if strategic:
            items_html = "".join([f'<li style="color:#c9d1d9;line-height:1.8;margin-bottom:8px;">{item}</li>' for item in strategic])
            sections.append(f'''<h3 style="color:#039be5;font-size:1rem;margin:16px 0 12px;">🎯 Strategic Initiatives (3-12 months)</h3>
<ul style="margin:0 0 16px 24px;padding:0;">{items_html}</ul>''')

        return f'''<h2 style="color:#fff;font-size:1.25rem;margin:24px 0 16px;padding-bottom:8px;border-bottom:1px solid #30363d;">7. Project Recommendations</h2>

{"".join(sections)}'''

    def _section_8_conclusion(self) -> str:
        """Generate conclusion with top priorities."""
        # Determine top 3 priorities based on risk levels
        priorities = []

        data = self.assessment_data
        identity = data.get("identity", {})
        security_score = data.get("securityScore", {})

        # MFA
        mfa_pct = identity.get("mfaStatus", {}).get("percentage", 0)
        enforcement = identity.get("mfaEnforcement", {}).get("enforcementMethod", "None detected")
        mfa_risk, _ = self._assess_mfa_risk(mfa_pct, enforcement)
        if mfa_risk in ["Critical", "High"]:
            priorities.append(("MFA enforcement", mfa_risk))

        # Secure Score
        score_pct = security_score.get("percentage", 0)
        score_risk = self._assess_secure_score_risk(score_pct)
        if score_risk in ["Critical", "High"]:
            priorities.append(("Secure Score improvement", score_risk))

        # Global Admins
        total_users = int(data.get("licensing", {}).get("totalUsers", 0) or 0)
        global_admins = identity.get("privilegedAccess", {}).get("globalAdminCount", 0)
        admin_risk, _ = self._assess_global_admin_risk(global_admins, total_users)
        if admin_risk in ["Critical", "High"]:
            priorities.append(("Privileged access review", admin_risk))

        # Sort by risk level
        risk_order = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
        priorities.sort(key=lambda x: risk_order.get(x[1], 0), reverse=True)
        top_3 = priorities[:3]

        priority_html = ""
        if top_3:
            priority_html = '<h3 style="color:#bc8cff;font-size:1rem;margin:20px 0 12px;">Top 3 Priorities</h3><ol style="margin:0 0 16px 24px;padding:0;">'
            for area, risk in top_3:
                priority_html += f'<li style="color:#c9d1d9;line-height:1.8;margin-bottom:8px;"><strong>{area}</strong> {self.risk_badge(risk)}</li>'
            priority_html += '</ol>'

        assessment_date = self.assessment_data.get('metadata', {}).get('assessmentDate', 'Unknown')

        return f'''<h2 style="color:#fff;font-size:1.25rem;margin:24px 0 16px;padding-bottom:8px;border-bottom:1px solid #30363d;">8. Conclusion</h2>

<p style="color:#c9d1d9;line-height:1.8;margin-bottom:16px;">
    This assessment provides a comprehensive analysis of your Microsoft 365 tenant's security posture.
    The findings highlight both strengths and areas requiring attention.
</p>

{priority_html}

<h3 style="color:#bc8cff;font-size:1rem;margin:20px 0 12px;">Next Steps</h3>
<ol style="margin:0 0 16px 24px;padding:0;">
    <li style="color:#c9d1d9;line-height:1.8;margin-bottom:6px;"><strong>Review this report</strong> with your IT security team and key stakeholders</li>
    <li style="color:#c9d1d9;line-height:1.8;margin-bottom:6px;"><strong>Prioritize remediation</strong> based on risk levels and business impact</li>
    <li style="color:#c9d1d9;line-height:1.8;margin-bottom:6px;"><strong>Develop an action plan</strong> with timelines and resource allocation</li>
    <li style="color:#c9d1d9;line-height:1.8;margin-bottom:6px;"><strong>Schedule follow-up assessment</strong> in 3-6 months to measure progress</li>
</ol>

<h3 style="color:#bc8cff;font-size:1rem;margin:20px 0 12px;">MSP Support Opportunities</h3>
<div style="display:flex;flex-wrap:wrap;gap:12px;margin-bottom:20px;">
    <div style="background:#161b22;border:1px solid #30363d;border-radius:6px;padding:12px 16px;flex:1;min-width:200px;">
        <p style="margin:0 0 4px;color:#039be5;font-weight:600;">Project-based remediation</p>
        <p style="margin:0;color:#7d8590;font-size:0.85rem;">for immediate and short-term actions</p>
    </div>
    <div style="background:#161b22;border:1px solid #30363d;border-radius:6px;padding:12px 16px;flex:1;min-width:200px;">
        <p style="margin:0 0 4px;color:#039be5;font-weight:600;">Managed security services</p>
        <p style="margin:0;color:#7d8590;font-size:0.85rem;">for ongoing monitoring and compliance</p>
    </div>
    <div style="background:#161b22;border:1px solid #30363d;border-radius:6px;padding:12px 16px;flex:1;min-width:200px;">
        <p style="margin:0 0 4px;color:#039be5;font-weight:600;">License optimization</p>
        <p style="margin:0;color:#7d8590;font-size:0.85rem;">to reduce waste and improve utilization</p>
    </div>
    <div style="background:#161b22;border:1px solid #30363d;border-radius:6px;padding:12px 16px;flex:1;min-width:200px;">
        <p style="margin:0 0 4px;color:#039be5;font-weight:600;">Zero Trust implementation</p>
        <p style="margin:0;color:#7d8590;font-size:0.85rem;">for long-term security maturity</p>
    </div>
</div>

<hr style="border:none;border-top:1px solid #30363d;margin:24px 0;">

<p style="color:#7d8590;font-size:0.85rem;text-align:center;">
    <em>Report generated by AAG Technical Audit Tool</em><br>
    <em>Assessment date: {assessment_date}</em>
</p>'''

    # Risk assessment methods

    def _assess_mfa_risk(self, registered_pct: float, enforcement_method: str) -> Tuple[str, str]:
        """Assess MFA risk based on registration and enforcement."""
        if registered_pct < 50 and enforcement_method == "None detected":
            return "Critical", "Immediate MFA enforcement required - less than 50% registered and no enforcement"
        elif registered_pct < 80:
            return "High", "Increase MFA registration to 95%+ and strengthen enforcement"
        elif enforcement_method == "Conditional Access (partial)":
            return "Medium", "Expand CA policy coverage to all users and applications"
        elif enforcement_method == "None detected":
            return "High", "Enable MFA enforcement via Security Defaults or Conditional Access"
        else:
            return "Low", "Continue monitoring MFA adoption and enforcement"

    def _assess_secure_score_risk(self, percentage: float) -> str:
        """Assess Secure Score risk level."""
        if percentage < 40:
            return "Critical"
        elif percentage < 60:
            return "High"
        elif percentage < 80:
            return "Medium"
        else:
            return "Low"

    def _assess_global_admin_risk(self, count: int, total_users: int) -> Tuple[str, str]:
        """Assess Global Admin count risk."""
        ratio = count / total_users if total_users > 0 else 0

        if count == 0:
            return "High", "No Global Admins detected - at least 2 required for redundancy"
        elif count == 1:
            return "Medium", "Only 1 Global Admin - recommend 2-3 break-glass accounts for redundancy"
        elif count > 5 or ratio > 0.05:
            return "High", f"Too many Global Admins ({count}), recommend max 3-5 following least privilege principle"
        elif count > 3:
            return "Medium", "Consider reducing Global Admin count to 3 or fewer"
        else:
            return "Low", "Global Admin count follows best practices (2-3 admins)"


class NetworkTemplatedReport(ReportSection):
    """Python-templated Network Discovery report generator (HTML output).

    Takes nmap scan data and generates a structured security assessment report
    with risk analysis, findings categorization, and recommendations.
    """

    # Known high-risk ports and their descriptions
    HIGH_RISK_PORTS = {
        21: ("FTP", "File Transfer Protocol - often transmits credentials in cleartext"),
        23: ("Telnet", "Unencrypted remote access - credentials sent in cleartext"),
        25: ("SMTP", "Mail server - can be abused for spam relay if misconfigured"),
        53: ("DNS", "Domain Name Service - can be used for amplification attacks"),
        69: ("TFTP", "Trivial FTP - no authentication, often used for firmware updates"),
        111: ("RPC/Portmapper", "Remote Procedure Call - prerequisite for NFS attacks"),
        135: ("MSRPC", "Microsoft RPC - commonly exploited for lateral movement"),
        137: ("NetBIOS-NS", "NetBIOS Name Service - information disclosure"),
        138: ("NetBIOS-DGM", "NetBIOS Datagram - legacy protocol with known vulnerabilities"),
        139: ("NetBIOS-SSN", "NetBIOS Session - SMB over NetBIOS, credential relay attacks"),
        161: ("SNMP", "Simple Network Management Protocol - default community strings exploitable"),
        445: ("SMB", "Server Message Block - credential relay, ransomware propagation"),
        512: ("rexec", "Remote execution - legacy, insecure"),
        513: ("rlogin", "Remote login - legacy, insecure"),
        514: ("rsh", "Remote shell - legacy, no encryption"),
        515: ("LPD", "Line Printer Daemon - printer attacks, often unpatched"),
        631: ("IPP/CUPS", "Internet Printing Protocol - printer vulnerabilities"),
        1433: ("MSSQL", "Microsoft SQL Server - default credentials, SQL injection"),
        1521: ("Oracle", "Oracle Database - potential for SQL injection"),
        2049: ("NFS", "Network File System - world-readable exports common"),
        3306: ("MySQL", "MySQL Database - default credentials, SQL injection"),
        3389: ("RDP", "Remote Desktop Protocol - brute force target, BlueKeep"),
        5432: ("PostgreSQL", "PostgreSQL Database - credential attacks"),
        5900: ("VNC", "Virtual Network Computing - weak authentication common"),
        5985: ("WinRM", "Windows Remote Management - lateral movement"),
        6379: ("Redis", "Redis Database - often exposed without authentication"),
        8080: ("HTTP-Alt", "Alternative HTTP - management interfaces"),
        8443: ("HTTPS-Alt", "Alternative HTTPS - management interfaces"),
        9100: ("JetDirect", "Printer protocol - pivot point, often unpatched"),
        27017: ("MongoDB", "MongoDB - often exposed without authentication"),
    }

    @staticmethod
    def _ip_sort_key(ip_item):
        """Sort key for IP addresses - handles numeric sorting correctly."""
        ip = ip_item[0] if isinstance(ip_item, tuple) else ip_item
        try:
            parts = ip.split('.')
            return tuple(int(p) for p in parts)
        except (ValueError, AttributeError):
            return (999, 999, 999, 999)  # Sort invalid IPs last

    # Service categories for network inventory
    SERVICE_CATEGORIES = {
        "Network Infrastructure": ["router", "switch", "firewall", "gateway", "mikrotik", "cisco", "juniper", "ubiquiti", "fortinet", "pfsense", "opnsense"],
        "Servers / Virtualisation": ["proxmox", "vmware", "esxi", "hyper-v", "linux", "ubuntu", "debian", "centos", "rhel", "windows server", "freenas", "truenas", "synology", "qnap"],
        "Network Storage": ["nas", "iscsi", "nfs", "cifs", "samba", "synology", "qnap", "freenas", "truenas"],
        "Printers / Scanners": ["printer", "jetdirect", "cups", "xerox", "hp laserjet", "brother", "canon", "epson", "ricoh", "kyocera"],
        "IoT / Smart Home": ["iot", "smart", "nest", "ring", "hue", "sonos", "alexa", "echo", "home assistant", "homekit", "tuya", "shelly", "tasmota"],
        "Media Devices": ["apple tv", "chromecast", "roku", "fire tv", "plex", "kodi", "sonos", "airplay", "dlna"],
        "Personal Devices": ["iphone", "ipad", "android", "macos", "macbook", "imac", "windows 10", "windows 11"],
        "Security Cameras": ["camera", "nvr", "dvr", "hikvision", "dahua", "axis", "reolink", "unifi protect"],
    }

    def __init__(self, scan_data: dict, metadata: dict = None):
        """
        Initialize with nmap scan data.

        Args:
            scan_data: Dictionary of {ip: host_info} from nmap parser
            metadata: Optional dict with client_name, target, scan_type, scan_depth, timestamp
        """
        self.scan_data = scan_data
        self.metadata = metadata or {}
        # Filter to only active hosts
        self.active_hosts = {ip: info for ip, info in scan_data.items() if info.get("status") == "up"}

    def generate(self, standalone: bool = True) -> str:
        """Generate complete Network Discovery report as HTML.

        Args:
            standalone: If True, wrap in full HTML document with styling.
                       If False, return just the body content (for web UI embedding).
        """
        sections = [
            self._header(),
            self._section_executive_summary(),
            self._section_network_inventory(),
            self._section_security_findings(),
            self._section_recommendations(),
            self._section_technical_appendix()
        ]

        body_content = "\n\n".join([s for s in sections if s])

        if not standalone:
            return body_content

        # Wrap in full HTML document with dark theme
        client_name = self.metadata.get('client_name', 'Unknown')
        target = self.metadata.get('target', 'Unknown')

        return f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Network Security Assessment - {client_name}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background: #0a0b0e;
            color: #c9d1d9;
            line-height: 1.6;
            padding: 40px;
            max-width: 1200px;
            margin: 0 auto;
        }}
        a {{ color: #039be5; text-decoration: none; }}
        a:hover {{ text-decoration: underline; }}
        code {{
            background: #1c2128;
            border: 1px solid #30363d;
            padding: 2px 6px;
            border-radius: 4px;
            font-size: 0.85em;
            color: #f0883e;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 12px 0;
            font-size: 0.85rem;
        }}
        th {{
            background: #161b22;
            color: #7d8590;
            text-align: left;
            padding: 10px 12px;
            border-bottom: 2px solid #30363d;
            font-weight: 600;
        }}
        td {{
            padding: 10px 12px;
            border-bottom: 1px solid #30363d;
            color: #c9d1d9;
        }}
        tr:hover td {{
            background: rgba(88, 166, 255, 0.06);
        }}
        @media print {{
            body {{
                background: #fff;
                color: #1a1a1a;
                padding: 20px;
            }}
            h1, h2, h3 {{ color: #1a1a1a !important; }}
            p, li, td {{ color: #333 !important; }}
            th {{ background: #f0f0f0 !important; color: #333 !important; }}
            div[style*="background:#161b22"], div[style*="background:#0d1117"] {{
                background: #f5f5f5 !important;
                border-color: #ddd !important;
            }}
        }}
    </style>
</head>
<body>
{body_content}
</body>
</html>'''

    def _header(self) -> str:
        """Generate report header."""
        client_name = self.metadata.get('client_name', 'Unknown')
        target = self.metadata.get('target', 'Unknown')
        scan_type = self.metadata.get('scan_type', 'unknown')
        scan_depth = self.metadata.get('scan_depth', 'medium')
        timestamp = self.metadata.get('timestamp', datetime.now().strftime("%Y-%m-%d %H:%M"))

        report_title = "Host Security Assessment" if scan_type == "single" else "Network Security Assessment"
        scan_label = f"{scan_depth.capitalize()} Scan"

        return f'''<h1 style="color:#fff;font-size:1.6rem;margin:0 0 16px;border-bottom:2px solid #7b1fa2;padding-bottom:12px;">{report_title} Report</h1>

<div style="background:#161b22;border:1px solid #30363d;border-radius:8px;padding:16px 20px;margin-bottom:20px;">
    <p style="margin:4px 0;color:#c9d1d9;"><strong style="color:#039be5;">Client:</strong> {client_name}</p>
    <p style="margin:4px 0;color:#c9d1d9;"><strong style="color:#039be5;">Target:</strong> <code style="background:#1c2128;padding:2px 6px;border-radius:3px;color:#f0883e;">{target}</code></p>
    <p style="margin:4px 0;color:#c9d1d9;"><strong style="color:#039be5;">Scan Type:</strong> {scan_label}</p>
    <p style="margin:4px 0;color:#c9d1d9;"><strong style="color:#039be5;">Assessment Date:</strong> {timestamp}</p>
    <p style="margin:4px 0;color:#c9d1d9;"><strong style="color:#039be5;">Classification:</strong> Confidential</p>
</div>'''

    def _section_executive_summary(self) -> str:
        """Generate executive summary with risk assessment."""
        total_hosts = len(self.active_hosts)
        hosts_with_ports = sum(1 for h in self.active_hosts.values() if h.get('protocols'))
        hosts_no_ports = total_hosts - hosts_with_ports

        # Count total open ports and services
        total_ports = 0
        services_found = set()
        for host in self.active_hosts.values():
            for proto, ports in host.get('protocols', {}).items():
                for port in ports:
                    if port.get('state') == 'open':
                        total_ports += 1
                        if port.get('name'):
                            services_found.add(port['name'])

        # Analyze findings and calculate overall risk
        findings = self._analyze_all_findings()
        critical_count = len([f for f in findings if f['risk'] == 'Critical'])
        high_count = len([f for f in findings if f['risk'] == 'High'])
        medium_count = len([f for f in findings if f['risk'] == 'Medium'])
        low_count = len([f for f in findings if f['risk'] == 'Low'])

        # Determine overall risk
        if critical_count > 0:
            overall_risk = "Critical"
            risk_color = "#f85149"
        elif high_count >= 3:
            overall_risk = "High"
            risk_color = "#f85149"
        elif high_count > 0:
            overall_risk = "Medium-High"
            risk_color = "#d29922"
        elif medium_count >= 3:
            overall_risk = "Medium"
            risk_color = "#d29922"
        elif medium_count > 0 or low_count > 0:
            overall_risk = "Low"
            risk_color = "#3fb950"
        else:
            overall_risk = "Minimal"
            risk_color = "#3fb950"

        # Build findings summary table
        findings_table = self.format_table(
            ["Risk Level", "Count", "Description"],
            [
                [self.risk_badge("Critical"), str(critical_count), "Immediate action required"],
                [self.risk_badge("High"), str(high_count), "Address within 7 days"],
                [self.risk_badge("Medium"), str(medium_count), "Address within 30 days"],
                [self.risk_badge("Low"), str(low_count), "Monitor and review"],
            ]
        )

        # Top findings preview
        top_findings_html = ""
        if findings:
            top_findings_html = '<h3 style="color:#bc8cff;font-size:1rem;margin:20px 0 12px;">Top Security Concerns</h3><ol style="margin:8px 0 16px 24px;padding:0;">'
            for finding in findings[:5]:
                top_findings_html += f'<li style="color:#c9d1d9;line-height:1.8;margin-bottom:8px;"><strong>{finding["title"]}</strong> {self.risk_badge(finding["risk"])}</li>'
            top_findings_html += '</ol>'

        return f'''<h2 style="color:#fff;font-size:1.25rem;margin:24px 0 16px;padding-bottom:8px;border-bottom:1px solid #30363d;">1. Executive Summary</h2>

<div style="background:rgba(248, 81, 73, 0.1);border:1px solid {risk_color};border-radius:8px;padding:16px 20px;margin-bottom:16px;">
    <p style="margin:0;color:#fff;font-size:1.1rem;"><strong>Overall Security Risk:</strong> {self.risk_badge(overall_risk)}</p>
</div>

<div style="display:flex;gap:20px;margin-bottom:16px;flex-wrap:wrap;">
    <div style="background:#161b22;border:1px solid #30363d;border-radius:6px;padding:12px 16px;flex:1;min-width:120px;text-align:center;">
        <p style="margin:0;color:#7d8590;font-size:0.8rem;">Hosts Discovered</p>
        <p style="margin:4px 0 0;color:#fff;font-size:1.4rem;font-weight:600;">{total_hosts}</p>
    </div>
    <div style="background:#161b22;border:1px solid #30363d;border-radius:6px;padding:12px 16px;flex:1;min-width:120px;text-align:center;">
        <p style="margin:0;color:#7d8590;font-size:0.8rem;">Open Ports</p>
        <p style="margin:4px 0 0;color:#fff;font-size:1.4rem;font-weight:600;">{total_ports}</p>
    </div>
    <div style="background:#161b22;border:1px solid #30363d;border-radius:6px;padding:12px 16px;flex:1;min-width:120px;text-align:center;">
        <p style="margin:0;color:#7d8590;font-size:0.8rem;">Unique Services</p>
        <p style="margin:4px 0 0;color:#fff;font-size:1.4rem;font-weight:600;">{len(services_found)}</p>
    </div>
    <div style="background:#161b22;border:1px solid #30363d;border-radius:6px;padding:12px 16px;flex:1;min-width:120px;text-align:center;">
        <p style="margin:0;color:#7d8590;font-size:0.8rem;">Security Findings</p>
        <p style="margin:4px 0 0;color:#fff;font-size:1.4rem;font-weight:600;">{len(findings)}</p>
    </div>
</div>

<h3 style="color:#bc8cff;font-size:1rem;margin:20px 0 12px;">Findings by Severity</h3>
{findings_table}

{top_findings_html}

<div style="background:#0d1117;border:1px solid #30363d;border-radius:6px;padding:12px 16px;margin-top:16px;">
    <p style="margin:0;color:#7d8590;font-size:0.85rem;"><em>This assessment is based on unauthenticated network discovery. An authenticated vulnerability scan would provide additional depth and accuracy.</em></p>
</div>'''

    def _section_network_inventory(self) -> str:
        """Generate network inventory section with categorized hosts."""
        if not self.active_hosts:
            return ""

        # Categorize hosts
        categories = {}
        uncategorized = []

        for ip, info in self.active_hosts.items():
            if not info.get('protocols'):
                uncategorized.append((ip, info, "No open ports detected"))
                continue

            category = self._categorize_host(info)
            if category:
                if category not in categories:
                    categories[category] = []
                categories[category].append((ip, info))
            else:
                uncategorized.append((ip, info, "Unclassified"))

        # Build inventory table
        inventory_rows = []
        for category in ["Network Infrastructure", "Servers / Virtualisation", "Network Storage",
                         "Printers / Scanners", "Security Cameras", "IoT / Smart Home",
                         "Media Devices", "Personal Devices"]:
            if category in categories:
                hosts = sorted(categories[category], key=lambda x: self._ip_sort_key(x[0]))
                examples = ", ".join([f"{ip} ({h.get('hostname') or h.get('os', 'Unknown')[:20]})"
                                     for ip, h in hosts[:3]])
                if len(hosts) > 3:
                    examples += f" +{len(hosts) - 3} more"
                inventory_rows.append([category, str(len(hosts)), examples])

        # Add uncategorized
        if uncategorized:
            no_ports = sorted([u for u in uncategorized if u[2] == "No open ports detected"],
                              key=lambda x: self._ip_sort_key(x[0]))
            other = sorted([u for u in uncategorized if u[2] != "No open ports detected"],
                           key=lambda x: self._ip_sort_key(x[0]))
            if no_ports:
                examples = ", ".join([f"{ip}" for ip, _, _ in no_ports[:5]])
                if len(no_ports) > 5:
                    examples += f" +{len(no_ports) - 5} more"
                inventory_rows.append(["No Ports Detected", str(len(no_ports)), examples])
            if other:
                examples = ", ".join([f"{ip}" for ip, _, _ in other[:5]])
                inventory_rows.append(["Other / Unclassified", str(len(other)), examples])

        inventory_table = self.format_table(
            ["Category", "Count", "Examples"],
            inventory_rows
        )

        return f'''<h2 style="color:#fff;font-size:1.25rem;margin:24px 0 16px;padding-bottom:8px;border-bottom:1px solid #30363d;">2. Network Inventory</h2>

{inventory_table}

<p style="color:#7d8590;font-size:0.85rem;margin-top:12px;">Categories are inferred from OS detection, service banners, and open ports. Accuracy depends on scan depth and host responsiveness.</p>'''

    def _section_security_findings(self) -> str:
        """Generate security findings section grouped by severity."""
        findings = self._analyze_all_findings()

        if not findings:
            return f'''<h2 style="color:#fff;font-size:1.25rem;margin:24px 0 16px;padding-bottom:8px;border-bottom:1px solid #30363d;">3. Security Findings</h2>

<div style="background:#161b22;border:1px solid #30363d;border-radius:8px;padding:16px 20px;">
    <p style="color:#3fb950;"><strong>No significant security findings.</strong></p>
    <p style="color:#7d8590;font-size:0.9rem;margin-top:8px;">The scan did not identify any high-risk services or configurations. Continue monitoring and perform regular assessments.</p>
</div>'''

        # Group by severity
        by_severity = {"Critical": [], "High": [], "Medium": [], "Low": []}
        for f in findings:
            by_severity[f['risk']].append(f)

        findings_html = ""
        finding_num = 1

        for severity in ["Critical", "High", "Medium", "Low"]:
            if by_severity[severity]:
                for finding in by_severity[severity]:
                    findings_html += f'''
<div style="background:#161b22;border:1px solid #30363d;border-radius:8px;padding:16px 20px;margin-bottom:16px;">
    <h3 style="color:#fff;font-size:1rem;margin:0 0 12px;">{finding_num}. {finding['title']} {self.risk_badge(finding['risk'])}</h3>
    <p style="margin:8px 0;color:#c9d1d9;"><strong style="color:#7d8590;">Finding:</strong> {finding['description']}</p>
    <p style="margin:8px 0;color:#c9d1d9;"><strong style="color:#7d8590;">Affected Hosts:</strong> <code style="background:#1c2128;padding:2px 6px;border-radius:3px;color:#f0883e;">{finding['hosts']}</code></p>
    <p style="margin:8px 0;color:#c9d1d9;"><strong style="color:#7d8590;">Risk:</strong> {finding['risk_explanation']}</p>
    <p style="margin:8px 0;color:#c9d1d9;"><strong style="color:#7d8590;">Recommendation:</strong> {finding['recommendation']}</p>
</div>'''
                    finding_num += 1

        return f'''<h2 style="color:#fff;font-size:1.25rem;margin:24px 0 16px;padding-bottom:8px;border-bottom:1px solid #30363d;">3. Security Findings</h2>

{findings_html}'''

    def _section_recommendations(self) -> str:
        """Generate prioritized recommendations."""
        findings = self._analyze_all_findings()

        # Build recommendations based on findings
        immediate = []
        short_term = []
        ongoing = []

        critical_high = [f for f in findings if f['risk'] in ['Critical', 'High']]
        medium = [f for f in findings if f['risk'] == 'Medium']
        low = [f for f in findings if f['risk'] == 'Low']

        for f in critical_high:
            immediate.append(f['recommendation'])
        for f in medium:
            short_term.append(f['recommendation'])
        for f in low:
            ongoing.append(f['recommendation'])

        # Remove duplicates while preserving order
        immediate = list(dict.fromkeys(immediate))
        short_term = list(dict.fromkeys(short_term))
        ongoing = list(dict.fromkeys(ongoing))

        # Add standard recommendations if list is short
        if len(immediate) < 2:
            immediate.append("Perform authenticated vulnerability scanning for comprehensive assessment")
        if len(short_term) < 2:
            short_term.append("Review firewall rules and network segmentation")
            short_term.append("Document all network assets and their business purpose")
        if len(ongoing) < 2:
            ongoing.append("Establish regular scanning schedule (monthly recommended)")
            ongoing.append("Monitor for new devices joining the network")

        # Build recommendations table
        rec_rows = []
        priority_order = 1
        for rec in immediate[:5]:
            rec_rows.append([f'<span style="color:#f85149;font-weight:600;">High</span>', rec, "Immediate"])
            priority_order += 1
        for rec in short_term[:4]:
            rec_rows.append([f'<span style="color:#d29922;font-weight:600;">Medium</span>', rec, "1-4 weeks"])
            priority_order += 1
        for rec in ongoing[:3]:
            rec_rows.append([f'<span style="color:#3fb950;font-weight:600;">Low</span>', rec, "Ongoing"])

        rec_table = self.format_table(
            ["Priority", "Action", "Timeframe"],
            rec_rows
        )

        return f'''<h2 style="color:#fff;font-size:1.25rem;margin:24px 0 16px;padding-bottom:8px;border-bottom:1px solid #30363d;">4. Recommendations</h2>

{rec_table}

<h3 style="color:#bc8cff;font-size:1rem;margin:20px 0 12px;">Next Steps</h3>
<ul style="margin:8px 0 16px 24px;padding:0;">
    <li style="color:#c9d1d9;line-height:1.8;margin-bottom:6px;"><strong>Review findings</strong> with IT team and prioritize remediation</li>
    <li style="color:#c9d1d9;line-height:1.8;margin-bottom:6px;"><strong>Authenticated scan</strong> recommended for deeper vulnerability assessment</li>
    <li style="color:#c9d1d9;line-height:1.8;margin-bottom:6px;"><strong>Network segmentation</strong> review to isolate critical assets</li>
    <li style="color:#c9d1d9;line-height:1.8;margin-bottom:6px;"><strong>Configuration review</strong> for high-risk services identified</li>
</ul>'''

    def _section_technical_appendix(self) -> str:
        """Generate technical appendix with full port table."""
        if not self.active_hosts:
            return ""

        # Build comprehensive port table
        rows = []
        for ip, info in sorted(self.active_hosts.items(), key=self._ip_sort_key):
            hostname = info.get('hostname') or '—'
            os_info = info.get('os', 'Unknown')
            if len(os_info) > 30:
                os_info = os_info[:27] + "..."

            if not info.get('protocols'):
                rows.append([ip, hostname, os_info, "—", "—", "—", "—", "—"])
            else:
                for proto, ports in info.get('protocols', {}).items():
                    for port in ports:
                        port_num = port.get('port', '—')
                        state = port.get('state', '—')
                        service = port.get('name', '—')
                        product = f"{port.get('product', '')} {port.get('version', '')}".strip() or '—'
                        rows.append([ip, hostname, os_info, str(port_num), proto.upper(), state, service, product])

        port_table = self.format_table(
            ["IP Address", "Hostname", "OS", "Port", "Protocol", "State", "Service", "Product"],
            rows
        )

        return f'''<h2 style="color:#fff;font-size:1.25rem;margin:24px 0 16px;padding-bottom:8px;border-bottom:1px solid #30363d;">5. Technical Appendix</h2>

<h3 style="color:#bc8cff;font-size:1rem;margin:16px 0 12px;">Port-Level Scan Data</h3>
<div style="overflow-x:auto;">
{port_table}
</div>

<hr style="border:none;border-top:1px solid #30363d;margin:24px 0;">

<p style="color:#7d8590;font-size:0.85rem;text-align:center;">
    <em>Report generated by AAG Technical Audit Tool</em><br>
    <em>Assessment date: {self.metadata.get('timestamp', datetime.now().strftime("%Y-%m-%d %H:%M"))}</em>
</p>'''

    def _categorize_host(self, host_info: dict) -> Optional[str]:
        """Categorize a host based on OS, hostname, and services."""
        os_name = (host_info.get('os') or '').lower()
        hostname = (host_info.get('hostname') or '').lower()
        vendor = (host_info.get('vendor') or '').lower()

        # Combine all text for matching
        all_text = f"{os_name} {hostname} {vendor}"

        # Check services for additional hints
        services = []
        for proto, ports in host_info.get('protocols', {}).items():
            for port in ports:
                services.append((port.get('name', ''), port.get('product', '')))
                all_text += f" {port.get('name', '')} {port.get('product', '')}"

        all_text = all_text.lower()

        # Match against categories
        for category, keywords in self.SERVICE_CATEGORIES.items():
            for keyword in keywords:
                if keyword in all_text:
                    return category

        # Fallback: check for common port patterns
        ports_set = set()
        for proto, ports in host_info.get('protocols', {}).items():
            for port in ports:
                ports_set.add(port.get('port'))

        # Printer ports
        if ports_set & {515, 631, 9100}:
            return "Printers / Scanners"

        # Server ports
        if ports_set & {22, 80, 443, 3389, 5900}:
            if 'windows' in all_text:
                return "Servers / Virtualisation" if 'server' in all_text else "Personal Devices"
            elif 'linux' in all_text or 'ubuntu' in all_text or 'debian' in all_text:
                return "Servers / Virtualisation"

        return None

    def _analyze_all_findings(self) -> List[dict]:
        """Analyze all hosts and generate security findings."""
        findings = []
        port_hosts = {}  # {port: [list of IPs]}

        # Collect all open ports across hosts
        for ip, info in self.active_hosts.items():
            for proto, ports in info.get('protocols', {}).items():
                for port in ports:
                    if port.get('state') == 'open':
                        port_num = port.get('port')
                        if port_num not in port_hosts:
                            port_hosts[port_num] = []
                        port_hosts[port_num].append({
                            'ip': ip,
                            'hostname': info.get('hostname'),
                            'service': port.get('name'),
                            'product': port.get('product'),
                            'version': port.get('version')
                        })

        # Check for high-risk ports
        for port_num, hosts in port_hosts.items():
            if port_num in self.HIGH_RISK_PORTS:
                service_name, risk_desc = self.HIGH_RISK_PORTS[port_num]
                host_list = ", ".join([h['ip'] for h in hosts])

                # Determine risk level
                if port_num in [23, 21, 161, 445, 3389, 2049]:
                    risk = "High"
                elif port_num in [111, 135, 139, 515, 631, 9100]:
                    risk = "Medium"
                else:
                    risk = "Low"

                # Critical if multiple hosts affected
                if len(hosts) >= 5 and risk == "High":
                    risk = "Critical"

                findings.append({
                    'title': f"{service_name} Service Exposed (Port {port_num})",
                    'risk': risk,
                    'description': f"{service_name} service detected on port {port_num}/{hosts[0].get('service', 'unknown')}.",
                    'hosts': host_list,
                    'risk_explanation': risk_desc,
                    'recommendation': self._get_recommendation_for_port(port_num, service_name)
                })

        # Check for management interfaces (common web ports with products)
        web_ports = [80, 443, 8080, 8443, 8000, 8888]
        for port_num in web_ports:
            if port_num in port_hosts:
                for host in port_hosts[port_num]:
                    product = (host.get('product') or '').lower()
                    if any(mgmt in product for mgmt in ['proxmox', 'idrac', 'ilo', 'ipmi', 'unifi', 'mikrotik', 'fortinet', 'pfsense']):
                        findings.append({
                            'title': f"Management Interface Exposed ({host.get('product', 'Unknown')})",
                            'risk': "Medium",
                            'description': f"Web-based management interface detected on {host['ip']}:{port_num}.",
                            'hosts': host['ip'],
                            'risk_explanation': "Management interfaces are high-value targets. If compromised, attackers gain administrative control.",
                            'recommendation': "Restrict access to management interfaces via firewall rules or VPN. Enable MFA if available."
                        })

        # Check for default/weak services on multiple hosts (indicates systematic issue)
        if len(port_hosts.get(22, [])) > 10:
            findings.append({
                'title': "SSH Widely Deployed",
                'risk': "Low",
                'description': f"SSH service detected on {len(port_hosts[22])} hosts.",
                'hosts': f"{len(port_hosts[22])} hosts",
                'risk_explanation': "SSH is secure when properly configured, but widespread deployment increases attack surface.",
                'recommendation': "Ensure key-based authentication is enforced. Disable password authentication where possible."
            })

        # Sort by risk level
        risk_order = {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3}
        findings.sort(key=lambda x: risk_order.get(x['risk'], 4))

        return findings

    def _get_recommendation_for_port(self, port: int, service: str) -> str:
        """Get specific recommendation for a port/service."""
        recommendations = {
            21: "Disable FTP or migrate to SFTP/SCP. If FTP is required, enforce TLS (FTPS).",
            23: "Disable Telnet immediately. Replace with SSH for secure remote access.",
            25: "Ensure SMTP relay is restricted to authorized hosts. Enable authentication.",
            53: "Restrict DNS to internal clients. Enable DNSSEC if public-facing.",
            111: "Disable RPC/Portmapper if NFS is not required. Restrict to trusted hosts.",
            135: "Block port 135 at the firewall. Not needed for normal operations.",
            139: "Disable NetBIOS over TCP/IP if not required. Prefer SMB over port 445 with signing.",
            161: "Change SNMP community strings from defaults. Upgrade to SNMPv3 with authentication.",
            445: "Enable SMB signing. Restrict access via firewall. Patch against known vulnerabilities.",
            515: "Restrict printer access to authorized hosts. Update firmware regularly.",
            631: "Restrict CUPS access. Disable unnecessary printer sharing.",
            1433: "Restrict SQL Server access to application servers. Use Windows authentication.",
            2049: "Restrict NFS exports to specific hosts. Use NFSv4 with Kerberos authentication.",
            3306: "Restrict MySQL access to application servers. Use strong authentication.",
            3389: "Enable Network Level Authentication. Restrict RDP to VPN users or specific IPs.",
            5432: "Restrict PostgreSQL access. Use SSL connections and strong passwords.",
            5900: "Disable VNC or restrict to localhost. Use SSH tunneling for remote access.",
            6379: "Bind Redis to localhost. Enable authentication. Never expose to internet.",
            9100: "Restrict JetDirect access. Place printers on isolated network segment.",
            27017: "Enable MongoDB authentication. Bind to localhost or private interface.",
        }
        return recommendations.get(port, f"Review {service} configuration and restrict access where possible.")


class AzureTemplatedReport(ReportSection):
    """Python-templated Azure Resource Inventory report generator (HTML output).

    Takes Azure inventory JSON data and generates a structured infrastructure
    assessment report with resource analysis, cost optimisation opportunities,
    and recommendations.
    """

    # Azure region display names
    REGION_NAMES = {
        "uksouth": "UK South",
        "ukwest": "UK West",
        "northeurope": "North Europe",
        "westeurope": "West Europe",
        "eastus": "East US",
        "eastus2": "East US 2",
        "westus": "West US",
        "westus2": "West US 2",
        "centralus": "Central US",
        "australiaeast": "Australia East",
        "australiasoutheast": "Australia Southeast",
        "southeastasia": "Southeast Asia",
        "eastasia": "East Asia",
        "japaneast": "Japan East",
        "japanwest": "Japan West",
        "brazilsouth": "Brazil South",
        "canadacentral": "Canada Central",
        "canadaeast": "Canada East",
        "germanywestcentral": "Germany West Central",
        "francecentral": "France Central",
        "switzerlandnorth": "Switzerland North",
        "norwayeast": "Norway East",
        "swedencentral": "Sweden Central",
    }

    # VM size categories for analysis
    VM_SIZE_CATEGORIES = {
        "B": ("Burstable", "Cost-effective for variable workloads"),
        "D": ("General Purpose", "Balanced compute/memory ratio"),
        "E": ("Memory Optimised", "High memory-to-core ratio"),
        "F": ("Compute Optimised", "High CPU-to-memory ratio"),
        "M": ("Memory Intensive", "Large memory configurations"),
        "L": ("Storage Optimised", "High disk throughput"),
        "N": ("GPU Enabled", "AI/ML and graphics workloads"),
        "H": ("High Performance", "HPC workloads"),
    }

    def __init__(self, inventory_data: dict):
        """Initialize with Azure inventory JSON data."""
        super().__init__(inventory_data)
        self.metadata = inventory_data.get("metadata", {})
        self.summary = inventory_data.get("summary", {})
        self.subscriptions = inventory_data.get("subscriptions", [])
        self.compute = inventory_data.get("compute", {})
        self.networking = inventory_data.get("networking", {})
        self.storage = inventory_data.get("storage", {})
        self.databases = inventory_data.get("databases", {})
        self.security = inventory_data.get("security", {})

    def generate(self, standalone: bool = False) -> str:
        """
        Generate the complete HTML report.

        Args:
            standalone: If True, wrap in full HTML document with styles.
                       If False, return just the body content (for web UI embedding).
        """
        sections = [
            self._header(),
            self._section_summary_cards(),
            self._section_executive_summary(),
            self._section_subscriptions(),
            self._section_compute(),
            self._section_networking(),
            self._section_storage_databases(),
            self._section_security(),
            self._section_cost_optimisation(),
            self._section_recommendations(),
            self._section_conclusion()
        ]

        body = "\n".join(sections)

        if standalone:
            return self._wrap_standalone(body)
        return body

    def _wrap_standalone(self, body: str) -> str:
        """Wrap content in a standalone HTML document."""
        client = self.metadata.get("clientName", "Unknown")
        date = self.metadata.get("assessmentDate", "")[:10]
        return f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Azure Resource Inventory - {client}</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background: #0d1117;
            color: #c9d1d9;
            line-height: 1.6;
            padding: 24px;
            max-width: 1200px;
            margin: 0 auto;
        }}
        h1, h2, h3 {{ color: #fff; }}
        a {{ color: #58a6ff; }}
        table {{ border-collapse: collapse; width: 100%; margin: 12px 0; }}
        th, td {{ padding: 10px 12px; text-align: left; border-bottom: 1px solid #30363d; }}
        th {{ background: #161b22; color: #7d8590; font-weight: 600; }}
        @media print {{
            body {{ background: #fff; color: #000; }}
            th {{ background: #f0f0f0; color: #000; }}
            td {{ color: #333; }}
        }}
    </style>
</head>
<body>
{body}
</body>
</html>'''

    def _header(self) -> str:
        """Generate report header with branding."""
        client = self.metadata.get("clientName", "Unknown Client")
        date = self.metadata.get("assessmentDate", "")[:10] if self.metadata.get("assessmentDate") else datetime.now().strftime("%Y-%m-%d")
        tenant_id = self.metadata.get("tenantId", "")

        tenant_display = f'<span style="color:#7d8590;font-size:0.9rem;">Tenant: {tenant_id[:8]}...{tenant_id[-4:]}</span>' if tenant_id and len(tenant_id) > 12 else ""

        return f'''<div style="border-bottom:3px solid;border-image:linear-gradient(90deg,#e81f63,#7b1fa2,#039be5) 1;padding-bottom:16px;margin-bottom:24px;">
    <h1 style="margin:0;font-size:1.75rem;color:#fff;">Azure Resource Inventory</h1>
    <p style="margin:8px 0 0;color:#7d8590;font-size:1rem;">{client} &mdash; {date}</p>
    {tenant_display}
</div>'''

    def _section_summary_cards(self) -> str:
        """Generate summary cards with key metrics."""
        total_resources = self.summary.get("totalResources", 0)
        subscription_count = self.summary.get("subscriptionCount", 0)

        # Count VMs
        vms = self.compute.get("virtualMachines", [])
        vm_count = len(vms)
        running_vms = sum(1 for vm in vms if "running" in (vm.get("powerState") or "").lower())
        stopped_vms = vm_count - running_vms

        # Count storage accounts
        storage_count = len(self.storage.get("storageAccounts", []))

        # Count databases
        db_count = (len(self.databases.get("sqlServers", [])) +
                   len(self.databases.get("sqlDatabases", [])) +
                   len(self.databases.get("cosmosDbAccounts", [])) +
                   len(self.databases.get("mySqlServers", [])) +
                   len(self.databases.get("postgreSqlServers", [])))

        # Count networking resources
        net_count = (len(self.networking.get("virtualNetworks", [])) +
                    len(self.networking.get("networkSecurityGroups", [])) +
                    len(self.networking.get("loadBalancers", [])) +
                    len(self.networking.get("publicIPs", [])))

        card_style = '''display:inline-block;background:#161b22;border:1px solid #30363d;
                       border-radius:8px;padding:16px 20px;margin:8px;min-width:140px;text-align:center;'''

        return f'''<div style="margin-bottom:24px;">
    <div style="{card_style}">
        <div style="font-size:2rem;font-weight:700;color:#58a6ff;">{total_resources:,}</div>
        <div style="color:#7d8590;font-size:0.85rem;">Total Resources</div>
    </div>
    <div style="{card_style}">
        <div style="font-size:2rem;font-weight:700;color:#a371f7;">{subscription_count}</div>
        <div style="color:#7d8590;font-size:0.85rem;">Subscriptions</div>
    </div>
    <div style="{card_style}">
        <div style="font-size:2rem;font-weight:700;color:#3fb950;">{vm_count}</div>
        <div style="color:#7d8590;font-size:0.85rem;">Virtual Machines</div>
        <div style="color:#7d8590;font-size:0.75rem;margin-top:4px;">
            <span style="color:#3fb950;">{running_vms} running</span> &bull;
            <span style="color:#d29922;">{stopped_vms} stopped</span>
        </div>
    </div>
    <div style="{card_style}">
        <div style="font-size:2rem;font-weight:700;color:#f0883e;">{storage_count}</div>
        <div style="color:#7d8590;font-size:0.85rem;">Storage Accounts</div>
    </div>
    <div style="{card_style}">
        <div style="font-size:2rem;font-weight:700;color:#79c0ff;">{db_count}</div>
        <div style="color:#7d8590;font-size:0.85rem;">Databases</div>
    </div>
    <div style="{card_style}">
        <div style="font-size:2rem;font-weight:700;color:#7ee787;">{net_count}</div>
        <div style="color:#7d8590;font-size:0.85rem;">Network Resources</div>
    </div>
</div>'''

    def _section_executive_summary(self) -> str:
        """Generate executive summary section."""
        total_resources = self.summary.get("totalResources", 0)
        subscription_count = self.summary.get("subscriptionCount", 0)
        resource_types = self.summary.get("resourcesByType", {})
        locations = self.summary.get("resourcesByLocation", {})

        vms = self.compute.get("virtualMachines", [])
        running_vms = sum(1 for vm in vms if "running" in (vm.get("powerState") or "").lower())
        stopped_vms = len(vms) - running_vms

        # Determine environment size
        if total_resources < 50:
            env_size = "small"
            env_desc = "a small Azure footprint"
        elif total_resources < 200:
            env_size = "medium"
            env_desc = "a medium-sized Azure environment"
        elif total_resources < 500:
            env_size = "large"
            env_desc = "a substantial Azure deployment"
        else:
            env_size = "enterprise"
            env_desc = "an enterprise-scale Azure environment"

        # Location summary
        location_list = sorted(locations.items(), key=lambda x: -x[1])[:3]
        location_text = ", ".join([f"{self.REGION_NAMES.get(loc, loc)} ({count})" for loc, count in location_list])

        # Observations
        observations = []
        if stopped_vms > 0 and stopped_vms >= running_vms * 0.3:
            observations.append(f"<li><strong>{stopped_vms} stopped/deallocated VMs</strong> detected — potential cost savings or cleanup opportunity</li>")
        if len(locations) == 1:
            observations.append("<li><strong>Single-region deployment</strong> — consider DR/availability requirements</li>")
        elif len(locations) > 3:
            observations.append(f"<li><strong>Multi-region presence</strong> across {len(locations)} regions — good for availability, review for cost optimisation</li>")

        key_vaults = len(self.security.get("keyVaults", []))
        if key_vaults == 0:
            observations.append("<li><strong>No Key Vaults detected</strong> — secrets management may need review</li>")

        observations_html = f"<ul style='margin:12px 0;padding-left:20px;'>{''.join(observations)}</ul>" if observations else ""

        return f'''<h2 style="color:#fff;font-size:1.25rem;margin:24px 0 16px;padding-bottom:8px;border-bottom:1px solid #30363d;">1. Executive Summary</h2>

<p style="color:#c9d1d9;margin-bottom:12px;">
This assessment covers <strong>{env_desc}</strong> with <strong>{total_resources:,} resources</strong> across
<strong>{subscription_count} subscription(s)</strong>. The environment includes {len(vms)} virtual machines,
{len(self.storage.get("storageAccounts", []))} storage accounts, and various networking and database resources.
</p>

<p style="color:#c9d1d9;margin-bottom:12px;">
<strong>Primary regions:</strong> {location_text if location_text else "Not determined"}
</p>

{f'<p style="color:#c9d1d9;margin-bottom:12px;"><strong>Key Observations:</strong></p>{observations_html}' if observations else ""}

<div style="background:#0d1117;border:1px solid #30363d;border-radius:6px;padding:12px 16px;margin-top:16px;">
    <p style="margin:0;color:#7d8590;font-size:0.85rem;"><em>This inventory was collected using Azure Resource Inventory (ARI). For detailed resource information, refer to the Excel workbook.</em></p>
</div>'''

    def _section_subscriptions(self) -> str:
        """Generate subscriptions overview section."""
        if not self.subscriptions:
            return ""

        rows = []
        for sub in self.subscriptions[:10]:
            name = sub.get("name", "Unknown")
            sub_id = sub.get("id", "")
            state = sub.get("state", "Unknown")

            # Truncate subscription ID for display
            short_id = f"{sub_id[:8]}...{sub_id[-4:]}" if sub_id and len(sub_id) > 12 else sub_id

            # State badge
            state_color = "#3fb950" if state.lower() == "enabled" else "#d29922"
            state_badge = f'<span style="color:{state_color};">{state}</span>'

            rows.append([name, short_id, state_badge])

        table = self.format_table(["Subscription Name", "ID", "State"], rows)

        return f'''<h2 style="color:#fff;font-size:1.25rem;margin:24px 0 16px;padding-bottom:8px;border-bottom:1px solid #30363d;">2. Subscription Overview</h2>

{table}'''

    def _section_compute(self) -> str:
        """Generate compute resources section."""
        vms = self.compute.get("virtualMachines", [])
        app_services = self.compute.get("appServices", [])
        functions = self.compute.get("functions", [])
        aks = self.compute.get("aks", [])
        vmss = self.compute.get("vmScaleSets", [])

        if not any([vms, app_services, functions, aks, vmss]):
            return f'''<h2 style="color:#fff;font-size:1.25rem;margin:24px 0 16px;padding-bottom:8px;border-bottom:1px solid #30363d;">3. Compute Resources</h2>
<p style="color:#7d8590;">No compute resources found in this inventory.</p>'''

        html_parts = ['''<h2 style="color:#fff;font-size:1.25rem;margin:24px 0 16px;padding-bottom:8px;border-bottom:1px solid #30363d;">3. Compute Resources</h2>''']

        # Virtual Machines analysis
        if vms:
            # Analyse VM sizes
            vm_by_size = {}
            vm_by_state = {"running": 0, "stopped": 0, "deallocated": 0, "other": 0}
            vm_by_os = {"Windows": 0, "Linux": 0, "Other": 0}

            for vm in vms:
                size = vm.get("vmSize", "Unknown")
                vm_by_size[size] = vm_by_size.get(size, 0) + 1

                state = (vm.get("powerState") or "").lower()
                if "running" in state:
                    vm_by_state["running"] += 1
                elif "stopped" in state:
                    vm_by_state["stopped"] += 1
                elif "deallocated" in state:
                    vm_by_state["deallocated"] += 1
                else:
                    vm_by_state["other"] += 1

                os_type = (vm.get("osType") or "").lower()
                if "windows" in os_type:
                    vm_by_os["Windows"] += 1
                elif "linux" in os_type:
                    vm_by_os["Linux"] += 1
                else:
                    vm_by_os["Other"] += 1

            # VM state breakdown
            state_html = f'''<p style="color:#c9d1d9;margin:12px 0;">
<strong>Power States:</strong>
<span style="color:#3fb950;">Running: {vm_by_state["running"]}</span> &bull;
<span style="color:#d29922;">Stopped: {vm_by_state["stopped"]}</span> &bull;
<span style="color:#f85149;">Deallocated: {vm_by_state["deallocated"]}</span>
</p>'''

            # OS breakdown
            os_html = f'''<p style="color:#c9d1d9;margin:12px 0;">
<strong>Operating Systems:</strong> Windows: {vm_by_os["Windows"]} &bull; Linux: {vm_by_os["Linux"]}
</p>'''

            # Top VM sizes table
            top_sizes = sorted(vm_by_size.items(), key=lambda x: -x[1])[:10]
            size_rows = []
            for size, count in top_sizes:
                # Determine size category
                prefix = size.split("_")[0].replace("Standard", "").strip("_") if "_" in size else size[:2]
                category_info = self.VM_SIZE_CATEGORIES.get(prefix[0].upper(), ("General", ""))
                size_rows.append([size, str(count), category_info[0]])

            size_table = self.format_table(["VM Size", "Count", "Category"], size_rows)

            html_parts.append(f'''<h3 style="color:#c9d1d9;font-size:1.1rem;margin:20px 0 12px;">Virtual Machines ({len(vms)})</h3>
{state_html}
{os_html}
<p style="color:#7d8590;font-size:0.9rem;margin:12px 0 8px;"><strong>VM Sizes:</strong></p>
{size_table}''')

        # App Services
        if app_services:
            running = sum(1 for a in app_services if (a.get("state") or "").lower() == "running")
            html_parts.append(f'''<h3 style="color:#c9d1d9;font-size:1.1rem;margin:20px 0 12px;">App Services ({len(app_services)})</h3>
<p style="color:#c9d1d9;"><span style="color:#3fb950;">{running} running</span> &bull; {len(app_services) - running} stopped/other</p>''')

        # Functions
        if functions:
            html_parts.append(f'''<h3 style="color:#c9d1d9;font-size:1.1rem;margin:20px 0 12px;">Azure Functions ({len(functions)})</h3>''')

        # AKS
        if aks:
            rows = []
            for cluster in aks[:5]:
                rows.append([
                    cluster.get("name", "Unknown"),
                    cluster.get("kubernetesVersion", "—"),
                    str(cluster.get("nodeCount", "—")),
                    self.REGION_NAMES.get(cluster.get("location", ""), cluster.get("location", "—"))
                ])
            aks_table = self.format_table(["Cluster Name", "K8s Version", "Nodes", "Region"], rows)
            html_parts.append(f'''<h3 style="color:#c9d1d9;font-size:1.1rem;margin:20px 0 12px;">AKS Clusters ({len(aks)})</h3>
{aks_table}''')

        # VM Scale Sets
        if vmss:
            html_parts.append(f'''<h3 style="color:#c9d1d9;font-size:1.1rem;margin:20px 0 12px;">VM Scale Sets ({len(vmss)})</h3>''')

        return "\n".join(html_parts)

    def _section_networking(self) -> str:
        """Generate networking section."""
        vnets = self.networking.get("virtualNetworks", [])
        nsgs = self.networking.get("networkSecurityGroups", [])
        lbs = self.networking.get("loadBalancers", [])
        app_gws = self.networking.get("applicationGateways", [])
        pips = self.networking.get("publicIPs", [])

        if not any([vnets, nsgs, lbs, app_gws, pips]):
            return f'''<h2 style="color:#fff;font-size:1.25rem;margin:24px 0 16px;padding-bottom:8px;border-bottom:1px solid #30363d;">4. Networking</h2>
<p style="color:#7d8590;">No networking resources found in this inventory.</p>'''

        html_parts = ['''<h2 style="color:#fff;font-size:1.25rem;margin:24px 0 16px;padding-bottom:8px;border-bottom:1px solid #30363d;">4. Networking</h2>''']

        # Summary counts
        summary_items = []
        if vnets:
            summary_items.append(f"<strong>{len(vnets)}</strong> Virtual Networks")
        if nsgs:
            summary_items.append(f"<strong>{len(nsgs)}</strong> Network Security Groups")
        if lbs:
            summary_items.append(f"<strong>{len(lbs)}</strong> Load Balancers")
        if app_gws:
            summary_items.append(f"<strong>{len(app_gws)}</strong> Application Gateways")
        if pips:
            summary_items.append(f"<strong>{len(pips)}</strong> Public IPs")

        html_parts.append(f'<p style="color:#c9d1d9;margin:12px 0;">{" &bull; ".join(summary_items)}</p>')

        # Virtual Networks table
        if vnets:
            rows = []
            for vnet in vnets[:10]:
                rows.append([
                    vnet.get("name", "Unknown"),
                    vnet.get("addressSpace", "—"),
                    self.REGION_NAMES.get(vnet.get("location", ""), vnet.get("location", "—")),
                    vnet.get("resourceGroup", "—")
                ])
            vnet_table = self.format_table(["VNet Name", "Address Space", "Region", "Resource Group"], rows)
            html_parts.append(f'''<h3 style="color:#c9d1d9;font-size:1.1rem;margin:20px 0 12px;">Virtual Networks</h3>
{vnet_table}''')

        # Public IPs (security consideration)
        if pips:
            assigned_pips = [p for p in pips if p.get("ipAddress")]
            html_parts.append(f'''<h3 style="color:#c9d1d9;font-size:1.1rem;margin:20px 0 12px;">Public IP Addresses</h3>
<p style="color:#c9d1d9;"><strong>{len(assigned_pips)}</strong> assigned public IPs detected — review for security exposure</p>''')

        return "\n".join(html_parts)

    def _section_storage_databases(self) -> str:
        """Generate storage and databases section."""
        storage_accounts = self.storage.get("storageAccounts", [])
        sql_servers = self.databases.get("sqlServers", [])
        sql_dbs = self.databases.get("sqlDatabases", [])
        cosmos = self.databases.get("cosmosDbAccounts", [])
        mysql = self.databases.get("mySqlServers", [])
        postgres = self.databases.get("postgreSqlServers", [])

        if not any([storage_accounts, sql_servers, sql_dbs, cosmos, mysql, postgres]):
            return f'''<h2 style="color:#fff;font-size:1.25rem;margin:24px 0 16px;padding-bottom:8px;border-bottom:1px solid #30363d;">5. Storage & Databases</h2>
<p style="color:#7d8590;">No storage or database resources found in this inventory.</p>'''

        html_parts = ['''<h2 style="color:#fff;font-size:1.25rem;margin:24px 0 16px;padding-bottom:8px;border-bottom:1px solid #30363d;">5. Storage & Databases</h2>''']

        # Storage Accounts
        if storage_accounts:
            # Analyse by tier and kind
            by_tier = {}
            by_kind = {}
            for sa in storage_accounts:
                tier = sa.get("accessTier", "Unknown")
                by_tier[tier] = by_tier.get(tier, 0) + 1
                kind = sa.get("kind", "Unknown")
                by_kind[kind] = by_kind.get(kind, 0) + 1

            tier_text = ", ".join([f"{k}: {v}" for k, v in sorted(by_tier.items(), key=lambda x: -x[1])])

            rows = []
            for sa in storage_accounts[:10]:
                rows.append([
                    sa.get("name", "Unknown"),
                    sa.get("kind", "—"),
                    sa.get("accessTier", "—"),
                    self.REGION_NAMES.get(sa.get("location", ""), sa.get("location", "—"))
                ])
            sa_table = self.format_table(["Storage Account", "Kind", "Access Tier", "Region"], rows)

            html_parts.append(f'''<h3 style="color:#c9d1d9;font-size:1.1rem;margin:20px 0 12px;">Storage Accounts ({len(storage_accounts)})</h3>
<p style="color:#c9d1d9;margin:8px 0;"><strong>By Tier:</strong> {tier_text}</p>
{sa_table}''')

        # SQL Databases
        if sql_servers or sql_dbs:
            html_parts.append(f'''<h3 style="color:#c9d1d9;font-size:1.1rem;margin:20px 0 12px;">Azure SQL</h3>
<p style="color:#c9d1d9;"><strong>{len(sql_servers)}</strong> SQL Servers &bull; <strong>{len(sql_dbs)}</strong> Databases</p>''')

        # Cosmos DB
        if cosmos:
            html_parts.append(f'''<h3 style="color:#c9d1d9;font-size:1.1rem;margin:20px 0 12px;">Cosmos DB ({len(cosmos)})</h3>''')

        # Other databases
        other_dbs = []
        if mysql:
            other_dbs.append(f"MySQL: {len(mysql)}")
        if postgres:
            other_dbs.append(f"PostgreSQL: {len(postgres)}")
        if other_dbs:
            html_parts.append(f'''<p style="color:#c9d1d9;margin:12px 0;"><strong>Other Databases:</strong> {" &bull; ".join(other_dbs)}</p>''')

        return "\n".join(html_parts)

    def _section_security(self) -> str:
        """Generate security section."""
        key_vaults = self.security.get("keyVaults", [])
        recommendations = self.security.get("recommendations", [])

        html_parts = ['''<h2 style="color:#fff;font-size:1.25rem;margin:24px 0 16px;padding-bottom:8px;border-bottom:1px solid #30363d;">6. Security Posture</h2>''']

        # Key Vaults
        if key_vaults:
            rows = []
            for kv in key_vaults[:10]:
                rows.append([
                    kv.get("name", "Unknown"),
                    self.REGION_NAMES.get(kv.get("location", ""), kv.get("location", "—")),
                    kv.get("resourceGroup", "—")
                ])
            kv_table = self.format_table(["Key Vault", "Region", "Resource Group"], rows)
            html_parts.append(f'''<h3 style="color:#c9d1d9;font-size:1.1rem;margin:20px 0 12px;">Key Vaults ({len(key_vaults)})</h3>
{kv_table}''')
        else:
            html_parts.append('''<p style="color:#d29922;margin:12px 0;">⚠️ <strong>No Key Vaults detected</strong> — consider implementing centralised secrets management</p>''')

        # Security Center recommendations
        if recommendations:
            # Group by severity
            by_severity = {"High": [], "Medium": [], "Low": []}
            for rec in recommendations:
                severity = rec.get("severity", "Low")
                if severity in by_severity:
                    by_severity[severity].append(rec)

            html_parts.append(f'''<h3 style="color:#c9d1d9;font-size:1.1rem;margin:20px 0 12px;">Security Recommendations ({len(recommendations)})</h3>
<p style="color:#c9d1d9;">
<span style="color:#f85149;">High: {len(by_severity["High"])}</span> &bull;
<span style="color:#d29922;">Medium: {len(by_severity["Medium"])}</span> &bull;
<span style="color:#3fb950;">Low: {len(by_severity["Low"])}</span>
</p>''')

            # Show top high severity recommendations
            if by_severity["High"]:
                rows = []
                for rec in by_severity["High"][:10]:
                    rows.append([
                        rec.get("recommendation", "Unknown")[:80],
                        self.risk_badge("High")
                    ])
                rec_table = self.format_table(["Recommendation", "Severity"], rows, highlight_col=1)
                html_parts.append(f'''<p style="color:#7d8590;font-size:0.9rem;margin:12px 0 8px;"><strong>Top High-Severity Findings:</strong></p>
{rec_table}''')
        else:
            html_parts.append('''<p style="color:#7d8590;margin:12px 0;"><em>Security Center recommendations not included in this scan. Enable "Include Security Center" option for security findings.</em></p>''')

        return "\n".join(html_parts)

    def _section_cost_optimisation(self) -> str:
        """Generate cost optimisation opportunities section."""
        vms = self.compute.get("virtualMachines", [])
        storage_accounts = self.storage.get("storageAccounts", [])

        html_parts = ['''<h2 style="color:#fff;font-size:1.25rem;margin:24px 0 16px;padding-bottom:8px;border-bottom:1px solid #30363d;">7. Cost Optimisation Opportunities</h2>''']

        opportunities = []

        # Stopped/Deallocated VMs
        stopped_vms = [vm for vm in vms if "stopped" in (vm.get("powerState") or "").lower() or "deallocated" in (vm.get("powerState") or "").lower()]
        if stopped_vms:
            vm_list = ", ".join([vm.get("name", "Unknown") for vm in stopped_vms[:5]])
            if len(stopped_vms) > 5:
                vm_list += f" +{len(stopped_vms) - 5} more"
            opportunities.append({
                "title": f"Stopped/Deallocated VMs ({len(stopped_vms)})",
                "description": f"Review for deletion or snapshot-and-delete: {vm_list}",
                "impact": "High" if len(stopped_vms) > 3 else "Medium",
                "type": "cleanup"
            })

        # Reserved Instance candidates (running VMs)
        running_vms = [vm for vm in vms if "running" in (vm.get("powerState") or "").lower()]
        if len(running_vms) >= 3:
            opportunities.append({
                "title": f"Reserved Instance Candidates ({len(running_vms)} running VMs)",
                "description": "Long-running VMs may benefit from 1 or 3-year Reserved Instance pricing (up to 72% savings)",
                "impact": "High",
                "type": "savings"
            })

        # Storage tier optimisation
        hot_storage = [sa for sa in storage_accounts if (sa.get("accessTier") or "").lower() == "hot"]
        if len(hot_storage) > 3:
            opportunities.append({
                "title": f"Storage Tier Review ({len(hot_storage)} Hot tier accounts)",
                "description": "Evaluate if Cool or Archive tier is appropriate for infrequently accessed data",
                "impact": "Medium",
                "type": "savings"
            })

        # Single region deployment
        locations = self.summary.get("resourcesByLocation", {})
        if len(locations) == 1:
            opportunities.append({
                "title": "Single Region Deployment",
                "description": "All resources in one region. Consider DR requirements vs. cost trade-offs",
                "impact": "Low",
                "type": "architecture"
            })

        if opportunities:
            for opp in opportunities:
                impact_color = {"High": "#f85149", "Medium": "#d29922", "Low": "#3fb950"}.get(opp["impact"], "#7d8590")
                html_parts.append(f'''<div style="background:#161b22;border:1px solid #30363d;border-radius:6px;padding:12px 16px;margin:12px 0;">
    <div style="display:flex;justify-content:space-between;align-items:center;">
        <strong style="color:#c9d1d9;">{opp["title"]}</strong>
        <span style="color:{impact_color};font-size:0.85rem;font-weight:600;">{opp["impact"]} Impact</span>
    </div>
    <p style="color:#7d8590;margin:8px 0 0;font-size:0.9rem;">{opp["description"]}</p>
</div>''')
        else:
            html_parts.append('<p style="color:#7d8590;">No immediate cost optimisation opportunities identified. Consider Azure Advisor for detailed recommendations.</p>')

        return "\n".join(html_parts)

    def _section_recommendations(self) -> str:
        """Generate recommendations roadmap section."""
        vms = self.compute.get("virtualMachines", [])
        key_vaults = self.security.get("keyVaults", [])
        locations = self.summary.get("resourcesByLocation", {})
        recommendations_data = self.security.get("recommendations", [])

        immediate = []
        short_term = []
        strategic = []

        # Build recommendations based on analysis
        stopped_vms = [vm for vm in vms if "stopped" in (vm.get("powerState") or "").lower() or "deallocated" in (vm.get("powerState") or "").lower()]
        if stopped_vms:
            immediate.append("Review and clean up stopped/deallocated VMs to reduce storage costs")

        if not key_vaults:
            immediate.append("Implement Azure Key Vault for centralised secrets management")

        high_severity = [r for r in recommendations_data if r.get("severity") == "High"]
        if high_severity:
            immediate.append(f"Address {len(high_severity)} high-severity security recommendations from Defender")

        # Short-term
        running_vms = [vm for vm in vms if "running" in (vm.get("powerState") or "").lower()]
        if len(running_vms) >= 3:
            short_term.append("Analyse VM utilisation and implement Reserved Instances for stable workloads")

        short_term.append("Review and optimise storage account tiers based on access patterns")
        short_term.append("Implement resource tagging strategy for cost allocation and governance")

        # Strategic
        if len(locations) == 1:
            strategic.append("Evaluate multi-region deployment for disaster recovery")

        strategic.append("Consider Azure Landing Zones for improved governance at scale")
        strategic.append("Implement Azure Policy for compliance and resource standardisation")

        html_parts = ['''<h2 style="color:#fff;font-size:1.25rem;margin:24px 0 16px;padding-bottom:8px;border-bottom:1px solid #30363d;">8. Recommendations Roadmap</h2>''']

        if immediate:
            html_parts.append('''<h3 style="color:#f85149;font-size:1rem;margin:16px 0 8px;">Immediate (0-30 days)</h3>
<ul style="margin:8px 0;padding-left:20px;color:#c9d1d9;">''')
            for rec in immediate[:5]:
                html_parts.append(f'<li>{rec}</li>')
            html_parts.append('</ul>')

        if short_term:
            html_parts.append('''<h3 style="color:#d29922;font-size:1rem;margin:16px 0 8px;">Short-term (1-3 months)</h3>
<ul style="margin:8px 0;padding-left:20px;color:#c9d1d9;">''')
            for rec in short_term[:5]:
                html_parts.append(f'<li>{rec}</li>')
            html_parts.append('</ul>')

        if strategic:
            html_parts.append('''<h3 style="color:#58a6ff;font-size:1rem;margin:16px 0 8px;">Strategic (3-6 months)</h3>
<ul style="margin:8px 0;padding-left:20px;color:#c9d1d9;">''')
            for rec in strategic[:3]:
                html_parts.append(f'<li>{rec}</li>')
            html_parts.append('</ul>')

        return "\n".join(html_parts)

    def _section_conclusion(self) -> str:
        """Generate conclusion section."""
        total_resources = self.summary.get("totalResources", 0)
        subscription_count = self.summary.get("subscriptionCount", 0)
        vms = self.compute.get("virtualMachines", [])

        # Determine overall assessment
        stopped_vms = len([vm for vm in vms if "stopped" in (vm.get("powerState") or "").lower() or "deallocated" in (vm.get("powerState") or "").lower()])
        key_vaults = len(self.security.get("keyVaults", []))
        high_severity = len([r for r in self.security.get("recommendations", []) if r.get("severity") == "High"])

        if high_severity > 5 or (key_vaults == 0 and len(vms) > 5):
            posture = "requires attention"
            posture_color = "#d29922"
        elif stopped_vms > 5 or high_severity > 0:
            posture = "has optimisation opportunities"
            posture_color = "#58a6ff"
        else:
            posture = "is well-maintained"
            posture_color = "#3fb950"

        return f'''<h2 style="color:#fff;font-size:1.25rem;margin:24px 0 16px;padding-bottom:8px;border-bottom:1px solid #30363d;">9. Conclusion</h2>

<p style="color:#c9d1d9;margin-bottom:12px;">
This Azure environment with <strong>{total_resources:,} resources</strong> across <strong>{subscription_count} subscription(s)</strong>
<span style="color:{posture_color};font-weight:600;">{posture}</span>.
</p>

<p style="color:#c9d1d9;margin-bottom:12px;"><strong>Recommended Next Steps:</strong></p>
<ol style="margin:8px 0;padding-left:20px;color:#c9d1d9;">
    <li>Review the full Excel inventory for detailed resource information</li>
    <li>Address any immediate recommendations identified above</li>
    <li>Schedule a follow-up session to discuss cost optimisation strategies</li>
    <li>Consider enabling Azure Defender for comprehensive security monitoring</li>
</ol>

<div style="background:linear-gradient(90deg,rgba(232,31,99,0.1),rgba(123,31,162,0.1),rgba(3,155,229,0.1));border:1px solid #30363d;border-radius:6px;padding:16px;margin-top:24px;">
    <p style="margin:0;color:#c9d1d9;font-size:0.9rem;"><strong>Need help implementing these recommendations?</strong> Our team can assist with Azure optimisation, security hardening, and managed services.</p>
</div>'''
