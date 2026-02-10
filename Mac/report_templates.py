"""
Python-templated report generators for instant structured reports.

This module provides template-based report generation without LLM dependencies.
All risk assessment and analysis is done in pure Python for speed and consistency.
Reports are generated as HTML for clean web UI rendering.
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
