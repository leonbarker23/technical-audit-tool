"""
Python-templated report generators for instant structured reports.

This module provides template-based report generation without LLM dependencies.
All risk assessment and analysis is done in pure Python for speed and consistency.
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
    def format_table(headers: List[str], rows: List[List[str]]) -> str:
        """
        Format a markdown table.

        Args:
            headers: List of column headers
            rows: List of rows, each row is a list of cell values

        Returns:
            Formatted markdown table string
        """
        if not headers or not rows:
            return ""

        lines = []
        # Header row
        lines.append("| " + " | ".join(headers) + " |")
        # Separator
        lines.append("|" + "|".join(["---"] * len(headers)) + "|")
        # Data rows
        for row in rows:
            lines.append("| " + " | ".join(str(cell) for cell in row) + " |")

        return "\n".join(lines)

    @staticmethod
    def format_bullet_list(items: List[str], indent: int = 0) -> str:
        """Format a markdown bullet list with optional indentation."""
        prefix = "  " * indent + "- "
        return "\n".join([prefix + item for item in items])


class M365TemplatedReport(ReportSection):
    """Python-templated Microsoft 365 assessment report generator."""

    def generate(self) -> str:
        """Generate complete M365 assessment report."""
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

        return "\n\n".join([s for s in sections if s])

    def _header(self) -> str:
        """Generate report header."""
        metadata = self.assessment_data.get("metadata", {})

        return f"""# Microsoft 365 Assessment Report

**Client:** {metadata.get('clientName', 'Unknown')}
**Tenant:** {metadata.get('tenantName', 'Unknown')}
**Primary Domain:** {metadata.get('primaryDomain', 'Unknown')}
**Assessment Date:** {metadata.get('assessmentDate', 'Unknown')}

---"""

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
                ["MFA Registration", f"{mfa_pct}% registered", f"**{mfa_risk}**"],
                ["Microsoft Secure Score", f"{secure_score_pct}%", f"**{score_risk}**"],
                ["Privileged Access", f"{global_admins} Global Admins", f"**{admin_risk}**"]
            ]
        )

        return f"""## 1. Executive Summary

**Overall Security Posture:** **{overall_risk} Risk**

**Total Users:** {total_users:,}
**Licensed Users:** {licensing.get('licensedUsers', 0):,}
**Guest Users:** {licensing.get('guestUsers', 0):,}

### Key Findings

{findings_table}

### Top Priorities

1. **MFA:** {mfa_rec}
2. **Privileged Access:** {admin_rec}
3. **Security Score:** {"Improve score from current " + str(secure_score_pct) + "% by implementing top recommendations"}

### Assessment Scope

This assessment analyzed:
- Identity & Access Management (MFA, Conditional Access, privileged accounts)
- Microsoft Secure Score & security recommendations
- Device management via Microsoft Intune
- License utilization & waste detection
- User account hygiene (stale accounts, guest access)
- Security test results (Maester framework)"""

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
            return "## 2. Licensing Overview\n\nNo paid license information available."

        # Build license table
        license_rows = []
        total_assigned = 0
        total_available = 0

        for sku in paid_skus[:15]:  # Limit to top 15
            sku_name = sku.get('skuPartNumber', 'Unknown')
            consumed = sku.get('consumedUnits', 0)
            prepaid = sku.get('prepaidUnits', 0)
            utilization = round((consumed / prepaid) * 100, 1) if prepaid > 0 else 0

            license_rows.append([sku_name, str(consumed), str(prepaid), f"{utilization}%"])
            total_assigned += consumed
            total_available += prepaid

        license_table = self.format_table(
            ["License SKU", "Assigned", "Available", "Utilization"],
            license_rows
        )

        overall_utilization = round((total_assigned / total_available) * 100, 1) if total_available > 0 else 0

        # Utilization assessment
        if overall_utilization > 95:
            util_status = "**High Risk** - License capacity nearly exhausted, consider purchasing more"
        elif overall_utilization > 85:
            util_status = "**Medium Risk** - License utilization high, monitor closely"
        elif overall_utilization < 50:
            util_status = "**Low Risk** - Underutilized licenses, consider reducing for cost optimization"
        else:
            util_status = "**Low Risk** - License utilization healthy"

        return f"""## 2. Licensing Overview

### Subscribed Licenses (Paid Only)

{license_table}

**Total:** {total_assigned:,} assigned / {total_available:,} available ({overall_utilization}% utilization)

**Utilization Status:** {util_status}

### License SKU Reference

- **SPE_E3** = Microsoft 365 E3
- **SPE_E5** = Microsoft 365 E5
- **SPE_A3 / M365EDU_A3** = Microsoft 365 A3 (Education)
- **SPE_A5 / M365EDU_A5** = Microsoft 365 A5 (Education)
- **ENTERPRISEPACK** = Office 365 E3
- **ENTERPRISEPREMIUM** = Office 365 E5
- **AAD_PREMIUM_P1** = Entra ID P1
- **AAD_PREMIUM_P2** = Entra ID P2
- **EMS** = Enterprise Mobility + Security
- **ATP_ENTERPRISE** = Microsoft Defender for Office 365
- **INTUNE_A** = Microsoft Intune"""

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

        return "## 3. Identity & Access Management\n\n" + "\n\n".join(sections)

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
            gap_status = "✅ **Good** - High registration + strong enforcement"
        elif pct >= 80 and enforcement_method == "Conditional Access (partial)":
            gap_status = "⚠️ **Medium** - Users ready but enforcement incomplete"
        elif pct < 80 and enforcement_method in ["Security Defaults", "Conditional Access (all users)"]:
            gap_status = "⚠️ **Medium** - Strong enforcement will prompt registration at next sign-in"
        else:
            gap_status = "❌ **Critical Gap** - Low registration and weak enforcement"

        result = f"""### MFA Status

- **Registration:** {registered:,} / {total:,} users ({pct}%) have registered an MFA method
- **Enforcement Method:** {enforcement_method}
- **Gap Analysis:** {gap_status}
- **Risk Level:** **{risk}**
- **Recommendation:** {rec}"""

        # Add enforcement policy details if partial
        if enforcement_method == "Conditional Access (partial)":
            policies = mfa_enforcement.get("policies", [])
            if policies:
                result += "\n\n**MFA-Requiring Policies:**"
                for policy in policies[:5]:  # Limit to 5
                    result += f"\n- {policy.get('displayName', 'Unknown')}: {policy.get('userScope', 'Unknown')} / {policy.get('appScope', 'Unknown')}"

        return result

    def _build_conditional_access_subsection(self, identity: dict) -> str:
        """Build Conditional Access subsection."""
        ca_policies = identity.get("conditionalAccess", [])

        if not ca_policies:
            return "### Conditional Access\n\nNo Conditional Access policies found."

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

        return f"""### Conditional Access

- **Total Policies:** {total_count}
- **Enabled Policies:** {enabled_count}
- **Risk Level:** **{risk}**
- **Recommendation:** {rec}

**Best Practice:** Minimum 5 CA policies recommended covering MFA, device compliance, location-based access, high-risk sign-ins, and privileged accounts."""

    def _build_privileged_access_subsection(self, identity: dict, governance: dict) -> str:
        """Build privileged access subsection."""
        priv_access = identity.get("privilegedAccess", {})
        global_admins = priv_access.get("globalAdminCount", 0)
        active_roles = priv_access.get("directoryRolesActive", 0)

        total_users = int(self.assessment_data.get("licensing", {}).get("totalUsers", 0) or 0)
        risk, rec = self._assess_global_admin_risk(global_admins, total_users)

        result = f"""### Privileged Access

- **Global Administrators:** {global_admins}
- **Active Directory Roles:** {active_roles}
- **Risk Level:** **{risk}**
- **Recommendation:** {rec}"""

        # Add role breakdown
        admin_roles = governance.get("adminRoles", [])
        if admin_roles:
            result += "\n\n**Top Admin Roles:**"
            for role in sorted(admin_roles, key=lambda x: -x.get('memberCount', 0))[:8]:
                result += f"\n- {role.get('roleName', 'Unknown')}: {role.get('memberCount', 0)} members"

        return result

    def _section_4_secure_score(self) -> str:
        """Generate Microsoft Secure Score section."""
        security_score = self.assessment_data.get("securityScore", {})

        current = security_score.get("currentScore", 0)
        maximum = security_score.get("maxScore", 0)
        pct = security_score.get("percentage", 0)
        identity_pct = security_score.get("identityScore", {}).get("percentage", 0)

        risk = self._assess_secure_score_risk(pct)

        recommendations = security_score.get("recommendations", [])[:10]  # Top 10

        rec_list = ""
        if recommendations:
            rec_list = "\n### Top 10 Security Recommendations\n\n"
            for i, rec in enumerate(recommendations, 1):
                title = rec.get("title", "Unknown")
                max_score = rec.get("maxScore", 0)
                rec_list += f"{i}. **{title}** (+{max_score} points)\n"

        return f"""## 4. Microsoft Secure Score

- **Current Score:** {current} / {maximum} ({pct}%)
- **Identity Score:** {identity_pct}%
- **Risk Level:** **{risk}**

**Performance Assessment:**
{"- ✅ Excellent security posture" if pct >= 80 else ""}{"- ✅ Good security posture, room for improvement" if 60 <= pct < 80 else ""}{"- ⚠️ Below average security posture, prioritize improvements" if 40 <= pct < 60 else ""}{"- ❌ Poor security posture, immediate action required" if pct < 40 else ""}

{rec_list}"""

    def _section_5_user_account_health(self) -> str:
        """Generate User Account Health section (reuse existing Python logic)."""
        # Import the existing function from app.py
        # For now, we'll implement inline, but we should refactor to avoid duplication

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

            stale_section = f"""### Stale Accounts
- **90+ days inactive:** {stale_90} users ({stale_pct}% of workforce)
- **180+ days:** {stale_180} | **365+ days:** {stale_365} | **Never signed in:** {never}
- **Risk Level:** {risk}
- **Recommendation:** {recommendation}"""

            top_stale = stale.get("topStaleWithLicenses", [])
            if top_stale:
                stale_section += "\n\n**Top stale accounts with licenses (priority for cleanup):**"
                for user in top_stale[:max_stale_users]:
                    stale_section += f"\n- {user.get('displayName', 'Unknown')} - Last sign-in: {user.get('lastSignIn', 'Never')}, Licenses: {user.get('licenseCount', 0)}"

            sections.append(stale_section)

        # Guest Analysis
        guest = insights.get("guestAnalysis", {})
        if guest and guest.get("totalGuests", 0) > 0:
            total_guests = guest.get("totalGuests", 0)
            active = guest.get("activeGuests", 0)
            inactive = guest.get("inactiveGuests", 0)
            never = guest.get("neverSignedIn", 0)
            active_pct = round((active / total_guests) * 100, 1) if total_guests > 0 else 0
            inactive_pct = round(((inactive + never) / total_guests) * 100, 1) if total_guests > 0 else 0

            # Risk assessment
            if inactive_pct > 70:
                risk = "High"
                recommendation = "Implement guest access review - majority of guests are inactive"
            elif inactive_pct > 50:
                risk = "Medium"
                recommendation = "Schedule guest access audit"
            else:
                risk = "Low"
                recommendation = "Continue periodic guest reviews"

            guest_section = f"""### Guest Account Hygiene
- **Total guests:** {total_guests}
- **Active (90 days):** {active} ({active_pct}%) | **Inactive:** {inactive} | **Never signed in:** {never}
- **Risk Level:** {risk}
- **Recommendation:** {recommendation}"""

            top_domains = guest.get("topDomains", [])
            if top_domains:
                guest_section += "\n\n**Top external domains:**"
                for domain in top_domains[:max_domains]:
                    guest_section += f"\n- {domain.get('domain', 'Unknown')}: {domain.get('count', 0)} guests"

            sections.append(guest_section)

        # License Waste
        waste = insights.get("licenseWaste", {})
        if waste and waste.get("inactiveUsers", 0) > 0:
            inactive_users = waste.get("inactiveUsers", 0)
            licenses = waste.get("licensesAffected", 0)
            monthly = waste.get("estimatedMonthlyGBP", 0)
            annual = round(monthly * 12, 2)

            # Priority assessment
            if monthly > 1000:
                priority = "Critical"
                recommendation = f"Immediate action - potential annual savings of GBP {annual:,.2f}"
            elif monthly > 500:
                priority = "High"
                recommendation = f"Review and reclaim - potential annual savings of GBP {annual:,.2f}"
            elif monthly > 100:
                priority = "Medium"
                recommendation = "Include in quarterly license review"
            else:
                priority = "Low"
                recommendation = "Monitor in regular reviews"

            waste_section = f"""### License Waste
- **Inactive licensed users:** {inactive_users} (90+ days no sign-in)
- **Licenses affected:** {licenses}
- **Estimated monthly waste:** GBP {monthly:,.2f}
- **Potential annual savings:** GBP {annual:,.2f}
- **Priority:** {priority}
- **Recommendation:** {recommendation}"""

            by_license = waste.get("byLicense", [])
            if by_license:
                waste_section += "\n\n**Waste by license type:**"
                for lic in by_license[:8]:
                    waste_section += f"\n- {lic.get('skuName', 'Unknown')}: {lic.get('count', 0)} inactive (GBP {lic.get('monthlyCost', 0):,.2f}/month)"

            sections.append(waste_section)

        # Enhanced MFA
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

            mfa_section = f"""### MFA Method Analysis
- **MFA Capable:** {capable} users
- **MFA Registered:** {registered} users
- **SMS-Only (weak MFA):** {sms_only} users
- **Passwordless Capable:** {passwordless} users
- **Risk Level:** {mfa_risk}
- **Recommendation:** {mfa_rec}"""

            methods = mfa.get("methodBreakdown", [])
            if methods:
                mfa_section += "\n\n**Authentication methods in use:**"
                for method in methods[:8]:
                    mfa_section += f"\n- {method.get('method', 'Unknown')}: {method.get('count', 0)} users"

            sections.append(mfa_section)

        if not sections:
            return ""

        return "## 5. User Account Health\n\n" + "\n\n".join(sections)

    def _section_6_device_management(self) -> str:
        """Generate Device Management (Intune) section."""
        intune = self.assessment_data.get("intune", {})
        devices = intune.get("managedDevices", {})

        if not devices or devices.get("total", 0) == 0:
            return "## 6. Device Management (Intune)\n\nIntune data not available (license may be required)."

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

        compliance_policies = intune.get("compliancePolicies", [])
        config_profiles = intune.get("configurationProfiles", [])
        app_protection = intune.get("appProtectionPolicies", [])

        return f"""## 6. Device Management (Intune)

### Managed Devices

- **Total Devices:** {total:,}
- **Compliant:** {compliant:,} ({compliance_rate}%)
- **Non-Compliant:** {non_compliant:,}
- **Risk Level:** **{risk}**
- **Recommendation:** {rec}

### Policies & Profiles

- **Compliance Policies:** {len(compliance_policies)}
- **Configuration Profiles:** {len(config_profiles)}
- **App Protection Policies:** {len(app_protection)}

**Best Practice:** Minimum 3 compliance policies (Windows, iOS, Android) and 5 configuration profiles for baseline security."""

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
            immediate.append("**Implement MFA enforcement** via Conditional Access policies covering all users and applications")

        # Secure Score
        score_pct = security_score.get("percentage", 0)
        if score_pct < 60:
            immediate.append(f"**Improve Secure Score** from {score_pct}% by implementing top 5 recommendations")

        # Global Admins
        total_users = int(data.get("licensing", {}).get("totalUsers", 0) or 0)
        global_admins = identity.get("privilegedAccess", {}).get("globalAdminCount", 0)
        if global_admins > 5 or (total_users > 0 and (global_admins / total_users) > 0.05):
            immediate.append(f"**Reduce Global Admin count** from {global_admins} to 3-5 users maximum")

        # CA Policies
        ca_policies = identity.get("conditionalAccess", [])
        enabled_ca = [p for p in ca_policies if p.get("state") == "enabled"]
        if len(enabled_ca) < 5:
            short_term.append("**Expand Conditional Access policies** - implement minimum 5 policies covering MFA, device compliance, location-based access, high-risk sign-ins, and privileged accounts")

        # Stale accounts
        stale = insights.get("staleAccounts", {})
        if stale and stale.get("stale90Days", 0) > 0:
            stale_pct = round((stale.get("stale90Days", 0) / stale.get("totalAnalysed", 1)) * 100, 1)
            if stale_pct > 20:
                immediate.append(f"**Cleanup stale accounts** - {stale.get('stale90Days', 0)} users inactive 90+ days ({stale_pct}% of workforce)")

        # License waste
        waste = insights.get("licenseWaste", {})
        if waste and waste.get("estimatedMonthlyGBP", 0) > 500:
            monthly = waste.get("estimatedMonthlyGBP", 0)
            annual = monthly * 12
            immediate.append(f"**Reclaim wasted licenses** - GBP {monthly:,.2f}/month waste identified (potential annual savings: GBP {annual:,.2f})")

        # Intune
        intune = data.get("intune", {})
        devices = intune.get("managedDevices", {})
        if devices.get("complianceRate", 0) < 85:
            short_term.append(f"**Improve device compliance** - current rate {devices.get('complianceRate', 0)}%, target 95%+")

        # Strategic recommendations
        strategic.append("**Implement Zero Trust architecture** - layered security with identity verification, device compliance, and least-privilege access")
        strategic.append("**Deploy Microsoft Defender for Endpoint** - advanced threat protection and EDR capabilities")
        strategic.append("**Establish Security Operations Center (SOC)** - 24/7 monitoring and incident response")

        # Build section
        result = "## 7. Project Recommendations\n\n"

        if immediate:
            result += "### Immediate Actions (0-30 days)\n\n"
            result += self.format_bullet_list(immediate)
            result += "\n\n"

        if short_term:
            result += "### Short-term Improvements (1-3 months)\n\n"
            result += self.format_bullet_list(short_term)
            result += "\n\n"

        if strategic:
            result += "### Strategic Initiatives (3-12 months)\n\n"
            result += self.format_bullet_list(strategic)

        return result

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

        priority_text = ""
        if top_3:
            priority_text = "\n\n### Top 3 Priorities\n\n"
            for i, (area, risk) in enumerate(top_3, 1):
                priority_text += f"{i}. **{area}** (Risk: {risk})\n"

        return f"""## 8. Conclusion

This assessment provides a comprehensive analysis of your Microsoft 365 tenant's security posture. The findings highlight both strengths and areas requiring attention.
{priority_text}

### Next Steps

1. **Review this report** with your IT security team and key stakeholders
2. **Prioritize remediation** based on risk levels and business impact
3. **Develop an action plan** with timelines and resource allocation
4. **Schedule follow-up assessment** in 3-6 months to measure progress

### MSP Support Opportunities

- **Project-based remediation** for immediate and short-term actions
- **Managed security services** for ongoing monitoring and compliance
- **License optimization** to reduce waste and improve utilization
- **Zero Trust implementation** for long-term security maturity

---

*Report generated by AAG Technical Audit Tool*
*Assessment date: {self.assessment_data.get('metadata', {}).get('assessmentDate', 'Unknown')}*"""

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

        if count > 5 or ratio > 0.05:
            return "High", f"Too many Global Admins ({count}), recommend max 3-5 following least privilege principle"
        elif count > 3:
            return "Medium", "Consider reducing Global Admin count to 3 or fewer"
        elif count == 0:
            return "High", "No Global Admins detected - at least 2 required for redundancy"
        else:
            return "Low", "Global Admin count follows best practices"
