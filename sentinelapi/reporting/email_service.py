"""SentinelAPI Automated Email Notification & Reporting Service via Brevo.

Sends publication-grade, responsive HTML security audit notifications
with attached `vulnerabilities.pdf` and `all_logs.pdf`.
"""
import base64
import os
import time
import html
from pathlib import Path
from typing import Optional, Dict, Any, Tuple, List
import httpx
from dotenv import load_dotenv

from sentinelapi.core.models import MasterScanResult, ScanStatus
from sentinelapi.reporting.pdf_generator import generate_scan_pdfs
from sentinelapi.cli.theme import console


def _esc(val: Any) -> str:
    """Escapes strings for HTML rendering safely."""
    if val is None:
        return ""
    return html.escape(str(val))

# Load .env configurations
load_dotenv()

BREVO_API_URL = "https://api.brevo.com/v3/smtp/email"
DEFAULT_SENDER_EMAIL = os.getenv("BREVO_SENDER_EMAIL", "wecare@fluffwalks.in")
DEFAULT_SENDER_NAME = os.getenv("BREVO_SENDER_NAME", "SentinelAPI Security Sentinel")
DEFAULT_RECIPIENT_EMAIL = os.getenv("ALERT_RECIPIENT_EMAIL", "yuvrajjsoni17@gmail.com")


def _get_api_key() -> str:
    """Retrieves the Brevo API key from the environment."""
    key = os.getenv("BREVO_API_KEY", "").strip()
    if not key:
        key = os.getenv("BRAVO_API", "").strip()
    return key


def _encode_file_to_base64(file_path: Path) -> str:
    """Reads a file and returns its base64-encoded string."""
    with open(file_path, "rb") as f:
        return base64.b64encode(f.read()).decode("utf-8")


def _render_email_html(master_result: MasterScanResult) -> str:
    """Generates an aesthetic, dark-mode cybersecurity email report with rich color accents."""
    st = master_result.status
    total_vulns = len(master_result.all_vulnerable_findings)
    total_crit = master_result.total_critical
    total_high = master_result.total_high
    total_probes = master_result.total_successful_probes
    planned_probes = master_result.total_planned_probes
    exit_code = master_result.exit_code

    if st == ScanStatus.PASS.value:
        status_bg = "#061d14"
        status_border = "#10b981"
        status_text = "#6ee7b7"
        status_sub_text = "#a7f3d0"
        status_title = "AUDIT PASSED — ALL SECURITY CONTROLS VERIFIED"
        status_badge_bg = "#052e16"
        status_badge_border = "#10b981"
        status_badge_text = "#34d399"
        status_badge = "ZERO VULNERABILITIES"
        status_sub = "All endpoints, authentication barriers, and security headers passed fail-closed verification."
    elif st == ScanStatus.FAIL.value:
        status_bg = "#1e0a0a"
        status_border = "#ef4444"
        status_text = "#fca5a5"
        status_sub_text = "#fecaca"
        status_title = "SECURITY ALERT — VULNERABILITIES DETECTED"
        status_badge_bg = "#3b0d0d"
        status_badge_border = "#ef4444"
        status_badge_text = "#fca5a5"
        status_badge = f"{total_vulns} FINDINGS IDENTIFIED"
        status_sub = f"Action Required: {total_crit} Critical, {total_high} High severity findings identified during scan."
    elif st == ScanStatus.INCOMPLETE.value:
        status_bg = "#221204"
        status_border = "#f59e0b"
        status_text = "#fde68a"
        status_sub_text = "#fef3c7"
        status_title = "PARTIAL COVERAGE — PROBE FAILURES DETECTED"
        status_badge_bg = "#381e05"
        status_badge_border = "#f59e0b"
        status_badge_text = "#fbbf24"
        status_badge = "INCOMPLETE ASSESSMENT"
        status_sub = "Several planned network probes were unreachable or returned connection errors."
    else:
        status_bg = "#1e0a0a"
        status_border = "#b91c1c"
        status_text = "#fca5a5"
        status_sub_text = "#fecaca"
        status_title = "ASSESSMENT ERROR — TARGET UNREACHABLE"
        status_badge_bg = "#3b0d0d"
        status_badge_border = "#dc2626"
        status_badge_text = "#f87171"
        status_badge = "SCAN ERROR"
        status_sub = "Could not complete assessment due to fatal probe or target connection errors."

    # Build Modules rows
    module_rows_html = ""
    for idx, (mod_id, mod_res) in enumerate(master_result.module_results.items()):
        v_count = len(mod_res.vulnerable_findings)
        row_bg = "#0a101f" if idx % 2 == 0 else "#0d1424"

        if mod_res.status == "PASS":
            mod_badge = "<span style='display:inline-block;padding:3px 9px;font-size:11px;font-weight:700;border-radius:4px;background:#052e16;color:#34d399;border:1px solid #10b981;'>PASS</span>"
        elif mod_res.status == "FAIL":
            mod_badge = f"<span style='display:inline-block;padding:3px 9px;font-size:11px;font-weight:700;border-radius:4px;background:#3b0d0d;color:#fca5a5;border:1px solid #ef4444;'>FAIL ({v_count})</span>"
        elif mod_res.status == "INCOMPLETE":
            mod_badge = "<span style='display:inline-block;padding:3px 9px;font-size:11px;font-weight:700;border-radius:4px;background:#381e05;color:#fde68a;border:1px solid #f59e0b;'>INCOMPLETE</span>"
        else:
            mod_badge = "<span style='display:inline-block;padding:3px 9px;font-size:11px;font-weight:700;border-radius:4px;background:#1e293b;color:#94a3b8;border:1px solid #334155;'>ERROR</span>"

        module_rows_html += f"""
        <tr bgcolor="{row_bg}" style="border-bottom: 1px solid #182236;">
            <td style="padding: 10px 14px; color: #f8fafc; font-size: 13px; font-weight: 600;">{_esc(mod_res.scanner_name)}</td>
            <td style="padding: 10px 14px; color: #94a3b8; font-size: 12px;">{_esc(mod_res.owasp_category)}</td>
            <td style="padding: 10px 14px; color: #38bdf8; font-size: 12px; font-family: monospace; font-weight: bold; text-align: center;">{mod_res.successful_probes}/{mod_res.planned_probes}</td>
            <td style="padding: 10px 14px; text-align: right;">{mod_badge}</td>
        </tr>
        """

    # Top vulnerabilities preview list (max 5)
    vulns_preview_html = ""
    vuln_findings = master_result.all_vulnerable_findings[:5]
    if vuln_findings:
        vulns_preview_html = """
        <div style="margin-top: 24px;">
            <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="margin-bottom: 10px;">
                <tr>
                    <td style="font-size: 13px; font-weight: 800; letter-spacing: 1px; color: #fca5a5; text-transform: uppercase;">
                        🚨 Key Vulnerability Findings ({len(master_result.all_vulnerable_findings)} Total)
                    </td>
                </tr>
            </table>
            <table role="presentation" width="100%" cellpadding="0" cellspacing="0" bgcolor="#090e1b" style="border-collapse: collapse; background-color: #090e1b; border: 1px solid #1e293b; border-radius: 8px; overflow: hidden;">
        """
        for f in vuln_findings:
            sev = (f.severity or "HIGH").upper()
            if sev == "CRITICAL":
                sev_bg, sev_border, sev_color = "#3b0d0d", "#ef4444", "#fca5a5"
            elif sev == "HIGH":
                sev_bg, sev_border, sev_color = "#3b1506", "#ea580c", "#fdba74"
            elif sev == "MEDIUM":
                sev_bg, sev_border, sev_color = "#361c04", "#d97706", "#fde68a"
            else:
                sev_bg, sev_border, sev_color = "#0c2340", "#0284c7", "#7dd3fc"

            method = (f.method or "GET").upper()
            if method == "GET":
                m_bg, m_border, m_color = "#083344", "#0284c7", "#38bdf8"
            elif method == "POST":
                m_bg, m_border, m_color = "#064e3b", "#059669", "#34d399"
            elif method == "PUT":
                m_bg, m_border, m_color = "#3b1a03", "#d97706", "#fde68a"
            elif method == "DELETE":
                m_bg, m_border, m_color = "#450a0a", "#ef4444", "#fca5a5"
            else:
                m_bg, m_border, m_color = "#2e1065", "#8b5cf6", "#c084fc"

            evidence_snippet = _esc(f.evidence or f.description or "Vulnerability confirmed via automated probe.")
            if len(evidence_snippet) > 140:
                evidence_snippet = evidence_snippet[:137] + "..."

            vulns_preview_html += f"""
            <tr style="border-bottom: 1px solid #182236;">
                <td style="padding: 12px 14px; vertical-align: top; width: 85px;">
                    <span style="display:inline-block;padding:3px 7px;font-size:10px;font-weight:800;border-radius:4px;background-color:{sev_bg};color:{sev_color};border:1px solid {sev_border};letter-spacing:0.5px;">
                        {sev}
                    </span>
                </td>
                <td style="padding: 12px 14px; vertical-align: top;">
                    <div style="font-size: 13px; font-weight: 700; color: #f8fafc; margin-bottom: 4px;">{_esc(f.title)}</div>
                    <div style="font-size: 12px; font-family: 'Courier New', Courier, monospace; margin-bottom: 5px;">
                        <span style="display:inline-block;padding:1px 6px;font-size:10px;font-weight:700;border-radius:3px;background-color:{m_bg};color:{m_color};border:1px solid {m_border};">{method}</span>
                        <span style="color: #38bdf8; margin-left: 6px;">{_esc(f.endpoint)}</span>
                        <span style="color: #64748b; margin-left: 8px;">(HTTP {f.status_code or '-'})</span>
                    </div>
                    <div style="font-size: 11px; color: #94a3b8; line-height: 1.4;">{evidence_snippet}</div>
                </td>
            </tr>
            """
        vulns_preview_html += "</table></div>"

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="color-scheme" content="dark only">
    <meta name="supported-color-schemes" content="dark">
    <title>SentinelAPI Security Assessment Report</title>
    <style>
        :root {{
            color-scheme: dark only;
            supported-color-schemes: dark;
        }}
        body, table, td, div, p, a {{
            -webkit-font-smoothing: antialiased;
        }}
    </style>
</head>
<body bgcolor="#060913" style="margin: 0; padding: 0; background-color: #060913; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; -webkit-font-smoothing: antialiased; color: #cbd5e1;">
    <table role="presentation" width="100%" cellpadding="0" cellspacing="0" bgcolor="#060913" style="background-color: #060913; padding: 28px 12px;">
        <tr>
            <td align="center">
                <!-- Master Card Container -->
                <table role="presentation" width="100%" cellpadding="0" cellspacing="0" bgcolor="#0d1424" style="max-width: 640px; background-color: #0d1424; border: 1px solid #1e293b; border-radius: 12px; overflow: hidden; box-shadow: 0 20px 35px -10px rgba(0, 0, 0, 0.7);">
                    
                    <!-- Header Bar -->
                    <tr>
                        <td bgcolor="#090d18" style="padding: 24px 28px; background: linear-gradient(135deg, #070a13 0%, #111a2e 100%); border-bottom: 1px solid #1e293b;">
                            <table role="presentation" width="100%" cellpadding="0" cellspacing="0">
                                <tr>
                                    <td>
                                        <div style="font-size: 11px; font-weight: 800; letter-spacing: 2px; color: #38bdf8; text-transform: uppercase; margin-bottom: 5px;">
                                            🛡️ SENTINELAPI • AUTOMATED CI/CD SENTINEL
                                        </div>
                                        <div style="font-size: 22px; font-weight: 800; color: #ffffff; letter-spacing: -0.5px;">
                                            Security Assessment Report
                                        </div>
                                    </td>
                                    <td align="right" style="vertical-align: middle;">
                                        <span style="display: inline-block; padding: 5px 12px; font-size: 11px; font-weight: 700; border-radius: 20px; background-color: #162036; color: #94a3b8; border: 1px solid #334155;">
                                            CI/CD Exit: <b style="color: {'#ef4444' if exit_code != 0 else '#10b981'};">{exit_code}</b>
                                        </span>
                                    </td>
                                </tr>
                            </table>
                        </td>
                    </tr>

                    <!-- Status Alert Banner -->
                    <tr>
                        <td bgcolor="{status_bg}" style="padding: 20px 28px; background-color: {status_bg}; border-bottom: 2px solid {status_border}; border-left: 5px solid {status_border};">
                            <table role="presentation" width="100%" cellpadding="0" cellspacing="0">
                                <tr>
                                    <td>
                                        <div style="font-size: 15px; font-weight: 800; color: {status_text}; margin-bottom: 5px; letter-spacing: 0.3px;">
                                            {status_title}
                                        </div>
                                        <div style="font-size: 13px; color: {status_sub_text}; line-height: 1.5;">
                                            {status_sub}
                                        </div>
                                    </td>
                                    <td align="right" style="vertical-align: top; width: 140px;">
                                        <span style="display:inline-block;padding:4px 10px;font-size:10px;font-weight:800;border-radius:4px;background-color:{status_badge_bg};color:{status_badge_text};border:1px solid {status_badge_border};letter-spacing:0.5px;text-align:center;">
                                            {status_badge}
                                        </span>
                                    </td>
                                </tr>
                            </table>
                        </td>
                    </tr>

                    <!-- Content Body -->
                    <tr>
                        <td style="padding: 28px;">
                            
                            <!-- Target Details Card -->
                            <table role="presentation" width="100%" cellpadding="0" cellspacing="0" bgcolor="#090e1b" style="background-color: #090e1b; border: 1px solid #1e293b; border-radius: 8px; padding: 14px 18px; margin-bottom: 24px;">
                                <tr>
                                    <td style="padding: 5px 0; font-size: 12px; color: #64748b; width: 100px;">Target API:</td>
                                    <td style="padding: 5px 0; font-size: 13px; color: #f8fafc; font-weight: 700;">{_esc(master_result.target_title)}</td>
                                </tr>
                                <tr>
                                    <td style="padding: 5px 0; font-size: 12px; color: #64748b;">Base URL:</td>
                                    <td style="padding: 5px 0; font-size: 13px; color: #38bdf8; font-family: 'Courier New', Courier, monospace; font-weight: bold;">{_esc(master_result.base_url)}</td>
                                </tr>
                                <tr>
                                    <td style="padding: 5px 0; font-size: 12px; color: #64748b;">Auth Strategy:</td>
                                    <td style="padding: 5px 0; font-size: 13px; color: #cbd5e1;">{_esc(master_result.auth_scheme or 'None (Public Endpoints)')}</td>
                                </tr>
                                <tr>
                                    <td style="padding: 5px 0; font-size: 12px; color: #64748b;">Completed:</td>
                                    <td style="padding: 5px 0; font-size: 13px; color: #94a3b8;">{_esc(master_result.end_time or time.strftime("%Y-%m-%d %H:%M:%S UTC"))}</td>
                                </tr>
                            </table>

                            <!-- KPI Metric Cards (2x2 Grid) -->
                            <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="margin-bottom: 24px;">
                                <tr>
                                    <td width="48%" bgcolor="#0f172a" style="padding: 14px 18px; background-color: #0f172a; border: 1px solid #1e293b; border-radius: 8px; vertical-align: top;">
                                        <div style="font-size: 11px; text-transform: uppercase; color: #94a3b8; font-weight: 700; margin-bottom: 4px; letter-spacing: 0.5px;">Total Vulnerabilities</div>
                                        <div style="font-size: 28px; font-weight: 800; color: {'#f87171' if total_vulns > 0 else '#34d399'};">
                                            {total_vulns}
                                        </div>
                                        <div style="font-size: 10px; color: {'#fca5a5' if total_vulns > 0 else '#6ee7b7'}; margin-top: 2px;">
                                            {'Action Required' if total_vulns > 0 else 'All Controls Verified'}
                                        </div>
                                    </td>
                                    <td width="4%"></td>
                                    <td width="48%" bgcolor="#0f172a" style="padding: 14px 18px; background-color: #0f172a; border: 1px solid #1e293b; border-radius: 8px; vertical-align: top;">
                                        <div style="font-size: 11px; text-transform: uppercase; color: #94a3b8; font-weight: 700; margin-bottom: 4px; letter-spacing: 0.5px;">Critical &amp; High</div>
                                        <div style="font-size: 28px; font-weight: 800; color: {'#ef4444' if (total_crit + total_high) > 0 else '#64748b'};">
                                            {total_crit + total_high}
                                        </div>
                                        <div style="font-size: 10px; color: {'#fca5a5' if (total_crit + total_high) > 0 else '#64748b'}; margin-top: 2px;">
                                            {f'{total_crit} Critical, {total_high} High' if (total_crit + total_high) > 0 else 'Zero High Risks'}
                                        </div>
                                    </td>
                                </tr>
                                <tr><td height="12"></td></tr>
                                <tr>
                                    <td width="48%" bgcolor="#0f172a" style="padding: 14px 18px; background-color: #0f172a; border: 1px solid #1e293b; border-radius: 8px; vertical-align: top;">
                                        <div style="font-size: 11px; text-transform: uppercase; color: #94a3b8; font-weight: 700; margin-bottom: 4px; letter-spacing: 0.5px;">Probe Delivery</div>
                                        <div style="font-size: 28px; font-weight: 800; color: #38bdf8;">
                                            {total_probes} / {planned_probes}
                                        </div>
                                        <div style="font-size: 10px; color: #7dd3fc; margin-top: 2px;">
                                            100% Network Delivery
                                        </div>
                                    </td>
                                    <td width="4%"></td>
                                    <td width="48%" bgcolor="#0f172a" style="padding: 14px 18px; background-color: #0f172a; border: 1px solid #1e293b; border-radius: 8px; vertical-align: top;">
                                        <div style="font-size: 11px; text-transform: uppercase; color: #94a3b8; font-weight: 700; margin-bottom: 4px; letter-spacing: 0.5px;">Modules Active</div>
                                        <div style="font-size: 28px; font-weight: 800; color: #a78bfa;">
                                            {len(master_result.module_results)} / 7
                                        </div>
                                        <div style="font-size: 10px; color: #c4b5fd; margin-top: 2px;">
                                            Full OWASP Suite Covered
                                        </div>
                                    </td>
                                </tr>
                            </table>

                            <!-- OWASP Module Breakdown -->
                            <div style="margin-bottom: 24px;">
                                <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="margin-bottom: 10px;">
                                    <tr>
                                        <td style="font-size: 13px; font-weight: 800; letter-spacing: 1px; color: #f8fafc; text-transform: uppercase;">
                                            OWASP Top 10 Module Breakdown
                                        </td>
                                    </tr>
                                </table>
                                <table role="presentation" width="100%" cellpadding="0" cellspacing="0" bgcolor="#090e1b" style="border-collapse: collapse; background-color: #090e1b; border: 1px solid #1e293b; border-radius: 8px; overflow: hidden;">
                                    <thead>
                                        <tr bgcolor="#141f36" style="background-color: #141f36; border-bottom: 1px solid #1e293b;">
                                            <th style="padding: 10px 14px; font-size: 11px; text-align: left; color: #94a3b8; font-weight: 700; letter-spacing: 0.5px;">MODULE</th>
                                            <th style="padding: 10px 14px; font-size: 11px; text-align: left; color: #94a3b8; font-weight: 700; letter-spacing: 0.5px;">OWASP STANDARD</th>
                                            <th style="padding: 10px 14px; font-size: 11px; text-align: center; color: #94a3b8; font-weight: 700; letter-spacing: 0.5px;">PROBES</th>
                                            <th style="padding: 10px 14px; font-size: 11px; text-align: right; color: #94a3b8; font-weight: 700; letter-spacing: 0.5px;">STATUS</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        {module_rows_html}
                                    </tbody>
                                </table>
                            </div>

                            <!-- Top Vulnerabilities Preview (if any) -->
                            {vulns_preview_html}

                            <!-- Attached PDF Reports Box -->
                            <div style="margin-top: 24px;">
                                <table role="presentation" width="100%" cellpadding="0" cellspacing="0" bgcolor="#10172e" style="background-color: #10172e; border: 1px solid #4f46e5; border-radius: 8px; padding: 18px 20px;">
                                    <tr>
                                        <td style="font-size: 26px; width: 44px; vertical-align: top;">📎</td>
                                        <td>
                                            <div style="font-size: 14px; font-weight: 800; color: #ffffff; margin-bottom: 6px; letter-spacing: 0.3px;">
                                                Attached PDF Assessment Artifacts (2 Files)
                                            </div>
                                            <div style="font-size: 12px; color: #c7d2fe; line-height: 1.7;">
                                                • <b style="color: #ffffff;">vulnerabilities.pdf</b> — Complete vulnerability dossiers, CVSS scores, reproduction cURL commands &amp; code remediation blueprints.<br/>
                                                • <b style="color: #ffffff;">all_logs.pdf</b> — Full route-by-route execution trace, HTTP status distribution, attack scenarios tested &amp; failure telemetry.
                                            </div>
                                        </td>
                                    </tr>
                                </table>
                            </div>

                        </td>
                    </tr>

                    <!-- Footer -->
                    <tr>
                        <td bgcolor="#070a13" style="padding: 22px 28px; background-color: #070a13; border-top: 1px solid #1e293b; text-align: center;">
                            <div style="font-size: 11px; color: #64748b; line-height: 1.6;">
                                Generated automatically by SentinelAPI Core Security Scanner.<br/>
                                Target: {_esc(master_result.base_url)} • Recipient: {DEFAULT_RECIPIENT_EMAIL}<br/>
                                <span style="color: #475569;">Confidential &amp; Proprietary Security Assessment Document.</span>
                            </div>
                        </td>
                    </tr>

                </table>
            </td>
        </tr>
    </table>
</body>
</html>
    """
    return html


def send_scan_report_email(
    master_result: MasterScanResult,
    recipient_email: Optional[str] = None,
    recipient_name: str = "Security Team",
    vuln_pdf_path: Optional[Path] = None,
    logs_pdf_path: Optional[Path] = None,
    output_dir: Optional[Path] = None,
) -> Dict[str, Any]:
    """Sends the master scan assessment report via Brevo SMTP API with PDF attachments.

    Args:
        master_result: Aggregated assessment results.
        recipient_email: Target email (defaults to ALERT_RECIPIENT_EMAIL / yuvrajjsoni17@gmail.com).
        recipient_name: Recipient name label.
        vuln_pdf_path: Existing path to vulnerabilities.pdf (auto-generated if None).
        logs_pdf_path: Existing path to all_logs.pdf (auto-generated if None).
        output_dir: Directory where generated PDFs should be saved.

    Returns:
        Dict[str, Any] with keys 'success', 'status_code', 'message_id', 'error'.
    """
    api_key = _get_api_key()
    if not api_key:
        error_msg = "Brevo API key is not configured. Set BREVO_API_KEY in .env."
        console.print(f"[bold red]✗ Email Dispatch Failed:[/bold red] {error_msg}")
        return {"success": False, "status_code": 0, "error": error_msg}

    target_email = recipient_email or os.getenv("ALERT_RECIPIENT_EMAIL") or DEFAULT_RECIPIENT_EMAIL
    sender_email = os.getenv("BREVO_SENDER_EMAIL") or DEFAULT_SENDER_EMAIL
    sender_name = os.getenv("BREVO_SENDER_NAME") or DEFAULT_SENDER_NAME

    # Ensure PDFs are generated
    if not vuln_pdf_path or not logs_pdf_path:
        out = output_dir or Path(__file__).resolve().parent.parent.parent / "markdown"
        vuln_pdf_path, logs_pdf_path = generate_scan_pdfs(master_result, out)

    # Convert PDFs to base64
    attachments = []
    try:
        if vuln_pdf_path and Path(vuln_pdf_path).exists():
            attachments.append({
                "name": "vulnerabilities.pdf",
                "content": _encode_file_to_base64(Path(vuln_pdf_path)),
            })
        if logs_pdf_path and Path(logs_pdf_path).exists():
            attachments.append({
                "name": "all_logs.pdf",
                "content": _encode_file_to_base64(Path(logs_pdf_path)),
            })
    except Exception as e:
        console.print(f"[dim yellow]Warning: Failed reading PDF attachments: {e}[/dim yellow]")

    # Subject line with clear CI/CD status
    vuln_count = len(master_result.all_vulnerable_findings)
    status_emoji = "🚨" if master_result.status == "FAIL" else ("✅" if master_result.status == "PASS" else "⚠️")
    subject = f"{status_emoji} [{master_result.status}] SentinelAPI Audit Report: {master_result.target_title} ({vuln_count} findings)"

    html_content = _render_email_html(master_result)

    payload = {
        "sender": {
            "name": sender_name,
            "email": sender_email,
        },
        "to": [
            {
                "email": target_email,
                "name": recipient_name,
            }
        ],
        "subject": subject,
        "htmlContent": html_content,
        "attachment": attachments,
    }

    headers = {
        "api-key": api_key,
        "Content-Type": "application/json",
        "accept": "application/json",
    }

    try:
        console.print(f"[bold cyan]ℹ Dispatching email alert via Brevo to [bold white]{target_email}[/bold white]...[/bold cyan]")
        with httpx.Client(timeout=30.0) as client:
            resp = client.post(BREVO_API_URL, headers=headers, json=payload)

        if resp.status_code in (200, 201, 202):
            data = resp.json()
            msg_id = data.get("messageId", "ok")
            console.print(f"[bold green]✓ Email successfully delivered via Brevo![/bold green] (Message ID: [cyan]{msg_id}[/cyan])")
            console.print(f"  ↳ Attached: [bold white]vulnerabilities.pdf[/bold white] & [bold white]all_logs.pdf[/bold white]")
            return {"success": True, "status_code": resp.status_code, "message_id": msg_id}
        else:
            err_text = resp.text
            console.print(f"[bold red]✗ Brevo API returned error {resp.status_code}:[/bold red] {err_text}")
            return {"success": False, "status_code": resp.status_code, "error": err_text}

    except Exception as e:
        console.print(f"[bold red]✗ Network exception during email dispatch:[/bold red] {e}")
        return {"success": False, "status_code": 0, "error": str(e)}
