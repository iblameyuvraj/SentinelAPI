"""Security Misconfiguration & Insecure Headers/Cookies (OWASP API8:2023) interactive UI & live scanner."""

import os
import json
import time
from pathlib import Path
from typing import Dict, Any, List, Optional
import httpx
from rich.table import Table
from rich.panel import Panel
from rich.syntax import Syntax
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
import questionary
from prompt_toolkit.styles import Style

from sentinelapi.cli.theme import console
from sentinelapi.api_source.spec_parser import ParsedSpecification, APIEndpointInfo
from sentinelapi.features.Security_Misconfiguration.detector import (
    audit_endpoint_security_misconfig,
    SecurityMisconfigFinding,
)

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent.parent
MARKDOWN_DIR = PROJECT_ROOT / "markdown"


def get_markdown_dir() -> Path:
    """Ensures and returns the markdown directory."""
    MARKDOWN_DIR.mkdir(parents=True, exist_ok=True)
    return MARKDOWN_DIR


CUSTOM_STYLE = Style(
    [
        ("qmark", "fg:#00f0ff bold"),
        ("question", "bold fg:#ffffff"),
        ("answer", "fg:#00ff88 bold"),
        ("pointer", "fg:#00f0ff bold"),
        ("highlighted", "fg:#00f0ff bold underline"),
        ("selected", "fg:#00ff88 bold"),
        ("separator", "fg:#64748b"),
        ("instruction", "fg:#94a3b8"),
        ("text", "fg:#ffffff"),
    ]
)


def run_sec_misconfig_flow(spec: ParsedSpecification):
    """Main interactive loop for Security Misconfiguration assessment."""
    while True:
        console.clear()

        console.print(
            Panel(
                f"[bold white]Target API:[/bold white] [bold cyan]{spec.title}[/bold cyan] (v{spec.version})\n"
                f"[bold white]Base URL:[/bold white]   [yellow]{spec.base_url}[/yellow]\n"
                f"[bold white]Auth Scheme:[/bold white] {spec.auth_scheme}\n"
                f"[bold white]Total Routes:[/bold white] {len(spec.endpoints)} discovered\n"
                f"[dim]Audits HSTS, CSP, nosniff, X-Frame-Options, Insecure Cookies, CORS, and Server Leaks.[/dim]",
                title="[bold yellow]OWASP API8:2023 — SECURITY MISCONFIGURATION AUDITOR[/bold yellow]",
                border_style="yellow",
                padding=(1, 2),
            )
        )

        menu_choices = [
            "1. Run Complete Security Misconfiguration Audit (All Routes)",
            "2. Inspect Expected Security Headers & Checklist",
            "3. Configure Target Base URL & Authentication",
            "4. Back to Main Menu",
        ]

        try:
            choice = questionary.select(
                "Select Action:",
                choices=menu_choices,
                style=CUSTOM_STYLE,
            ).ask()
        except (KeyboardInterrupt, EOFError):
            return

        if not choice or "4. Back" in choice:
            return

        if "1. Run Complete" in choice:
            config = {
                "base_url": spec.base_url,
                "auth_header": "Bearer test_token" if spec.auth_scheme != "None" else "",
            }
            run_full_sec_misconfig_audit(spec, config)
        elif "2. Inspect Expected" in choice:
            display_headers_checklist()
        elif "3. Configure Target" in choice:
            configure_sec_misconfig_target(spec)


def configure_sec_misconfig_target(spec: ParsedSpecification):
    """Allows updating target base URL and authorization header."""
    console.print()
    try:
        new_url = questionary.text(
            "Target Base URL:",
            default=spec.base_url,
            style=CUSTOM_STYLE,
        ).ask()
        if new_url and new_url.strip():
            spec.base_url = new_url.strip()
            console.print(f"[bold green]✔ Base URL updated to:[/bold green] {spec.base_url}")
            time.sleep(1)
    except (KeyboardInterrupt, EOFError):
        pass


def run_full_sec_misconfig_audit(spec: ParsedSpecification, config: Dict[str, Any]):
    """Executes live network probes evaluating HTTP headers, cookies, and CORS configuration."""
    console.print()
    console.print("[bold yellow]Initiating OWASP API8:2023 Security Misconfiguration Audit...[/bold yellow]")

    endpoints = spec.endpoints
    if not endpoints:
        console.print("[bold red]No endpoints discovered in specification to audit.[/bold red]")
        try:
            input("\nPress Enter to return...")
        except (KeyboardInterrupt, EOFError):
            pass
        return

    all_findings: List[SecurityMisconfigFinding] = []
    base_url = config.get("base_url", spec.base_url).rstrip("/")
    auth_header = config.get("auth_header", "")

    # Progress bar
    with Progress(
        SpinnerColumn(spinner_name="dots", style="bold yellow"),
        TextColumn("[bold white]{task.description}[/bold white]"),
        BarColumn(bar_width=30, style="yellow", complete_style="bold green"),
        TextColumn("[bold cyan]{task.percentage:>3.0f}%[/bold cyan]"),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("Auditing HTTP security posture...", total=len(endpoints))

        with httpx.Client(timeout=6.0, verify=False, follow_redirects=True) as client:
            for ep in endpoints:
                target_path = ep.path
                if "{" in target_path:
                    # Provide realistic path parameters for parameterized paths
                    target_path = target_path.replace("{userId}", "101")
                    target_path = target_path.replace("{id}", "101")

                target_url = f"{base_url}/{target_path.lstrip('/')}"
                progress.update(task, description=f"Auditing [bold cyan]{ep.method} {ep.path}[/bold cyan]")

                req_headers = {"User-Agent": "SentinelAPI-Security-Scanner/1.0"}
                if auth_header:
                    req_headers["Authorization"] = auth_header

                # Probe 1: Standard declared method probe
                try:
                    res = client.request(
                        ep.method.upper(),
                        target_url,
                        headers=req_headers,
                        json={"test": "probe"} if ep.method.upper() in ("POST", "PUT", "PATCH") else None,
                    )

                    # Extract raw cookies via get_list
                    raw_cookies = res.headers.get_list("set-cookie")

                    findings = audit_endpoint_security_misconfig(
                        endpoint=ep.path,
                        method=ep.method.upper(),
                        base_url=base_url,
                        response_headers=dict(res.headers),
                        status_code=res.status_code,
                        response_body=res.text[:1000],
                        raw_set_cookie_headers=raw_cookies,
                        auth_header=auth_header,
                    )
                    all_findings.extend(findings)

                except Exception as e:
                    all_findings.append(
                        SecurityMisconfigFinding(
                            endpoint=ep.path,
                            method=ep.method.upper(),
                            test_id="SEC-00-CONN-ERR",
                            test_name="Probe Connection Error / Host Unreachable",
                            is_vulnerable=False,
                            severity="NONE",
                            category="Network / Transport Error",
                            reason=f"Probe failed to reach {target_url}: {str(e)}",
                            cwe="CWE-1188: Initialization of a Resource with Insecure Default Values",
                            reproduction_curl=f"curl -s -i -X {ep.method} \"{target_url}\"",
                            header_found="None (Connection Refused / Network Error)",
                            remediation="Ensure target server is live, online, and accessible from scanner network.",
                        )
                    )

                # Probe 2: CORS Origin Reflection Probe (Send Origin: https://evil-attacker.io)
                try:
                    cors_headers = dict(req_headers)
                    cors_headers["Origin"] = "https://evil-attacker.io"
                    cors_res = client.request(
                        "OPTIONS" if ep.method.upper() != "GET" else "GET",
                        target_url,
                        headers=cors_headers,
                    )
                    cors_allow_origin = cors_res.headers.get("access-control-allow-origin")
                    cors_allow_cred = cors_res.headers.get("access-control-allow-credentials", "").lower() == "true"

                    if cors_allow_origin == "https://evil-attacker.io" and cors_allow_cred:
                        all_findings.append(
                            SecurityMisconfigFinding(
                                endpoint=ep.path,
                                method=ep.method.upper(),
                                test_id="SEC-06-CORS",
                                test_name="Arbitrary Origin Reflection with Credentials",
                                is_vulnerable=True,
                                severity="CRITICAL",
                                category="CORS Misconfiguration",
                                reason="Server reflected arbitrary Origin 'https://evil-attacker.io' alongside 'Access-Control-Allow-Credentials: true'. Any malicious site can read authenticated responses cross-origin.",
                                cwe="CWE-942: Permissive Cross-Domain Policy with Untrusted Domains",
                                reproduction_curl=f"curl -s -i -H \"Origin: https://evil-attacker.io\" -X {ep.method} \"{target_url}\"",
                                header_found="Access-Control-Allow-Origin: https://evil-attacker.io | Credentials: true",
                                remediation="Whitelist trusted origins explicitly. Prohibit echoing arbitrary origins when credentials are enabled.",
                            )
                        )
                except Exception:
                    pass

                progress.advance(task)

    # Render Results
    display_sec_misconfig_results(spec, all_findings, config)
    return all_findings


def display_sec_misconfig_results(
    spec: ParsedSpecification,
    findings: List[SecurityMisconfigFinding],
    config: Dict[str, Any],
):
    """Displays findings table, severity scorecards, remediation code, and report."""
    console.clear()

    vuln_findings = [f for f in findings if f.is_vulnerable]
    conn_err_findings = [f for f in findings if f.test_id == "SEC-00-CONN-ERR"]
    crit_count = sum(1 for f in vuln_findings if f.severity == "CRITICAL")
    high_count = sum(1 for f in vuln_findings if f.severity == "HIGH")
    med_count = sum(1 for f in vuln_findings if f.severity == "MEDIUM")
    low_count = sum(1 for f in vuln_findings if f.severity == "LOW")

    console.print()
    # Executive Summary Card (Fail-Closed)
    if len(conn_err_findings) == len(spec.endpoints) or len(findings) == 0:
        status_label = "[bold red]ERROR — TARGET SERVER UNREACHABLE (0 PROBES SUCCEEDED)[/bold red]"
        card_border = "red"
    elif vuln_findings:
        status_label = "[bold red]ACTION REQUIRED — CRITICAL MISCONFIGURATIONS DETECTED[/bold red]"
        card_border = "red"
    elif conn_err_findings:
        status_label = f"[bold yellow]INCOMPLETE — {len(conn_err_findings)} PROBES FAILED / UNREACHABLE[/bold yellow]"
        card_border = "yellow"
    else:
        status_label = "[bold green]SECURITY POSTURE SECURED — ALL HEADERS ENFORCED[/bold green]"
        card_border = "green"

    stats_panel = Panel(
        f"[bold white]Target API:[/bold white]          [bold cyan]{spec.title}[/bold cyan] ({config.get('base_url')})\n"
        f"[bold white]Standard:[/bold white]            OWASP API Security Top 10 — API8:2023 Security Misconfiguration\n"
        f"[bold white]Total Evaluated:[/bold white]     {len(findings)} checks across {len(spec.endpoints)} routes\n"
        f"[bold white]Vulnerabilities:[/bold white]     [bold red]{len(vuln_findings)} detected[/bold red] "
        f"([bold magenta]{crit_count} Critical[/bold magenta], [bold red]{high_count} High[/bold red], [bold yellow]{med_count} Medium[/bold yellow], [bold blue]{low_count} Low[/bold blue])\n"
        f"[bold white]Probe Failures:[/bold white]      {len(conn_err_findings)} Unreachable\n"
        f"[bold white]Audit Status:[/bold white]        {status_label}",
        title="[bold yellow]AUDIT SUMMARY — OWASP API8:2023[/bold yellow]",
        border_style=card_border,
        padding=(0, 2),
    )
    console.print(stats_panel)

    # Findings Table
    console.print()
    t = Table(title="[bold white]SECURITY HEADERS & CONFIGURATION AUDIT MATRIX[/bold white]", box=None, padding=(0, 1))
    t.add_column("Endpoint", style="bold cyan", no_wrap=True)
    t.add_column("Category", style="magenta")
    t.add_column("Audit Check", style="white")
    t.add_column("Observed Header / Directive", style="dim")
    t.add_column("Severity", justify="center")
    t.add_column("Status", justify="center")

    for f in findings:
        sev_color = "magenta" if f.severity == "CRITICAL" else ("red" if f.severity == "HIGH" else ("yellow" if f.severity == "MEDIUM" else "blue"))
        if f.is_vulnerable:
            badge = f"[bold {sev_color}]{f.severity}[/]"
            status = "[bold red]FAIL[/bold red]"
        else:
            badge = "[dim]NONE[/dim]"
            status = "[bold green]PASS[/bold green]"

        hdr_snippet = f.header_found or "[dim red]MISSING[/dim red]"
        if len(hdr_snippet) > 40:
            hdr_snippet = hdr_snippet[:37] + "..."

        t.add_row(
            f"{f.method} {f.endpoint}",
            f.category,
            f.test_name,
            hdr_snippet,
            badge,
            status,
        )

    console.print(t)

    # Detailed Vulnerability Finding Cards
    if vuln_findings:
        console.print()
        console.print("[bold red]🚨 DETAILED SECURITY MISCONFIGURATION FINDINGS[/bold red]")

        for idx, vf in enumerate(vuln_findings, 1):
            sev_color = "magenta" if vf.severity == "CRITICAL" else ("red" if vf.severity == "HIGH" else "yellow")
            poc_card = Table(box=None, show_header=False, padding=(0, 1))
            poc_card.add_column("Key", style="bold cyan", width=18)
            poc_card.add_column("Val", style="white")

            poc_card.add_row("Finding #:", f"{idx} of {len(vuln_findings)}")
            poc_card.add_row("Endpoint:", f"[bold white]{vf.method} {vf.endpoint}[/bold white]")
            poc_card.add_row("Severity:", f"[bold {sev_color}]{vf.severity}[/]")
            poc_card.add_row("Category:", vf.category)
            poc_card.add_row("CWE Classification:", vf.cwe)
            poc_card.add_row("Security Risk:", f"[bold {sev_color}]{vf.reason}[/]")
            poc_card.add_row("Observed State:", vf.header_found or "[dim red]Header absent or misconfigured[/dim red]")
            poc_card.add_row("PoC cURL Command:", f"[bold green]{vf.reproduction_curl}[/bold green]")
            poc_card.add_row("Remediation Fix:", vf.remediation)

            console.print(
                Panel(
                    poc_card,
                    title=f"[bold {sev_color}]VULNERABILITY: {vf.test_name}[/]",
                    border_style=sev_color,
                    padding=(1, 2),
                )
            )

        # Code Remediation Snippets
        display_sec_misconfig_remediation()

    # Save markdown report to markdown/
    md_path = save_sec_misconfig_markdown_report(spec, findings, config)
    console.print()
    console.print(f"[bold green]✔ Comprehensive audit report saved to:[/bold green] [underline cyan]{md_path}[/underline cyan]")

    # AI Security Analysis Flow
    prompt_ai_sec_misconfig_overview(spec, findings, config)

    try:
        input("\nPress Enter to return to menu...")
    except (KeyboardInterrupt, EOFError):
        pass


def display_headers_checklist():
    """Displays industry-standard security headers checklist with OWASP references."""
    console.clear()
    t = Table(title="[bold yellow]OWASP API8:2023 Security Headers & Configuration Standard[/bold yellow]", box=None, padding=(0, 2))
    t.add_column("Security Header / Flag", style="bold cyan")
    t.add_column("Recommended Value", style="bold green")
    t.add_column("Defense Purpose", style="dim")

    t.add_row(
        "Strict-Transport-Security",
        "max-age=31536000; includeSubDomains; preload",
        "Enforces HTTPS exclusively; prevents SSL stripping & MitM.",
    )
    t.add_row(
        "Content-Security-Policy",
        "default-src 'self'; frame-ancestors 'none';",
        "Restricts sources of executable scripts, objects, and framing.",
    )
    t.add_row(
        "X-Content-Type-Options",
        "nosniff",
        "Blocks MIME-type sniffing; stops non-executable files executing as code.",
    )
    t.add_row(
        "X-Frame-Options",
        "DENY",
        "Prevents UI clickjacking via malicious iframe overlay.",
    )
    t.add_row(
        "Referrer-Policy",
        "strict-origin-when-cross-origin",
        "Prevents leaking full URL paths and secret tokens to external links.",
    )
    t.add_row(
        "Set-Cookie: HttpOnly",
        "HttpOnly",
        "Blocks JavaScript document.cookie access to session tokens.",
    )
    t.add_row(
        "Set-Cookie: Secure",
        "Secure",
        "Transmits cookies only over encrypted HTTPS channels.",
    )
    t.add_row(
        "Set-Cookie: SameSite",
        "SameSite=Strict (or Lax)",
        "Mitigates Cross-Site Request Forgery (CSRF) across origins.",
    )
    t.add_row(
        "X-Powered-By / Server",
        "[REMOVED]",
        "Suppresses technology stack fingerprinting from malicious reconnaissance.",
    )

    console.print(Panel(t, title="[bold white]SECURITY HEADERS DEFENSE STANDARD[/bold white]", border_style="yellow", padding=(1, 2)))
    try:
        input("\nPress Enter to return...")
    except (KeyboardInterrupt, EOFError):
        pass


def display_sec_misconfig_remediation():
    """Renders production code fixes for Express.js (Helmet) and FastAPI."""
    console.print()
    console.print(
        Panel(
            "[bold white]Production Hardening Blueprints[/bold white]\n"
            "[dim]Enforce security headers and hardened cookie flags in middleware.[/dim]",
            title="[bold green]🛠️ RECOMMENDED REMEDIATION CODE[/bold green]",
            border_style="green",
            padding=(0, 2),
        )
    )

    express_fix = """// Node.js / Express: Production Security Headers with Helmet
const helmet = require("helmet");

// 1. Enforce complete security header suite
app.use(helmet({
  hsts: { maxAge: 31536000, includeSubDomains: true, preload: true },
  contentSecurityPolicy: { directives: { defaultSrc: ["'self'"], frameAncestors: ["'none'"] } },
  noSniff: true,
  frameguard: { action: "deny" },
  referrerPolicy: { policy: "strict-origin-when-cross-origin" },
  hidePoweredBy: true,
}));

// 2. Strict CORS Configuration
const cors = require("cors");
app.use(cors({
  origin: ["https://app.yourdomain.com"], // Whitelist only
  credentials: true,
}));

// 3. Hardened Cookie Directives
res.cookie("session_id", token, {
  httpOnly: true,
  secure: true, // Requires HTTPS
  sameSite: "strict",
  maxAge: 3600000,
});"""

    fastapi_fix = """# Python / FastAPI: Custom Security Headers Middleware
from starlette.middleware.base import BaseHTTPMiddleware
from fastapi import FastAPI, Response
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response: Response = await call_next(request)
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Content-Security-Policy"] = "default-src 'self'; frame-ancestors 'none'"
        # Remove fingerprinting
        if "x-powered-by" in response.headers:
            del response.headers["x-powered-by"]
        return response

app.add_middleware(SecurityHeadersMiddleware)

# Strict CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://app.yourdomain.com"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["*"],
)"""

    console.print("[bold cyan]Node.js (Express & Helmet) Fix:[/bold cyan]")
    console.print(Syntax(express_fix, "javascript", theme="monokai", line_numbers=True))
    console.print()
    console.print("[bold cyan]Python (FastAPI & Starlette) Fix:[/bold cyan]")
    console.print(Syntax(fastapi_fix, "python", theme="monokai", line_numbers=True))


def save_sec_misconfig_markdown_report(
    spec: ParsedSpecification,
    findings: List[SecurityMisconfigFinding],
    config: Dict[str, Any],
) -> Path:
    """Saves structured markdown report in the root markdown/ directory."""
    md_dir = get_markdown_dir()
    slug = "".join([c if c.isalnum() else "_" for c in spec.title.lower()]).strip("_") or "api"
    filename = f"{slug}_security_misconfiguration_scan_results_{int(time.time())}.md"
    file_path = md_dir / filename

    vuln_findings = [f for f in findings if f.is_vulnerable]

    lines = [
        "# OWASP API8:2023 — Security Misconfiguration Audit Report",
        "",
        f"- **API Target:** {spec.title} (v{spec.version})",
        f"- **Base URL:** `{config.get('base_url')}`",
        f"- **Scan Timestamp:** {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}",
        f"- **Standard:** OWASP API Security Top 10 — API8:2023 Security Misconfiguration",
        f"- **Total Checks Evaluated:** {len(findings)}",
        f"- **Misconfigurations Flagged:** {len(vuln_findings)}",
        "",
        "## Executive Summary",
        f"{'CRITICAL WARNING: The target API exhibits serious Security Misconfigurations. Missing fundamental HTTP security headers, insecure cookie flags, and/or overly permissive CORS policies leave the application vulnerable to Clickjacking, XSS exploitation, MIME sniffing, and cleartext token exposure.' if vuln_findings else 'CLEARANCE: Hardened security headers and strict cookie policies are enforced across evaluated routes. No critical security misconfigurations detected.'}",
        "",
        "## Findings Matrix",
        "",
        "| Endpoint | Category | Audit Check | Severity | Status | Observed Header / Detail |",
        "| :--- | :--- | :--- | :---: | :---: | :--- |",
    ]

    for f in findings:
        status_str = "**FAIL**" if f.is_vulnerable else "PASS"
        hdr_det = f.header_found or "Header Absent"
        lines.append(f"| `{f.method} {f.endpoint}` | {f.category} | {f.test_name} | {f.severity} | {status_str} | `{hdr_det}` |")

    if vuln_findings:
        lines.extend([
            "",
            "## Detailed Vulnerability Analysis & Proof of Concept",
            "",
        ])
        for idx, vf in enumerate(vuln_findings, 1):
            lines.extend([
                f"### Finding {idx}: {vf.test_name} on `{vf.method} {vf.endpoint}`",
                f"- **Severity:** {vf.severity}",
                f"- **Category:** {vf.category}",
                f"- **CWE Classification:** {vf.cwe}",
                f"- **Security Risk:** {vf.reason}",
                f"- **Observed Header/Directive:** `{vf.header_found or 'None'}`",
                "",
                "**Reproduction Proof-of-Concept:**",
                "```bash",
                vf.reproduction_curl,
                "```",
                "",
                "**Remediation Recommendation:**",
                f"> {vf.remediation}",
                "",
            ])

    with open(file_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    return file_path


def prompt_ai_sec_misconfig_overview(
    spec: ParsedSpecification,
    findings: List[SecurityMisconfigFinding],
    config: Dict[str, Any],
):
    """Presents AI token estimate and prompts user for AI Executive Security Overview."""
    from rich.markdown import Markdown
    from sentinelapi.modals.ai_engine import (
        get_active_ai_config,
        estimate_token_usage,
        request_ai_overview,
    )

    ai_cfg = get_active_ai_config()
    prompt_text = build_sec_misconfig_ai_prompt(spec, findings, config)
    usage = estimate_token_usage(prompt_text)

    console.print()
    t = Table(box=None, show_header=False, padding=(0, 2))
    t.add_column("Key", style="bold cyan")
    t.add_column("Val", style="bold white")

    t.add_row("Active AI Model:", f"[bold green]{ai_cfg['model']}[/bold green] [dim]({ai_cfg['provider']})[/dim]")
    t.add_row("Target API Scope:", f"{spec.title} ({len(findings)} checks evaluated)")
    t.add_row("Context Included:", "HTTP security headers, cookie flags, CORS directives, technology leaks")
    t.add_row("Context Payload:", f"{usage['char_count']} characters [dim](full test telemetry)[/dim]")
    t.add_row("Estimated Prompt Cost:", f"[bold yellow]~{usage['prompt_tokens']} input tokens[/bold yellow]")
    t.add_row("Estimated Generation:", f"~{usage['estimated_output_tokens']} completion tokens")
    t.add_row("Estimated Total:", f"[bold cyan]~{usage['estimated_total_tokens']} tokens[/bold cyan]")

    console.print(
        Panel(
            t,
            title="[bold yellow]🤖 AI SECURITY EXECUTIVE SUMMARY GENERATOR[/bold yellow]",
            border_style="yellow",
            padding=(0, 2),
        )
    )

    try:
        generate = questionary.confirm(
            "Generate AI Security Analysis Report with these tokens?",
            default=False,
            style=CUSTOM_STYLE,
        ).ask()
    except (KeyboardInterrupt, EOFError):
        return

    if not generate:
        console.print("[dim]AI summary generation skipped.[/dim]")
        return

    console.print()
    with console.status("[bold cyan]Consulting AI Security Engine (OWASP API8:2023 Analysis)...[/bold cyan]"):
        success, ai_response = request_ai_overview(prompt_text)

    if not success or not ai_response:
        console.print(f"[bold red]AI Generation Failed:[/bold red] {ai_response}")
        return

    console.print()
    console.print(
        Panel(
            Markdown(ai_response),
            title="[bold green]AI SECURITY EXECUTIVE SUMMARY & COMPLIANCE ROADMAP[/bold green]",
            border_style="green",
            padding=(1, 2),
        )
    )

    # Append AI analysis to report
    md_dir = get_markdown_dir()
    slug = "".join([c if c.isalnum() else "_" for c in spec.title.lower()]).strip("_") or "api"
    ai_report_file = md_dir / f"{slug}_sec_misconfig_ai_report_{int(time.time())}.md"
    try:
        with open(ai_report_file, "w", encoding="utf-8") as f:
            f.write(f"# AI Security Executive Summary: {spec.title}\n\n{ai_response}")
        console.print(f"[dim green]✔ AI Executive Report saved to: {ai_report_file}[/dim green]")
    except Exception:
        pass


def build_sec_misconfig_ai_prompt(
    spec: ParsedSpecification,
    findings: List[SecurityMisconfigFinding],
    config: Dict[str, Any],
) -> str:
    """Builds prompt for LLM security analysis."""
    vulns = [f for f in findings if f.is_vulnerable]

    summary_data = {
        "api_title": spec.title,
        "base_url": config.get("base_url"),
        "total_checks": len(findings),
        "vulnerabilities_detected": len(vulns),
        "misconfigurations": [
            {
                "endpoint": f"{f.method} {f.endpoint}",
                "category": f.category,
                "test": f.test_name,
                "severity": f.severity,
                "risk": f.reason,
                "remediation": f.remediation,
            }
            for f in vulns
        ],
    }

    return (
        "You are an elite application security engineer specializing in OWASP API Security Top 10.\n"
        "Analyze the following Security Misconfiguration (API8:2023) audit results for the target API:\n\n"
        f"{json.dumps(summary_data, indent=2)}\n\n"
        "Provide a high-impact executive security briefing covering:\n"
        "1. Executive Risk Summary (Clickjacking, XSS, Man-in-the-Middle, Session Hijacking risk)\n"
        "2. Severity Breakdown (Critical/High/Medium/Low issues found)\n"
        "3. Concrete Engineering Action Plan (Helmet.js, Gateway header injection, strict cookie configuration)\n"
        "4. Compliance Impact (PCI-DSS, ISO 27001, SOC 2 compliance violations for missing HSTS/CSP)"
    )
