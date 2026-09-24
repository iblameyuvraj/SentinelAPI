"""Broken Function Level Authorization (BFLA) interactive assessment UI & live scanner."""

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
from sentinelapi.features.BFLA.detector import (
    generate_bfla_test_vectors,
    evaluate_bfla_response,
    is_admin_route,
    BFLAFinding,
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


def run_bfla_flow(spec: ParsedSpecification):
    """Main interactive loop for Broken Function Level Authorization assessment."""
    while True:
        console.clear()

        console.print(
            Panel(
                f"[bold white]Target API:[/bold white] [bold cyan]{spec.title}[/bold cyan] (v{spec.version})\n"
                f"[bold white]Base URL:[/bold white]   [yellow]{spec.base_url}[/yellow]\n"
                f"[bold white]Auth Scheme:[/bold white] {spec.auth_scheme}\n"
                f"[bold white]Total Routes:[/bold white] {len(spec.endpoints)} discovered\n"
                f"[dim]Tests endpoints for user-to-admin privilege escalation, verb tampering, and missing RBAC.[/dim]",
                title="[bold purple]OWASP API5:2023 — BROKEN FUNCTION LEVEL AUTHORIZATION AUDITOR[/bold purple]",
                border_style="purple",
                padding=(1, 2),
            )
        )

        choices = [
            "1. Start Live BFLA / Privilege Escalation Scan",
            "2. Inspect Endpoints & Admin Privileges",
            "3. Return to Security Test Menu",
        ]

        try:
            selection = questionary.select(
                "Select BFLA Action:",
                choices=choices,
                style=CUSTOM_STYLE,
            ).ask()
        except (KeyboardInterrupt, EOFError):
            return

        if not selection or "3. Return" in selection:
            return

        if "1. Start Live" in selection:
            config = configure_bfla_scan(spec)
            if config:
                run_live_bfla_scan(spec, config)
        elif "2. Inspect" in selection:
            inspect_bfla_endpoints(spec.endpoints)


def configure_bfla_scan(spec: ParsedSpecification) -> Optional[Dict[str, Any]]:
    """Prompts user in terminal for target URL and low-privilege user credentials."""
    console.print()
    console.print(
        Panel(
            "[bold white]BFLA Connection & Role Configuration[/bold white]\n"
            "[dim]A Low-Privilege (Standard User) Bearer token is used to attempt administrative actions.\n"
            "If an admin route returns 200 OK, BFLA / Privilege Escalation is confirmed.[/dim]",
            title="[bold cyan]BFLA AUDIT CONFIGURATION[/bold cyan]",
            border_style="cyan",
            padding=(0, 2),
        )
    )

    default_base = spec.base_url if spec.base_url and spec.base_url.startswith("http") else "http://localhost:8008"

    try:
        base_url = questionary.text(
            "Enter Target Base URL:",
            default=default_base,
            style=CUSTOM_STYLE,
        ).ask()
        if not base_url:
            return None

        # Check for saved Fluffwalks session or local sandbox
        is_sandbox = "8008" in default_base or "8009" in default_base or "localhost" in default_base or "bfla" in spec.title.lower()
        auth_session_file = PROJECT_ROOT / "fluffwalks-test-case" / "auth_session.json"
        saved_session = {}
        if auth_session_file.exists() and not is_sandbox:
            try:
                with open(auth_session_file) as f:
                    saved_session = json.load(f)
            except Exception:
                pass

        default_tok = "Bearer user_token_101" if is_sandbox else (saved_session.get("bearer_token") or "Bearer user_token_101")

        token_input = questionary.text(
            "Enter Standard (Low-Privilege User) Bearer Token:",
            default=default_tok,
            style=CUSTOM_STYLE,
        ).ask()

        if token_input:
            token_input = token_input.strip()
            if not token_input.lower().startswith("bearer "):
                token_input = f"Bearer {token_input}"

        return {
            "base_url": base_url.rstrip("/"),
            "user_token": token_input,
        }

    except (KeyboardInterrupt, EOFError):
        return None


def run_live_bfla_scan(spec: ParsedSpecification, config: Dict[str, Any]):
    """Executes live BFLA privilege escalation probes across API routes."""
    base_url = config["base_url"]
    user_token = config["user_token"]

    headers = {"Authorization": user_token, "Accept": "application/json"}

    endpoints_to_test = [ep for ep in spec.endpoints if ep.method.upper() in ("GET", "POST", "PUT", "DELETE")]
    if not endpoints_to_test:
        endpoints_to_test = [
            APIEndpointInfo(path="/api/public/status", method="GET", summary="Public health baseline", parameters=[], is_deprecated=False),
            APIEndpointInfo(path="/api/admin/system/metrics", method="GET", summary="Admin metrics", parameters=[], is_deprecated=False),
            APIEndpointInfo(path="/api/admin/audit-logs", method="GET", summary="Audit logs", parameters=[], is_deprecated=False),
            APIEndpointInfo(path="/api/users/103", method="DELETE", summary="Delete user account", parameters=[], is_deprecated=False),
            APIEndpointInfo(path="/api/users/101/role", method="PUT", summary="Elevate user role", parameters=[], is_deprecated=False),
        ]

    console.print()
    console.print(
        Panel(
            f"[bold white]Target Host:[/bold white]      [yellow]{base_url}[/yellow]\n"
            f"[bold white]Target Endpoints:[/bold white] [bold cyan]{len(endpoints_to_test)}[/bold cyan] routes\n"
            f"[bold white]Caller Credential:[/bold white] Standard User Token [dim]({user_token[:20]}...)[/dim]\n"
            f"[dim]Probing administrative boundaries, verb tampering, and role injection...[/dim]",
            title="[bold purple]EXECUTING LIVE BFLA PRIVILEGE ESCALATION AUDIT[/bold purple]",
            border_style="purple",
            padding=(1, 2),
        )
    )

    findings: List[BFLAFinding] = []

    with Progress(
        SpinnerColumn(spinner_name="dots"),
        TextColumn("[bold cyan]{task.description}[/bold cyan]"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("Auditing function-level authorization...", total=len(endpoints_to_test))

        with httpx.Client(timeout=10.0, follow_redirects=True, verify=False) as client:
            for ep in endpoints_to_test:
                is_public = "public" in ep.path.lower() or "status" in ep.path.lower() or "health" in ep.path.lower()

                test_path = ep.path
                if "{" in test_path:
                    test_path = test_path.replace("{id}", "103").replace("{userId}", "103").replace("{productId}", "1")

                target_url = f"{base_url}/{test_path.lstrip('/')}"
                progress.update(task, description=f"Auditing [cyan]{ep.method}[/cyan] {test_path}")

                vectors = generate_bfla_test_vectors(test_path, ep.method)

                for vec in vectors:
                    try:
                        req_hdrs = dict(headers)
                        if vec.payload:
                            req_hdrs["Content-Type"] = "application/json"

                        if vec.method == "GET":
                            resp = client.get(target_url, headers=req_hdrs)
                        elif vec.method == "POST":
                            resp = client.post(target_url, headers=req_hdrs, json=vec.payload or {})
                        elif vec.method == "PUT":
                            resp = client.put(target_url, headers=req_hdrs, json=vec.payload or {})
                        elif vec.method == "DELETE":
                            resp = client.delete(target_url, headers=req_hdrs)
                        else:
                            resp = client.get(target_url, headers=req_hdrs)

                        finding = evaluate_bfla_response(
                            endpoint=test_path,
                            method=vec.method,
                            vector=vec,
                            status_code=resp.status_code,
                            response_body=resp.text,
                            base_url=base_url,
                            auth_header_value=user_token,
                            is_public=is_public,
                        )
                        findings.append(finding)

                    except Exception as err:
                        findings.append(
                            BFLAFinding(
                                endpoint=test_path,
                                method=vec.method,
                                test_id=vec.id,
                                test_name=vec.name,
                                status_code=0,
                                is_vulnerable=False,
                                severity="NONE",
                                reason=f"Connection Error: {str(err)}",
                                cwe=vec.cwe,
                                reproduction_curl=f"curl -X {vec.method} \"{target_url}\"",
                                response_snippet=f"Failed to connect: {str(err)}",
                                remediation="Verify server availability.",
                            )
                        )

                progress.advance(task, 1)

    display_bfla_results(spec, findings, config)


def display_bfla_results(
    spec: ParsedSpecification,
    findings: List[BFLAFinding],
    config: Dict[str, Any],
):
    """Renders formatted audit table, finding cards, and remediation code."""
    console.print()

    t = Table(title="[bold purple]BFLA & PRIVILEGE ESCALATION AUDIT MATRIX[/bold purple]", border_style="purple", header_style="bold cyan")
    t.add_column("Endpoint", style="bold white")
    t.add_column("Method", justify="center")
    t.add_column("Test Vector", style="dim")
    t.add_column("Status", justify="center")
    t.add_column("Verdict", justify="center")
    t.add_column("Severity", justify="center")

    vuln_findings = [f for f in findings if f.is_vulnerable]

    auth_err_count = sum(1 for f in findings if f.status_code == 401)

    for f in findings:
        method_style = "[bold green]GET[/bold green]" if f.method == "GET" else f"[bold yellow]{f.method}[/bold yellow]"

        if f.is_vulnerable:
            status_style = f"[bold red]{f.status_code}[/bold red]"
            verdict_badge = "[bold red]VULNERABLE[/bold red]"
            sev_badge = f"[bold red]{f.severity}[/bold red]" if f.severity == "CRITICAL" else f"[bold yellow]{f.severity}[/bold yellow]"
        elif f.status_code == 403:
            status_style = f"[bold green]{f.status_code}[/bold green]"
            verdict_badge = "[bold green]PROTECTED (403)[/bold green]"
            sev_badge = "[dim]CLEAR[/dim]"
        elif f.status_code == 401:
            status_style = f"[bold yellow]{f.status_code}[/bold yellow]"
            verdict_badge = "[bold yellow]AUTH REQUIRED (401)[/bold yellow]"
            sev_badge = "[yellow]INVALID TOKEN[/yellow]"
        elif f.status_code == 0:
            status_style = "[bold red]ERR[/bold red]"
            verdict_badge = "[bold red]CONN FAILED[/bold red]"
            sev_badge = "[red]OFFLINE[/red]"
        elif f.status_code in (404, 405):
            status_style = f"[dim]{f.status_code}[/dim]"
            verdict_badge = "[dim]PASS (Public)[/dim]"
            sev_badge = "[dim]NONE[/dim]"
        else:
            status_style = f"[dim]{f.status_code}[/dim]"
            verdict_badge = "[cyan]PASS (Public)[/cyan]"
            sev_badge = "[dim]NONE[/dim]"

        t.add_row(f.endpoint, method_style, f.test_name, status_style, verdict_badge, sev_badge)

    console.print(t)

    # Summary Statistics Panel
    critical_count = sum(1 for f in vuln_findings if f.severity == "CRITICAL")
    high_count = sum(1 for f in vuln_findings if f.severity == "HIGH")
    conn_err_count = sum(1 for f in findings if f.status_code == 0)

    if conn_err_count == len(findings):
        status_label = "[bold red]FAILED — TARGET SERVER UNREACHABLE (CONNECTION REFUSED / SERVER OFFLINE)[/bold red]"
        border_col = "red"
    elif vuln_findings:
        status_label = "[bold red]ACTION REQUIRED — PRIVILEGE ESCALATION FLAWS DETECTED[/bold red]"
        border_col = "red"
    elif auth_err_count > 0:
        status_label = "[bold yellow]INCONCLUSIVE — TOKEN REJECTED BY SERVER (HTTP 401 UNAUTHORIZED)[/bold yellow]"
        border_col = "yellow"
    else:
        status_label = "[bold green]COMPLIANT — RBAC STRICTLY ENFORCED (HTTP 403 FORBIDDEN)[/bold green]"
        border_col = "green"

    console.print()
    stats_panel = Panel(
        f"[bold white]Total Probes Run:[/bold white]       {len(findings)}\n"
        f"[bold white]BFLA Flaws Detected:[/bold white]    [bold red]{len(vuln_findings)}[/bold red]\n"
        f"  • [bold red]CRITICAL:[/bold red] {critical_count} (User-to-Admin privilege escalation, Verb tampering)\n"
        f"  • [bold yellow]HIGH:[/bold yellow]     {high_count} (Sensitive audit trail / export access)\n"
        f"[bold white]Status:[/bold white]             {status_label}",
        title="[bold purple]AUDIT SUMMARY[/bold purple]",
        border_style=border_col,
        padding=(0, 2),
    )
    console.print(stats_panel)

    # Detailed Vulnerability Finding Cards
    if vuln_findings:
        console.print()
        console.print("[bold red]🚨 DETAILED BFLA PRIVILEGE ESCALATION FINDINGS[/bold red]")

        for idx, vf in enumerate(vuln_findings, 1):
            sev_color = "red" if vf.severity == "CRITICAL" else "yellow"
            poc_card = Table(box=None, show_header=False, padding=(0, 1))
            poc_card.add_column("Key", style="bold cyan", width=18)
            poc_card.add_column("Val", style="white")

            poc_card.add_row("Finding #:", f"{idx} of {len(vuln_findings)}")
            poc_card.add_row("Endpoint:", f"[bold white]{vf.method} {vf.endpoint}[/bold white]")
            poc_card.add_row("Severity:", f"[bold {sev_color}]{vf.severity}[/]")
            poc_card.add_row("CWE Classification:", vf.cwe)
            poc_card.add_row("Security Impact:", f"[bold {sev_color}]{vf.reason}[/]")
            poc_card.add_row("Response Code:", f"{vf.status_code}")
            poc_card.add_row("Response Body:", f"[dim]{vf.response_snippet}[/dim]")
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
        display_bfla_code_remediation()

    # Automatically save markdown report in markdown/
    md_path = save_bfla_markdown_report(spec, findings, config)
    console.print()
    console.print(f"[bold green]✔ Comprehensive audit report saved to:[/bold green] [underline cyan]{md_path}[/underline cyan]")

    # AI Security Analysis Flow
    prompt_ai_bfla_overview(spec, findings, config)

    try:
        input("\nPress Enter to return to BFLA menu...")
    except (KeyboardInterrupt, EOFError):
        pass

    return findings


def display_bfla_code_remediation():
    """Renders production code fixes for Express.js and FastAPI RBAC."""
    console.print()
    console.print(
        Panel(
            "[bold white]Production Remediation Blueprints[/bold white]\n"
            "[dim]Implement declarative Role-Based Access Control (RBAC) guards before business logic.[/dim]",
            title="[bold green]🛠️ RECOMMENDED REMEDIATION CODE[/bold green]",
            border_style="green",
            padding=(0, 2),
        )
    )

    express_fix = """// Node.js / Express: Role-Based Authorization Guard Middleware
function requireRole(allowedRoles) {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ error: "Unauthorized: Login required" });
    }

    if (!allowedRoles.includes(req.user.role)) {
      return res.status(403).json({
        error: "Forbidden: You lack necessary permissions to invoke this action"
      });
    }

    next();
  };
}

// Protect administrative routes
app.get("/api/admin/system/metrics", requireRole(["admin"]), getSystemMetrics);
app.delete("/api/users/:userId", requireRole(["admin"]), deleteUserAccount);
app.put("/api/users/:userId/role", requireRole(["super_admin"]), updateUserRole);"""

    fastapi_fix = """# Python / FastAPI: Role Guard Dependency
from fastapi import Depends, HTTPException, status

def require_admin(current_user: User = Depends(get_current_user)):
    if current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Forbidden: Administrative privileges required"
        )
    return current_user

@app.delete("/api/users/{user_id}", dependencies=[Depends(require_admin)])
def delete_user(user_id: int):
    return {"status": "deleted"}"""

    console.print("[bold cyan]Node.js (Express) Fix:[/bold cyan]")
    console.print(Syntax(express_fix, "javascript", theme="monokai", line_numbers=True))
    console.print()
    console.print("[bold cyan]Python (FastAPI) Fix:[/bold cyan]")
    console.print(Syntax(fastapi_fix, "python", theme="monokai", line_numbers=True))


def save_bfla_markdown_report(
    spec: ParsedSpecification,
    findings: List[BFLAFinding],
    config: Dict[str, Any],
) -> Path:
    """Saves structured markdown report in the root markdown/ directory."""
    md_dir = get_markdown_dir()
    slug = "".join([c if c.isalnum() else "_" for c in spec.title.lower()]).strip("_") or "api"
    filename = f"{slug}_bfla_privilege_escalation_scan_results_{int(time.time())}.md"
    file_path = md_dir / filename

    vuln_findings = [f for f in findings if f.is_vulnerable]

    lines = [
        "# OWASP API5:2023 — Broken Function Level Authorization (BFLA) Audit Report",
        "",
        f"- **API Target:** {spec.title} (v{spec.version})",
        f"- **Base URL:** `{config.get('base_url')}`",
        f"- **Scan Timestamp:** {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}",
        f"- **Standard:** OWASP API Security Top 10 — API5:2023 Broken Function Level Authorization",
        f"- **Probes Executed:** {len(findings)}",
        f"- **Privilege Escalation Flaws:** {len(vuln_findings)}",
        "",
        "## Executive Summary",
        f"{'CRITICAL WARNING: The target API suffers from Broken Function Level Authorization. Standard non-administrative user tokens are capable of invoking administrative routes, executing destructive account deletions, or elevating privileges.' if vuln_findings else 'CLEARANCE: Role-based access control (RBAC) boundaries are strictly enforced. All non-admin attempts to invoke administrative operations were rejected with HTTP 403 Forbidden.'}",
        "",
        "## Findings Matrix",
        "",
        "| Endpoint | Method | Test Vector | Status | Verdict | Severity |",
        "| :--- | :---: | :--- | :---: | :---: | :---: |",
    ]

    for f in findings:
        verdict = "**VULNERABLE**" if f.is_vulnerable else ("PROTECTED" if f.status_code in (403, 401, 405) else "PASS (Public)")
        lines.append(f"| `{f.endpoint}` | {f.method} | {f.test_name} | `{f.status_code}` | {verdict} | {f.severity} |")

    if vuln_findings:
        lines.extend([
            "",
            "## Detailed Vulnerability Analysis & Proof of Concept",
            "",
        ])
        for idx, vf in enumerate(vuln_findings, 1):
            lines.extend([
                f"### Finding {idx}: Privilege Escalation on `{vf.method} {vf.endpoint}`",
                f"- **Severity:** {vf.severity}",
                f"- **CWE Classification:** {vf.cwe}",
                f"- **HTTP Status Code Returned:** `{vf.status_code}`",
                f"- **Security Risk:** {vf.reason}",
                "",
                "**Reproduction Proof-of-Concept:**",
                "```bash",
                vf.reproduction_curl,
                "```",
                "",
                "**Server Response Preview:**",
                "```json",
                vf.response_snippet,
                "```",
                "",
                "**Remediation Recommendation:**",
                f"> {vf.remediation}",
                "",
            ])

    with open(file_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    return file_path


def prompt_ai_bfla_overview(
    spec: ParsedSpecification,
    findings: List[BFLAFinding],
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
    prompt_text = build_bfla_ai_prompt(spec, findings, config)
    usage = estimate_token_usage(prompt_text)

    console.print()
    t = Table(box=None, show_header=False, padding=(0, 2))
    t.add_column("Key", style="bold cyan")
    t.add_column("Val", style="bold white")

    t.add_row("Active AI Model:", f"[bold green]{ai_cfg['model']}[/bold green] [dim]({ai_cfg['provider']})[/dim]")
    t.add_row("Target API Scope:", f"{spec.title} ({len(findings)} probes evaluated)")
    t.add_row("Context Included:", "OpenAPI endpoints, role matrix, verb tampering status, HTTP response codes")
    t.add_row("Context Payload:", f"{usage['char_count']} characters [dim](full test telemetry)[/dim]")
    t.add_row("Estimated Prompt Cost:", f"[bold yellow]~{usage['prompt_tokens']} input tokens[/bold yellow]")
    t.add_row("Estimated Generation:", f"~{usage['estimated_output_tokens']} completion tokens")
    t.add_row("Estimated Total:", f"[bold cyan]~{usage['estimated_total_tokens']} tokens[/bold cyan]")

    console.print(
        Panel(
            t,
            title="[bold purple]⚡ SENTINEL AI INTELLIGENCE OVERVIEW[/bold purple]",
            border_style="purple",
            padding=(1, 2),
        )
    )

    try:
        wants_ai = questionary.confirm(
            f"Generate AI BFLA & RBAC Security Blueprint with {ai_cfg['model']}?",
            default=True,
            style=CUSTOM_STYLE,
        ).ask()
    except (KeyboardInterrupt, EOFError):
        return

    if not wants_ai:
        console.print("[dim]AI Overview skipped by user.[/dim]")
        return

    with Progress(
        SpinnerColumn(spinner_name="dots"),
        TextColumn("[bold cyan]{task.description}[/bold cyan]"),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        task = progress.add_task(f"Connecting to {ai_cfg['model']}...", total=None)

        def update_spinner(count: int):
            progress.update(task, description=f"[bold green]Generating RBAC Security Overview ({count} tokens)...[/bold green]")

        success, response_text = request_ai_overview(prompt_text, progress_callback=update_spinner)

    if not success or not response_text:
        console.print(f"[bold red]AI Generation Failed:[/bold red] {response_text}")
        return

    console.print()
    console.print(
        Panel(
            Markdown(response_text),
            title="[bold purple]🤖 AI EXECUTIVE BFLA ASSESSMENT[/bold purple]",
            border_style="purple",
            padding=(1, 2),
        )
    )

    # Save AI report
    md_dir = get_markdown_dir()
    slug = "".join([c if c.isalnum() else "_" for c in spec.title.lower()]).strip("_") or "api"
    ai_filename = f"{slug}_bfla_ai_report_{int(time.time())}.md"
    ai_file_path = md_dir / ai_filename

    with open(ai_file_path, "w", encoding="utf-8") as f:
        f.write(f"# Sentinel AI Security Overview: {spec.title}\n\n")
        f.write(f"- Standard: OWASP API5:2023 — Broken Function Level Authorization\n")
        f.write(f"- Generated At: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}\n")
        f.write(f"- AI Model: {ai_cfg['model']}\n\n")
        f.write(response_text)

    console.print(f"[bold green]✔ AI Security Report saved to:[/bold green] [underline cyan]{ai_file_path}[/underline cyan]")


def build_bfla_ai_prompt(
    spec: ParsedSpecification,
    findings: List[BFLAFinding],
    config: Dict[str, Any],
) -> str:
    """Builds a targeted prompt for AI analysis of Broken Function Level Authorization."""
    vuln_findings = [f for f in findings if f.is_vulnerable]

    lines = [
        "You are an Elite Principal Security Architect specializing in API Authorization Models and Role-Based Access Control (RBAC).",
        "Perform a comprehensive security evaluation based on the live BFLA audit telemetry below:",
        "",
        f"- Target API: {spec.title} (v{spec.version})",
        f"- Target Base URL: {config.get('base_url')}",
        f"- Standard: OWASP API5:2023 — Broken Function Level Authorization (BFLA)",
        f"- Probes Executed: {len(findings)}",
        f"- Vulnerable Endpoints Detected: {len(vuln_findings)}",
        "",
        "### Audit Telemetry Summary:",
    ]

    for f in findings:
        lines.append(
            f"- Endpoint: {f.method} {f.endpoint} | Vector: {f.test_name} | Status: {f.status_code} | "
            f"Vulnerable: {f.is_vulnerable} | Severity: {f.severity} | Reason: {f.reason}"
        )

    lines.extend([
        "",
        "### Report Requirements:",
        "1. Executive Threat Summary: Detail the business impact of standard users seizing administrative control or altering critical business functions.",
        "2. Technical Flaw Deep Dive: Explain why relying on UI concealment or HTTP verb assumptions creates severe authorization bypasses.",
        "3. Concrete Production Blueprint: Provide exact, production-grade RBAC middleware code (Node.js/Express, Python/FastAPI, or Java/Spring Security) to enforce strict role checks.",
        "4. Policy-as-Code & Zero-Trust: Explain how to implement Open Policy Agent (OPA) or declarative permission matrices.",
        "",
        "Format your response in clean, professional GitHub Flavored Markdown.",
    ])

    return "\n".join(lines)


def inspect_bfla_endpoints(endpoints: List[APIEndpointInfo]):
    """Displays endpoint administrative classification from OpenAPI specification."""
    console.print()
    t = Table(title="[bold purple]OPENAPI FUNCTION LEVEL PRIVILEGE MATRIX[/bold purple]", border_style="purple", header_style="bold cyan")
    t.add_column("Path", style="bold white")
    t.add_column("Method", justify="center")
    t.add_column("Classification", justify="center")
    t.add_column("Required Role", justify="center")

    for ep in endpoints:
        method_style = "[bold green]GET[/bold green]" if ep.method == "GET" else f"[bold yellow]{ep.method}[/bold yellow]"
        if is_admin_route(ep.path):
            cls_badge = "[bold red]ADMINISTRATIVE / PRIVILEGED[/bold red]"
            role_badge = "[bold red]Admin / Superuser[/bold red]"
        elif "public" in ep.path.lower() or "health" in ep.path.lower():
            cls_badge = "[cyan]Public Baseline[/cyan]"
            role_badge = "[dim]Anonymous (No Auth)[/dim]"
        else:
            cls_badge = "[yellow]Standard Business Route[/yellow]"
            role_badge = "[bold green]Standard User (Role: user)[/bold green]"

        t.add_row(ep.path, method_style, cls_badge, role_badge)

    console.print(t)
    try:
        input("\nPress Enter to return to menu...")
    except (KeyboardInterrupt, EOFError):
        pass
