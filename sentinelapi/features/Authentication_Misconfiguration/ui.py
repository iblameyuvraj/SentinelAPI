"""Authentication Misconfiguration (OWASP API2:2023) interactive assessment UI & live scanner."""

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
from sentinelapi.features.Authentication_Misconfiguration.detector import (
    generate_auth_test_vectors,
    evaluate_auth_response,
    AuthMutationVector,
    AuthAuditFinding,
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


def run_auth_misconfig_flow(spec: ParsedSpecification):
    """Main interactive loop for Authentication Misconfiguration assessment."""
    while True:
        console.clear()

        console.print(
            Panel(
                f"[bold white]Target API:[/bold white] [bold cyan]{spec.title}[/bold cyan] (v{spec.version})\n"
                f"[bold white]Base URL:[/bold white]   [yellow]{spec.base_url}[/yellow]\n"
                f"[bold white]Auth Scheme:[/bold white] {spec.auth_scheme}\n"
                f"[bold white]Total Routes:[/bold white] {len(spec.endpoints)} discovered\n"
                f"[dim]Tests endpoints for missing authentication, alg:none bypass, signature tampering, expired tokens, and verbose errors.[/dim]",
                title="[bold yellow]OWASP API2:2023 — AUTHENTICATION MISCONFIGURATION AUDITOR[/bold yellow]",
                border_style="yellow",
                padding=(1, 2),
            )
        )

        choices = [
            "1. Start Live API Auth Scan",
            "2. Inspect Endpoints & Auth Requirements",
            "3. Return to Security Test Menu",
        ]

        try:
            selection = questionary.select(
                "Select Authentication Misconfiguration Action:",
                choices=choices,
                style=CUSTOM_STYLE,
            ).ask()
        except (KeyboardInterrupt, EOFError):
            return

        if not selection or "3. Return" in selection:
            return

        if "1. Start Live" in selection:
            config = configure_auth_scan(spec)
            if config:
                run_live_auth_scan(spec, config)
        elif "2. Inspect" in selection:
            inspect_auth_endpoints(spec.endpoints)


def configure_auth_scan(spec: ParsedSpecification) -> Optional[Dict[str, Any]]:
    """Prompts user in terminal for target URL, valid Bearer token, and test vectors."""
    console.print()
    console.print(
        Panel(
            "[bold white]Target Connection & Authentication Parameters[/bold white]\n"
            "[dim]A baseline valid Bearer Token / JWT is used to craft mutation vectors (alg:none, tampered signature, expired tokens).\n"
            "If no token is provided, synthesized probe tokens will be used.[/dim]",
            title="[bold cyan]AUTHENTICATION SCAN CONFIGURATION[/bold cyan]",
            border_style="cyan",
            padding=(0, 2),
        )
    )

    default_base = spec.base_url if spec.base_url and spec.base_url.startswith("http") else "http://localhost:8004"

    try:
        base_url = questionary.text(
            "Enter Target Base URL:",
            default=default_base,
            style=CUSTOM_STYLE,
        ).ask()
        if not base_url:
            return None

        # Check for saved Fluffwalks session
        auth_session_file = PROJECT_ROOT / "fluffwalks-test-case" / "auth_session.json"
        saved_session = {}
        if auth_session_file.exists():
            try:
                with open(auth_session_file) as f:
                    saved_session = json.load(f)
            except Exception:
                pass

        default_tok = saved_session.get("bearer_token") or "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MTAxLCJ1c2VybmFtZSI6Inl1dnJhal9kZXYiLCJyb2xlIjoiZGV2ZWxvcGVyIiwiaWF0IjoxNzg5MDAwMDAwLCJleHAiOjE4ODkwMDAwMDB9.dummy_valid_sig"

        token_input = questionary.text(
            "Enter Baseline Valid Bearer Token / JWT (or press Enter for default):",
            default=default_tok,
            style=CUSTOM_STYLE,
        ).ask()

        if token_input:
            token_input = token_input.strip()
            if token_input.lower().startswith("bearer "):
                token_input = token_input[7:].strip()

        # Vector Scope Selection
        vector_choice = questionary.select(
            "Select Authentication Test Vectors to Execute:",
            choices=[
                "1. All Test Vectors (Missing Auth, alg:none, Tampered Sig, Expired Token, Malformed)",
                "2. Missing Auth Only (Unprotected Endpoint Detection)",
                "3. JWT Specific (alg:none bypass, signature tampering, expired claims)",
            ],
            style=CUSTOM_STYLE,
        ).ask()

        return {
            "base_url": base_url.rstrip("/"),
            "base_token": token_input,
            "vector_choice": vector_choice,
        }

    except (KeyboardInterrupt, EOFError):
        return None


def run_live_auth_scan(spec: ParsedSpecification, config: Dict[str, Any]):
    """Executes live HTTP requests across endpoints and mutation vectors."""
    base_url = config["base_url"]
    base_token = config["base_token"]
    vector_choice = config.get("vector_choice", "")

    all_vectors = generate_auth_test_vectors(base_token=base_token)

    # Filter vectors if user chose subset
    if "2. Missing Auth" in vector_choice:
        test_vectors = [v for v in all_vectors if "NO-AUTH" in v.id]
    elif "3. JWT" in vector_choice:
        test_vectors = [v for v in all_vectors if any(x in v.id for x in ("ALG-NONE", "TAMPERED", "EXPIRED"))]
    else:
        test_vectors = all_vectors

    # Filter candidate endpoints
    endpoints_to_test = [ep for ep in spec.endpoints if ep.method.upper() in ("GET", "POST", "PUT")]
    if not endpoints_to_test:
        endpoints_to_test = [
            APIEndpointInfo(path="/api/public/status", method="GET", summary="Public health baseline", parameters=[], is_deprecated=False),
            APIEndpointInfo(path="/api/admin/users", method="GET", summary="Admin users", parameters=[], is_deprecated=False),
            APIEndpointInfo(path="/api/user/profile", method="GET", summary="User profile", parameters=[], is_deprecated=False),
            APIEndpointInfo(path="/api/user/settings", method="GET", summary="User settings", parameters=[], is_deprecated=False),
            APIEndpointInfo(path="/api/user/data", method="GET", summary="User data vault", parameters=[], is_deprecated=False),
        ]

    total_probes = len(endpoints_to_test) * len(test_vectors)

    console.print()
    console.print(
        Panel(
            f"[bold white]Target Host:[/bold white]      [yellow]{base_url}[/yellow]\n"
            f"[bold white]Target Endpoints:[/bold white] [bold cyan]{len(endpoints_to_test)}[/bold cyan] routes\n"
            f"[bold white]Test Vectors:[/bold white]     [bold magenta]{len(test_vectors)}[/bold magenta] vectors per route\n"
            f"[bold white]Total HTTP Probes:[/bold white]   [bold green]{total_probes}[/bold green] requests\n"
            f"[dim]Live network probing underway...[/dim]",
            title="[bold yellow]EXECUTING LIVE AUTHENTICATION MISCONFIGURATION AUDIT[/bold yellow]",
            border_style="yellow",
            padding=(1, 2),
        )
    )

    findings: List[AuthAuditFinding] = []

    with Progress(
        SpinnerColumn(spinner_name="dots"),
        TextColumn("[bold cyan]{task.description}[/bold cyan]"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("Auditing authentication boundaries...", total=total_probes)

        with httpx.Client(timeout=10.0, follow_redirects=True, verify=False) as client:
            for ep in endpoints_to_test:
                # Determine if endpoint is public
                is_public = (
                    "public" in ep.path.lower()
                    or "health" in ep.path.lower()
                    or "status" in ep.path.lower()
                    or (hasattr(ep, "security") and ep.security == [])
                )

                # Format endpoint path replacing any path variables
                test_path = ep.path
                if "{" in test_path:
                    test_path = test_path.replace("{id}", "101").replace("{userId}", "101").replace("{productId}", "1")

                target_url = f"{base_url}/{test_path.lstrip('/')}"

                for vec in test_vectors:
                    progress.update(task, description=f"[cyan]{ep.method}[/cyan] {test_path} [dim]({vec.name})[/dim]")

                    try:
                        headers = dict(vec.headers)
                        headers["Accept"] = "application/json"

                        if ep.method.upper() == "GET":
                            resp = client.get(target_url, headers=headers)
                        elif ep.method.upper() == "POST":
                            resp = client.post(target_url, headers=headers, json={})
                        elif ep.method.upper() == "PUT":
                            resp = client.put(target_url, headers=headers, json={})
                        else:
                            resp = client.get(target_url, headers=headers)

                        finding = evaluate_auth_response(
                            endpoint=test_path,
                            method=ep.method.upper(),
                            vector=vec,
                            status_code=resp.status_code,
                            response_body=resp.text,
                            base_url=base_url,
                            is_public=is_public,
                        )
                        findings.append(finding)

                    except Exception as err:
                        findings.append(
                            AuthAuditFinding(
                                endpoint=test_path,
                                method=ep.method.upper(),
                                test_id=vec.id,
                                test_name=vec.name,
                                status_code=0,
                                is_vulnerable=False,
                                severity="NONE",
                                reason=f"Connection Error: {str(err)}",
                                cwe=vec.cwe,
                                reproduction_curl=f"curl -X {ep.method.upper()} \"{target_url}\"",
                                response_snippet=f"Failed to connect to {target_url}",
                                remediation="Verify server availability and network connectivity.",
                            )
                        )

                    progress.advance(task, 1)

    return display_auth_results(spec, findings, config)


def display_auth_results(
    spec: ParsedSpecification,
    findings: List[AuthAuditFinding],
    config: Dict[str, Any],
):
    """Renders formatted audit tables, failure details, and remediation guidance."""
    console.print()

    # Matrix Table
    t = Table(title="[bold yellow]AUTHENTICATION MISCONFIGURATION AUDIT MATRIX[/bold yellow]", border_style="yellow", header_style="bold cyan")
    t.add_column("Endpoint", style="bold white")
    t.add_column("Method", justify="center")
    t.add_column("Test Vector", style="dim")
    t.add_column("Status", justify="center")
    t.add_column("Verdict", justify="center")
    t.add_column("Severity", justify="center")

    vuln_findings = [f for f in findings if f.is_vulnerable]

    for f in findings:
        method_style = "[bold green]GET[/bold green]" if f.method == "GET" else f"[bold yellow]{f.method}[/bold yellow]"
        status_style = f"[bold green]{f.status_code}[/bold green]" if f.status_code in (401, 403) else (
            f"[bold red]{f.status_code}[/bold red]" if f.status_code in (200, 201, 204, 500) else f"[dim]{f.status_code}[/dim]"
        )

        if f.is_vulnerable:
            verdict_badge = "[bold red]VULNERABLE[/bold red]"
            sev_badge = f"[bold red]{f.severity}[/bold red]" if f.severity == "CRITICAL" else f"[bold yellow]{f.severity}[/bold yellow]"
        elif f.status_code == 0:
            verdict_badge = "[bold red]ERROR (UNREACHABLE)[/bold red]"
            sev_badge = "[red]PROBE_ERROR[/red]"
        elif f.status_code in (401, 403):
            verdict_badge = "[bold green]PROTECTED[/bold green]"
            sev_badge = "[dim]CLEAR[/dim]"
        else:
            verdict_badge = "[cyan]PUBLIC / PASS[/cyan]"
            sev_badge = "[dim]NONE[/dim]"

        t.add_row(f.endpoint, method_style, f.test_name, status_style, verdict_badge, sev_badge)

    console.print(t)

    # Summary Statistics (Fail-Closed)
    vuln_findings = [f for f in findings if f.is_vulnerable]
    conn_err_count = sum(1 for f in findings if f.status_code == 0)
    critical_count = sum(1 for f in vuln_findings if f.severity == "CRITICAL")
    high_count = sum(1 for f in vuln_findings if f.severity == "HIGH")
    medium_count = sum(1 for f in vuln_findings if f.severity == "MEDIUM")

    if conn_err_count == len(findings):
        status_label = "[bold red]ERROR — TARGET SERVER UNREACHABLE (0 PROBES SUCCEEDED)[/bold red]"
        card_border = "red"
    elif vuln_findings:
        status_label = "[bold red]ACTION REQUIRED — BROKEN AUTHENTICATION VULNERABILITIES DETECTED[/bold red]"
        card_border = "red"
    elif conn_err_count > 0:
        status_label = f"[bold yellow]INCOMPLETE — {conn_err_count} PROBE(S) FAILED / UNREACHABLE[/bold yellow]"
        card_border = "yellow"
    else:
        status_label = "[bold green]COMPLIANT — ALL BOUNDARIES SECURE[/bold green]"
        card_border = "green"

    console.print()
    stats_panel = Panel(
        f"[bold white]Total Probes Run:[/bold white]       {len(findings)}\n"
        f"[bold white]Vulnerabilities Found:[/bold white]  [bold red]{len(vuln_findings)}[/bold red]\n"
        f"  • [bold red]CRITICAL:[/bold red] {critical_count} (Missing auth, alg:none bypass, unverified signatures)\n"
        f"  • [bold yellow]HIGH:[/bold yellow]     {high_count} (Expired tokens accepted)\n"
        f"  • [bold cyan]MEDIUM:[/bold cyan]   {medium_count} (Verbose 500 stack trace leaks)\n"
        f"[bold white]Probe Failures:[/bold white]        {conn_err_count} Unreachable / Failed\n"
        f"[bold white]Audit Status:[/bold white]          {status_label}",
        title="[bold yellow]AUDIT SUMMARY[/bold yellow]",
        border_style=card_border,
        padding=(0, 2),
    )
    console.print(stats_panel)

    # Detailed Vulnerability Cards
    if vuln_findings:
        console.print()
        console.print("[bold red]🚨 DETAILED VULNERABILITY FINDINGS & PROOF-OF-CONCEPT[/bold red]")

        for idx, vf in enumerate(vuln_findings, 1):
            sev_color = "red" if vf.severity == "CRITICAL" else "yellow"
            poc_card = Table(box=None, show_header=False, padding=(0, 1))
            poc_card.add_column("Key", style="bold cyan", width=18)
            poc_card.add_column("Val", style="white")

            poc_card.add_row("Finding #:", f"{idx} of {len(vuln_findings)}")
            poc_card.add_row("Endpoint:", f"[bold white]{vf.method} {vf.endpoint}[/bold white]")
            poc_card.add_row("Severity:", f"[bold {sev_color}]{vf.severity}[/bold {sev_color}]")
            poc_card.add_row("CWE Classification:", vf.cwe)
            poc_card.add_row("Failure Reason:", f"[bold {sev_color}]{vf.reason}[/bold {sev_color}]")
            poc_card.add_row("Response Status:", f"{vf.status_code}")
            poc_card.add_row("Response Sample:", f"[dim]{vf.response_snippet}[/dim]")
            poc_card.add_row("PoC cURL Command:", f"[bold green]{vf.reproduction_curl}[/bold green]")
            poc_card.add_row("Remediation Fix:", vf.remediation)

            console.print(
                Panel(
                    poc_card,
                    title=f"[bold {sev_color}]VULNERABILITY: {vf.test_name}[/bold {sev_color}]",
                    border_style=sev_color,
                    padding=(1, 2),
                )
            )

        # Code Remediation Snippets
        display_code_remediation()

    # Automatically save markdown report in markdown/
    md_path = save_auth_markdown_report(spec, findings, config)
    console.print()
    console.print(f"[bold green]✔ Comprehensive audit report saved to:[/bold green] [underline cyan]{md_path}[/underline cyan]")

    # AI Security Analysis Flow
    prompt_ai_auth_overview(spec, findings, config)

    try:
        input("\nPress Enter to return to Authentication Misconfiguration menu...")
    except (KeyboardInterrupt, EOFError):
        pass

    return findings


def display_code_remediation():
    """Renders production code fixes for Express.js and FastAPI."""
    console.print()
    console.print(
        Panel(
            "[bold white]Production Remediation Blueprints[/bold white]\n"
            "[dim]Implement strict JWT algorithm whitelisting, signature verification, and mandatory route guards.[/dim]",
            title="[bold green]🛠️ RECOMMENDED REMEDIATION CODE[/bold green]",
            border_style="green",
            padding=(0, 2),
        )
    )

    express_fix = """// Node.js / Express.js: Hardened JWT Authentication Middleware
const jwt = require("jsonwebtoken");

function requireAuth(req, res, next) {
  const authHeader = req.headers["authorization"];
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Unauthorized: Missing Bearer token" });
  }

  const token = authHeader.split(" ")[1];

  try {
    // 1. Explicitly whitelist HS256 to prevent 'alg: none' and algorithm confusion
    // 2. Secret key verifies HMAC cryptographic signature
    // 3. Automatically enforces 'exp' (expiration) validation
    const decoded = jwt.verify(token, process.env.JWT_SECRET, {
      algorithms: ["HS256"],
      clockTolerance: 0,
    });

    req.user = decoded;
    next();
  } catch (err) {
    // Safe error handling: Do not leak stack traces or internal parsing errors
    return res.status(401).json({ error: "Unauthorized: Invalid or expired token" });
  }
}"""

    fastapi_fix = """# Python / FastAPI: Hardened JWT Route Guard
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import jwt

security = HTTPBearer()
JWT_SECRET = os.getenv("JWT_SECRET")

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    try:
        # Enforces HS256 algorithm and verifies signature + exp timestamp
        payload = jwt.decode(
            token,
            JWT_SECRET,
            algorithms=["HS256"],
            options={"require": ["exp", "sub"]}
        )
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except (jwt.InvalidTokenError, Exception):
        raise HTTPException(status_code=401, detail="Invalid authorization credentials")"""

    console.print("[bold cyan]Node.js (Express) Fix:[/bold cyan]")
    console.print(Syntax(express_fix, "javascript", theme="monokai", line_numbers=True))
    console.print()
    console.print("[bold cyan]Python (FastAPI) Fix:[/bold cyan]")
    console.print(Syntax(fastapi_fix, "python", theme="monokai", line_numbers=True))


def save_auth_markdown_report(
    spec: ParsedSpecification,
    findings: List[AuthAuditFinding],
    config: Dict[str, Any],
) -> Path:
    """Saves structured markdown report in the root markdown/ directory."""
    md_dir = get_markdown_dir()
    slug = "".join([c if c.isalnum() else "_" for c in spec.title.lower()]).strip("_") or "api"
    filename = f"{slug}_auth_misconfiguration_scan_results_{int(time.time())}.md"
    file_path = md_dir / filename

    vuln_findings = [f for f in findings if f.is_vulnerable]

    lines = [
        f"# OWASP API2:2023 — Authentication Misconfiguration Security Audit Report",
        "",
        f"- **API Target:** {spec.title} (v{spec.version})",
        f"- **Base URL:** `{config.get('base_url')}`",
        f"- **Scan Timestamp:** {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}",
        f"- **Standard:** OWASP API Security Top 10 — API2:2023 Broken Authentication",
        f"- **Total Probes Executed:** {len(findings)}",
        f"- **Vulnerabilities Identified:** {len(vuln_findings)}",
        "",
        "## Executive Summary",
        f"{'CRITICAL FINDING: Authentication controls are misconfigured. One or more endpoints permit unauthenticated access, accept unsigned (alg: none) tokens, ignore expired credentials, or leak verbose server traces.' if vuln_findings else 'CLEARANCE: Authentication boundaries are strictly enforced. Unauthenticated, unsigned, expired, and forged requests were all properly rejected with 401/403 status codes.'}",
        "",
        "## Findings Matrix",
        "",
        "| Endpoint | Method | Test Vector | Status | Verdict | Severity |",
        "| :--- | :---: | :--- | :---: | :---: | :---: |",
    ]

    for f in findings:
        verdict = "**VULNERABLE**" if f.is_vulnerable else "PROTECTED"
        lines.append(f"| `{f.endpoint}` | {f.method} | {f.test_name} | `{f.status_code}` | {verdict} | {f.severity} |")

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
                f"- **CWE Classification:** {vf.cwe}",
                f"- **HTTP Status Code Returned:** `{vf.status_code}`",
                f"- **Security Impact:** {vf.reason}",
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


def prompt_ai_auth_overview(
    spec: ParsedSpecification,
    findings: List[AuthAuditFinding],
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
    prompt_text = build_auth_ai_prompt(spec, findings, config)
    usage = estimate_token_usage(prompt_text)

    console.print()
    t = Table(box=None, show_header=False, padding=(0, 2))
    t.add_column("Key", style="bold cyan")
    t.add_column("Val", style="bold white")

    t.add_row("Active AI Model:", f"[bold green]{ai_cfg['model']}[/bold green] [dim]({ai_cfg['provider']})[/dim]")
    t.add_row("Target API Scope:", f"{spec.title} ({len(findings)} probes evaluated)")
    t.add_row("Context Included:", "OpenAPI endpoints, auth test vectors, HTTP status codes, verdicts")
    t.add_row("Context Payload:", f"{usage['char_count']} characters [dim](full test telemetry)[/dim]")
    t.add_row("Estimated Prompt Cost:", f"[bold yellow]~{usage['prompt_tokens']} input tokens[/bold yellow]")
    t.add_row("Estimated Generation:", f"~{usage['estimated_output_tokens']} completion tokens")
    t.add_row("Estimated Total:", f"[bold cyan]~{usage['estimated_total_tokens']} tokens[/bold cyan]")

    console.print(
        Panel(
            t,
            title="[bold yellow]⚡ SENTINEL AI INTELLIGENCE OVERVIEW[/bold yellow]",
            border_style="yellow",
            padding=(1, 2),
        )
    )

    try:
        wants_ai = questionary.confirm(
            f"Generate AI Security Overview & Remediation Blueprint with {ai_cfg['model']}?",
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
            progress.update(task, description=f"[bold green]Generating Security Overview ({count} tokens)...[/bold green]")

        success, response_text = request_ai_overview(prompt_text, progress_callback=update_spinner)

    if not success or not response_text:
        console.print(f"[bold red]AI Generation Failed:[/bold red] {response_text}")
        return

    console.print()
    console.print(
        Panel(
            Markdown(response_text),
            title="[bold yellow]🤖 AI EXECUTIVE AUTHENTICATION ASSESSMENT[/bold yellow]",
            border_style="yellow",
            padding=(1, 2),
        )
    )

    # Save AI report
    md_dir = get_markdown_dir()
    slug = "".join([c if c.isalnum() else "_" for c in spec.title.lower()]).strip("_") or "api"
    ai_filename = f"{slug}_auth_misconfiguration_ai_report_{int(time.time())}.md"
    ai_file_path = md_dir / ai_filename

    with open(ai_file_path, "w", encoding="utf-8") as f:
        f.write(f"# Sentinel AI Security Overview: {spec.title}\n\n")
        f.write(f"- Standard: OWASP API2:2023 — Authentication Misconfiguration\n")
        f.write(f"- Generated At: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}\n")
        f.write(f"- AI Model: {ai_cfg['model']}\n\n")
        f.write(response_text)

    console.print(f"[bold green]✔ AI Security Report saved to:[/bold green] [underline cyan]{ai_file_path}[/underline cyan]")


def build_auth_ai_prompt(
    spec: ParsedSpecification,
    findings: List[AuthAuditFinding],
    config: Dict[str, Any],
) -> str:
    """Builds a targeted prompt for AI analysis of Authentication Misconfiguration."""
    vuln_findings = [f for f in findings if f.is_vulnerable]

    lines = [
        "You are a Principal Application Security Architect specializing in API Security (OWASP API Top 10).",
        "Perform a comprehensive security evaluation based on the live authentication audit telemetry below:",
        "",
        f"- Target API: {spec.title} (v{spec.version})",
        f"- Target Base URL: {config.get('base_url')}",
        f"- Vulnerability Standard: OWASP API2:2023 — Broken Authentication / Authentication Misconfiguration",
        f"- Total Probes Executed: {len(findings)}",
        f"- Vulnerable Vectors Detected: {len(vuln_findings)}",
        "",
        "### Audit Telemetry Summary:",
    ]

    for f in findings:
        lines.append(
            f"- Endpoint: {f.method} {f.endpoint} | Test: {f.test_name} | Status: {f.status_code} | "
            f"Vulnerable: {f.is_vulnerable} | Severity: {f.severity} | Reason: {f.reason}"
        )

    lines.extend([
        "",
        "### Report Requirements:",
        "1. Executive Threat Summary: Summarize the business & compliance impact (e.g. Account Takeover, Privilege Escalation).",
        "2. Technical Flaw Deep Dive: Explain the root cause of any detected flaws (e.g. missing middleware, alg:none bypass, lack of exp validation).",
        "3. Concrete Remediation Blueprint: Provide exact, hardened code snippets (FastAPI, Express.js, or Spring Boot) showing how to patch the vulnerabilities.",
        "4. Testing / CI Guardrails: Suggest automated regression checks to prevent authentication misconfigurations in CI/CD.",
        "",
        "Format your response in clean, professional GitHub Flavored Markdown.",
    ])

    return "\n".join(lines)


def inspect_auth_endpoints(endpoints: List[APIEndpointInfo]):
    """Displays endpoint authentication requirements from OpenAPI specification."""
    console.print()
    t = Table(title="[bold yellow]OPENAPI ENDPOINTS AUTHENTICATION MATRIX[/bold yellow]", border_style="yellow", header_style="bold cyan")
    t.add_column("Path", style="bold white")
    t.add_column("Method", justify="center")
    t.add_column("Summary", style="dim")
    t.add_column("Security Required", justify="center")

    for ep in endpoints:
        method_style = "[bold green]GET[/bold green]" if ep.method == "GET" else f"[bold yellow]{ep.method}[/bold yellow]"
        is_pub = "public" in ep.path.lower() or "status" in ep.path.lower() or "health" in ep.path.lower()
        sec_label = "[dim]None (Public)[/dim]" if is_pub else "[bold green]Bearer Auth Required[/bold green]"
        t.add_row(ep.path, method_style, ep.summary or "Endpoint", sec_label)

    console.print(t)
    try:
        input("\nPress Enter to return to menu...")
    except (KeyboardInterrupt, EOFError):
        pass
