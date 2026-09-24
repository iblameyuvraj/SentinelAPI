"""Rate Limiting & Resource Exhaustion (OWASP API4:2023) interactive assessment UI & live scanner."""

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
from sentinelapi.features.Rate_Limiting.detector import (
    evaluate_rate_limit_results,
    RateLimitFinding,
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


def run_rate_limiting_flow(spec: ParsedSpecification):
    """Main interactive loop for Rate Limiting assessment."""
    while True:
        console.clear()

        console.print(
            Panel(
                f"[bold white]Target API:[/bold white] [bold cyan]{spec.title}[/bold cyan] (v{spec.version})\n"
                f"[bold white]Base URL:[/bold white]   [yellow]{spec.base_url}[/yellow]\n"
                f"[bold white]Auth Scheme:[/bold white] {spec.auth_scheme}\n"
                f"[bold white]Total Routes:[/bold white] {len(spec.endpoints)} discovered\n"
                f"[dim]Tests endpoints for missing rate limits, brute-force exposure, and resource exhaustion.[/dim]",
                title="[bold red]OWASP API4:2023 — RATE LIMITING & RESOURCE EXHAUSTION AUDITOR[/bold red]",
                border_style="red",
                padding=(1, 2),
            )
        )

        choices = [
            "1. Start Live Burst Rate Limit Scan",
            "2. Inspect Endpoints & Sensitivity",
            "3. Return to Security Test Menu",
        ]

        try:
            selection = questionary.select(
                "Select Rate Limiting Action:",
                choices=choices,
                style=CUSTOM_STYLE,
            ).ask()
        except (KeyboardInterrupt, EOFError):
            return

        if not selection or "3. Return" in selection:
            return

        if "1. Start Live" in selection:
            config = configure_rate_limit_scan(spec)
            if config:
                run_live_rate_limit_scan(spec, config)
        elif "2. Inspect" in selection:
            inspect_rate_limit_endpoints(spec.endpoints)


def configure_rate_limit_scan(spec: ParsedSpecification) -> Optional[Dict[str, Any]]:
    """Prompts user in terminal for target URL, burst volume, and auth token."""
    console.print()
    console.print(
        Panel(
            "[bold white]Target Connection & Burst Parameters[/bold white]\n"
            "[dim]A burst sequence of rapid HTTP requests will be executed against each route\n"
            "to check for HTTP 429 Too Many Requests and RFC rate limiting headers.[/dim]",
            title="[bold cyan]RATE LIMIT SCAN CONFIGURATION[/bold cyan]",
            border_style="cyan",
            padding=(0, 2),
        )
    )

    default_base = spec.base_url if spec.base_url and spec.base_url.startswith("http") else "http://localhost:8006"

    try:
        base_url = questionary.text(
            "Enter Target Base URL:",
            default=default_base,
            style=CUSTOM_STYLE,
        ).ask()
        if not base_url:
            return None

        # Burst Volume Selection
        burst_choice = questionary.select(
            "Select Burst Request Intensity:",
            choices=[
                "1. Standard Burst (20 rapid requests per route)",
                "2. Aggressive Burst (30 rapid requests per route)",
                "3. Gentle Probe (10 rapid requests per route)",
            ],
            style=CUSTOM_STYLE,
        ).ask()

        if "10" in burst_choice:
            burst_count = 10
        elif "30" in burst_choice:
            burst_count = 30
        else:
            burst_count = 20

        # Check for saved Fluffwalks session or bearer token
        auth_session_file = PROJECT_ROOT / "fluffwalks-test-case" / "auth_session.json"
        saved_session = {}
        if auth_session_file.exists():
            try:
                with open(auth_session_file) as f:
                    saved_session = json.load(f)
            except Exception:
                pass

        default_tok = saved_session.get("bearer_token") or ""

        token_input = questionary.text(
            "Enter Optional Bearer Token (Press Enter if unauthenticated):",
            default=default_tok,
            style=CUSTOM_STYLE,
        ).ask()

        auth_headers = {}
        if token_input:
            token_input = token_input.strip()
            if not token_input.lower().startswith("bearer "):
                token_input = f"Bearer {token_input}"
            auth_headers["Authorization"] = token_input

        return {
            "base_url": base_url.rstrip("/"),
            "burst_count": burst_count,
            "headers": auth_headers,
        }

    except (KeyboardInterrupt, EOFError):
        return None


def run_live_rate_limit_scan(spec: ParsedSpecification, config: Dict[str, Any]):
    """Executes live burst requests across discovered API routes."""
    base_url = config["base_url"]
    burst_count = config["burst_count"]
    headers = dict(config.get("headers", {}))
    headers["Accept"] = "application/json"

    endpoints_to_test = [ep for ep in spec.endpoints if ep.method.upper() in ("GET", "POST", "PUT")]
    if not endpoints_to_test:
        endpoints_to_test = [
            APIEndpointInfo(path="/api/public/status", method="GET", summary="Public health baseline", parameters=[], is_deprecated=False),
            APIEndpointInfo(path="/api/auth/login", method="POST", summary="Auth login", parameters=[], is_deprecated=False),
            APIEndpointInfo(path="/api/auth/forgot-password", method="POST", summary="Forgot password OTP", parameters=[], is_deprecated=False),
            APIEndpointInfo(path="/api/search", method="GET", summary="Search", parameters=[], is_deprecated=False),
            APIEndpointInfo(path="/api/user/export", method="GET", summary="Data export", parameters=[], is_deprecated=False),
        ]

    total_requests = len(endpoints_to_test) * burst_count

    console.print()
    console.print(
        Panel(
            f"[bold white]Target Host:[/bold white]      [yellow]{base_url}[/yellow]\n"
            f"[bold white]Target Endpoints:[/bold white] [bold cyan]{len(endpoints_to_test)}[/bold cyan] routes\n"
            f"[bold white]Burst Volume:[/bold white]     [bold magenta]{burst_count}[/bold magenta] requests per route\n"
            f"[bold white]Total Injections:[/bold white] [bold green]{total_requests}[/bold green] requests\n"
            f"[dim]Sending rapid request bursts to check for HTTP 429 & throttling...[/dim]",
            title="[bold red]EXECUTING LIVE RATE LIMITING & RESOURCE EXHAUSTION AUDIT[/bold red]",
            border_style="red",
            padding=(1, 2),
        )
    )

    findings: List[RateLimitFinding] = []

    with Progress(
        SpinnerColumn(spinner_name="dots"),
        TextColumn("[bold cyan]{task.description}[/bold cyan]"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("Auditing rate limit boundaries...", total=len(endpoints_to_test))

        with httpx.Client(timeout=10.0, follow_redirects=True, verify=False) as client:
            for ep in endpoints_to_test:
                is_public = "public" in ep.path.lower() or "status" in ep.path.lower() or "health" in ep.path.lower()
                test_path = ep.path
                if "{" in test_path:
                    test_path = test_path.replace("{id}", "101").replace("{userId}", "101").replace("{productId}", "1")

                target_url = f"{base_url}/{test_path.lstrip('/')}"
                progress.update(task, description=f"Bursting [cyan]{ep.method}[/cyan] {test_path} ({burst_count} reqs)")

                status_codes = []
                last_headers = {}

                # Send burst sequence
                for _ in range(burst_count):
                    try:
                        if ep.method.upper() == "GET":
                            resp = client.get(target_url, headers=headers)
                        elif ep.method.upper() == "POST":
                            resp = client.post(target_url, headers=headers, json={"username": "sentinel_probe", "password": "probe_password"})
                        elif ep.method.upper() == "PUT":
                            resp = client.put(target_url, headers=headers, json={})
                        else:
                            resp = client.get(target_url, headers=headers)

                        status_codes.append(resp.status_code)
                        last_headers = dict(resp.headers)
                    except Exception:
                        status_codes.append(0)

                finding = evaluate_rate_limit_results(
                    endpoint=test_path,
                    method=ep.method.upper(),
                    burst_count=burst_count,
                    status_codes=status_codes,
                    headers=last_headers,
                    base_url=base_url,
                    is_public=is_public,
                )
                findings.append(finding)
                progress.advance(task, 1)

    display_rate_limit_results(spec, findings, config)


def display_rate_limit_results(
    spec: ParsedSpecification,
    findings: List[RateLimitFinding],
    config: Dict[str, Any],
):
    """Renders formatted audit table, finding cards, and remediation code."""
    console.print()

    t = Table(title="[bold red]RATE LIMITING & RESOURCE EXHAUSTION AUDIT MATRIX[/bold red]", border_style="red", header_style="bold cyan")
    t.add_column("Endpoint", style="bold white")
    t.add_column("Method", justify="center")
    t.add_column("Burst", justify="center")
    t.add_column("200 OK", justify="center", style="bold green")
    t.add_column("429 Throttled", justify="center")
    t.add_column("Rate Limit Headers", justify="center")
    t.add_column("Verdict", justify="center")
    t.add_column("Severity", justify="center")

    vuln_findings = [f for f in findings if f.is_vulnerable]

    for f in findings:
        method_style = "[bold green]GET[/bold green]" if f.method == "GET" else f"[bold yellow]{f.method}[/bold yellow]"
        throttled_style = f"[bold green]{f.throttled_count}[/bold green]" if f.throttled_count > 0 else f"[bold red]0[/bold red]"
        headers_style = f"[bold green]Yes ({len(f.rate_limit_headers)})[/bold green]" if f.rate_limit_headers else "[dim]None[/dim]"

        if f.is_vulnerable:
            verdict_badge = "[bold red]VULNERABLE[/bold red]"
            sev_badge = f"[bold red]{f.severity}[/bold red]" if f.severity == "HIGH" else f"[bold yellow]{f.severity}[/bold yellow]"
        elif f.has_429:
            verdict_badge = "[bold green]PROTECTED[/bold green]"
            sev_badge = "[dim]CLEAR[/dim]"
        else:
            verdict_badge = "[cyan]PASS (Public)[/cyan]"
            sev_badge = "[dim]NONE[/dim]"

        t.add_row(
            f.endpoint,
            method_style,
            str(f.total_requests),
            str(f.success_count),
            throttled_style,
            headers_style,
            verdict_badge,
            sev_badge,
        )

    console.print(t)

    # Summary Statistics Panel
    high_count = sum(1 for f in vuln_findings if f.severity == "HIGH")
    medium_count = sum(1 for f in vuln_findings if f.severity == "MEDIUM")
    protected_count = sum(1 for f in findings if f.has_429)

    status_label = "[bold red]ACTION REQUIRED[/bold red]" if vuln_findings else "[bold green]COMPLIANT — ALL BOUNDARIES PROTECTED[/bold green]"

    console.print()
    stats_panel = Panel(
        f"[bold white]Routes Audited:[/bold white]        {len(findings)}\n"
        f"[bold white]Throttled Routes:[/bold white]      [bold green]{protected_count}[/bold green] (Enforced 429 status)\n"
        f"[bold white]Unprotected Routes:[/bold white]    [bold red]{len(vuln_findings)}[/bold red]\n"
        f"  • [bold red]HIGH SEVERITY:[/bold red]   {high_count} (Sensitive auth, OTP, or export routes)\n"
        f"  • [bold yellow]MEDIUM SEVERITY:[/bold yellow] {medium_count} (Uncapped standard routes)\n"
        f"[bold white]Status:[/bold white]             {status_label}",
        title="[bold red]AUDIT SUMMARY[/bold red]",
        border_style="red" if vuln_findings else "green",
        padding=(0, 2),
    )
    console.print(stats_panel)

    # Detailed Vulnerability Finding Cards
    if vuln_findings:
        console.print()
        console.print("[bold red]🚨 DETAILED UNRESTRICTED RESOURCE CONSUMPTION FINDINGS[/bold red]")

        for idx, vf in enumerate(vuln_findings, 1):
            sev_color = "red" if vf.severity == "HIGH" else "yellow"
            poc_card = Table(box=None, show_header=False, padding=(0, 1))
            poc_card.add_column("Key", style="bold cyan", width=18)
            poc_card.add_column("Val", style="white")

            poc_card.add_row("Finding #:", f"{idx} of {len(vuln_findings)}")
            poc_card.add_row("Endpoint:", f"[bold white]{vf.method} {vf.endpoint}[/bold white]")
            poc_card.add_row("Severity:", f"[bold {sev_color}]{vf.severity}[/bold {sev_color}]")
            poc_card.add_row("CWE Classification:", vf.cwe)
            poc_card.add_row("Audit Outcome:", f"[bold {sev_color}]{vf.reason}[/bold {sev_color}]")
            poc_card.add_row("Processed Reqs:", f"{vf.success_count}/{vf.total_requests} (0 Throttled)")
            poc_card.add_row("Headers Found:", json.dumps(vf.rate_limit_headers) if vf.rate_limit_headers else "None")
            poc_card.add_row("PoC Burst Script:", f"[bold green]{vf.reproduction_curl}[/bold green]")
            poc_card.add_row("Remediation Fix:", vf.remediation)

            console.print(
                Panel(
                    poc_card,
                    title=f"[bold {sev_color}]VULNERABILITY: Unrestricted Rate Limits on {vf.endpoint}[/bold {sev_color}]",
                    border_style=sev_color,
                    padding=(1, 2),
                )
            )

        # Code Remediation Snippets
        display_rate_limit_code_remediation()

    # Automatically save markdown report in markdown/
    md_path = save_rate_limit_markdown_report(spec, findings, config)
    console.print()
    console.print(f"[bold green]✔ Comprehensive audit report saved to:[/bold green] [underline cyan]{md_path}[/underline cyan]")

    # AI Security Analysis Flow
    prompt_ai_rate_limit_overview(spec, findings, config)

    try:
        input("\nPress Enter to return to Rate Limiting menu...")
    except (KeyboardInterrupt, EOFError):
        pass

    return findings


def display_rate_limit_code_remediation():
    """Renders production code fixes for Express.js and FastAPI."""
    console.print()
    console.print(
        Panel(
            "[bold white]Production Remediation Blueprints[/bold white]\n"
            "[dim]Implement Redis-backed sliding window rate limiters with HTTP 429 and Retry-After headers.[/dim]",
            title="[bold green]🛠️ RECOMMENDED REMEDIATION CODE[/bold green]",
            border_style="green",
            padding=(0, 2),
        )
    )

    express_fix = """// Node.js / Express: Hardened Rate Limiting with express-rate-limit
const rateLimit = require("express-rate-limit");
const RedisStore = require("rate-limit-redis");

// Sensitive Auth Limiter: 5 requests per 60 seconds
const authLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 5,
  standardHeaders: true, // Returns 'RateLimit-*' headers
  legacyHeaders: false,  // Disables 'X-RateLimit-*' headers
  message: {
    error: "Too Many Requests",
    message: "Rate limit exceeded. Try again in 60 seconds."
  },
  statusCode: 429,
});

app.use("/api/auth/login", authLimiter);
app.use("/api/auth/forgot-password", authLimiter);"""

    fastapi_fix = """# Python / FastAPI: Hardened Throttling with slowapi
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from fastapi import Request

limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

@app.post("/api/auth/login")
@limiter.limit("5/minute")
async def login(request: Request):
    return {"status": "authenticated"}"""

    console.print("[bold cyan]Node.js (Express) Fix:[/bold cyan]")
    console.print(Syntax(express_fix, "javascript", theme="monokai", line_numbers=True))
    console.print()
    console.print("[bold cyan]Python (FastAPI) Fix:[/bold cyan]")
    console.print(Syntax(fastapi_fix, "python", theme="monokai", line_numbers=True))


def save_rate_limit_markdown_report(
    spec: ParsedSpecification,
    findings: List[RateLimitFinding],
    config: Dict[str, Any],
) -> Path:
    """Saves structured markdown report in the root markdown/ directory."""
    md_dir = get_markdown_dir()
    slug = "".join([c if c.isalnum() else "_" for c in spec.title.lower()]).strip("_") or "api"
    filename = f"{slug}_rate_limiting_scan_results_{int(time.time())}.md"
    file_path = md_dir / filename

    vuln_findings = [f for f in findings if f.is_vulnerable]

    lines = [
        "# OWASP API4:2023 — Unrestricted Resource Consumption & Rate Limiting Audit Report",
        "",
        f"- **API Target:** {spec.title} (v{spec.version})",
        f"- **Base URL:** `{config.get('base_url')}`",
        f"- **Burst Volume Tested:** {config.get('burst_count')} requests/route",
        f"- **Scan Timestamp:** {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}",
        f"- **Standard:** OWASP API Security Top 10 — API4:2023 Unrestricted Resource Consumption",
        f"- **Routes Tested:** {len(findings)}",
        f"- **Vulnerable Routes Identified:** {len(vuln_findings)}",
        "",
        "## Executive Summary",
        f"{'CRITICAL WARNING: The target API lacks essential request throttling and rate limiting controls. Sensitive endpoints permit unlimited burst requests, rendering the API vulnerable to credential stuffing, SMS/email denial-of-wallet, and DoS.' if vuln_findings else 'CLEARANCE: The target API correctly enforces rate limiting across critical and standard endpoints, returning HTTP 429 Too Many Requests upon exceeding thresholds.'}",
        "",
        "## Findings Matrix",
        "",
        "| Endpoint | Method | Burst Reqs | 200 OK | 429 Throttled | Rate Limit Headers | Verdict | Severity |",
        "| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |",
    ]

    for f in findings:
        verdict = "**VULNERABLE**" if f.is_vulnerable else ("PROTECTED" if f.has_429 else "PASS (Public)")
        headers_str = "Yes" if f.rate_limit_headers else "None"
        lines.append(
            f"| `{f.endpoint}` | {f.method} | {f.total_requests} | {f.success_count} | {f.throttled_count} | {headers_str} | {verdict} | {f.severity} |"
        )

    if vuln_findings:
        lines.extend([
            "",
            "## Detailed Vulnerability Analysis & Proof of Concept",
            "",
        ])
        for idx, vf in enumerate(vuln_findings, 1):
            lines.extend([
                f"### Finding {idx}: Unrestricted Resource Consumption on `{vf.method} {vf.endpoint}`",
                f"- **Severity:** {vf.severity}",
                f"- **CWE Classification:** {vf.cwe}",
                f"- **Total Burst Requests:** {vf.total_requests}",
                f"- **Successful Responses (Unthrottled):** {vf.success_count}",
                f"- **Throttled Responses (429):** {vf.throttled_count}",
                f"- **Security Risk:** {vf.reason}",
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


def prompt_ai_rate_limit_overview(
    spec: ParsedSpecification,
    findings: List[RateLimitFinding],
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
    prompt_text = build_rate_limit_ai_prompt(spec, findings, config)
    usage = estimate_token_usage(prompt_text)

    console.print()
    t = Table(box=None, show_header=False, padding=(0, 2))
    t.add_column("Key", style="bold cyan")
    t.add_column("Val", style="bold white")

    t.add_row("Active AI Model:", f"[bold green]{ai_cfg['model']}[/bold green] [dim]({ai_cfg['provider']})[/dim]")
    t.add_row("Target API Scope:", f"{spec.title} ({len(findings)} routes evaluated)")
    t.add_row("Context Included:", "OpenAPI routes, burst request telemetry, 429 throttling status, headers")
    t.add_row("Context Payload:", f"{usage['char_count']} characters [dim](full test telemetry)[/dim]")
    t.add_row("Estimated Prompt Cost:", f"[bold yellow]~{usage['prompt_tokens']} input tokens[/bold yellow]")
    t.add_row("Estimated Generation:", f"~{usage['estimated_output_tokens']} completion tokens")
    t.add_row("Estimated Total:", f"[bold cyan]~{usage['estimated_total_tokens']} tokens[/bold cyan]")

    console.print(
        Panel(
            t,
            title="[bold red]⚡ SENTINEL AI INTELLIGENCE OVERVIEW[/bold red]",
            border_style="red",
            padding=(1, 2),
        )
    )

    try:
        wants_ai = questionary.confirm(
            f"Generate AI Rate Limiting & Resource Security Blueprint with {ai_cfg['model']}?",
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
            progress.update(task, description=f"[bold green]Generating Resource Security Overview ({count} tokens)...[/bold green]")

        success, response_text = request_ai_overview(prompt_text, progress_callback=update_spinner)

    if not success or not response_text:
        console.print(f"[bold red]AI Generation Failed:[/bold red] {response_text}")
        return

    console.print()
    console.print(
        Panel(
            Markdown(response_text),
            title="[bold red]🤖 AI EXECUTIVE RATE LIMITING ASSESSMENT[/bold red]",
            border_style="red",
            padding=(1, 2),
        )
    )

    # Save AI report
    md_dir = get_markdown_dir()
    slug = "".join([c if c.isalnum() else "_" for c in spec.title.lower()]).strip("_") or "api"
    ai_filename = f"{slug}_rate_limiting_ai_report_{int(time.time())}.md"
    ai_file_path = md_dir / ai_filename

    with open(ai_file_path, "w", encoding="utf-8") as f:
        f.write(f"# Sentinel AI Security Overview: {spec.title}\n\n")
        f.write(f"- Standard: OWASP API4:2023 — Unrestricted Resource Consumption\n")
        f.write(f"- Generated At: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}\n")
        f.write(f"- AI Model: {ai_cfg['model']}\n\n")
        f.write(response_text)

    console.print(f"[bold green]✔ AI Security Report saved to:[/bold green] [underline cyan]{ai_file_path}[/underline cyan]")


def build_rate_limit_ai_prompt(
    spec: ParsedSpecification,
    findings: List[RateLimitFinding],
    config: Dict[str, Any],
) -> str:
    """Builds a targeted prompt for AI analysis of Rate Limiting & Resource Exhaustion."""
    vuln_findings = [f for f in findings if f.is_vulnerable]

    lines = [
        "You are an Elite Infrastructure Security & SRE Architect specializing in API Rate Limiting and DDoS mitigation.",
        "Perform a comprehensive security evaluation based on the live rate limit burst audit telemetry below:",
        "",
        f"- Target API: {spec.title} (v{spec.version})",
        f"- Target Base URL: {config.get('base_url')}",
        f"- Standard: OWASP API4:2023 — Unrestricted Resource Consumption / Missing Rate Limiting",
        f"- Burst Volume: {config.get('burst_count')} requests/endpoint",
        f"- Total Routes Tested: {len(findings)}",
        f"- Unprotected Routes: {len(vuln_findings)}",
        "",
        "### Audit Telemetry Summary:",
    ]

    for f in findings:
        lines.append(
            f"- Route: {f.method} {f.endpoint} | Total: {f.total_requests} | 200 OK: {f.success_count} | "
            f"429 Throttled: {f.throttled_count} | Headers: {list(f.rate_limit_headers.keys())} | "
            f"Vulnerable: {f.is_vulnerable} | Severity: {f.severity} | Reason: {f.reason}"
        )

    lines.extend([
        "",
        "### Report Requirements:",
        "1. Executive Threat Summary: Highlight the financial (Denial of Wallet), operational (DoS / connection pool exhaustion), and credential security risks.",
        "2. Architecture Bottleneck Analysis: Pinpoint why endpoints like search, export, and auth require differentiated throttling tiers.",
        "3. Concrete Production Blueprint: Provide exact implementation code (e.g. Redis sliding window or Nginx/Cloudflare WAF rate limiting rules) to enforce 429 status and Retry-After.",
        "4. Distributed Systems Guardrails: Explain token bucket vs sliding window algorithms and exponential backoff.",
        "",
        "Format your response in clean, professional GitHub Flavored Markdown.",
    ])

    return "\n".join(lines)


def inspect_rate_limit_endpoints(endpoints: List[APIEndpointInfo]):
    """Displays endpoint sensitivity and expected throttling tiers from OpenAPI specification."""
    console.print()
    t = Table(title="[bold red]OPENAPI ROUTE SENSITIVITY & RESOURCE PROFILE[/bold red]", border_style="red", header_style="bold cyan")
    t.add_column("Path", style="bold white")
    t.add_column("Method", justify="center")
    t.add_column("Sensitivity Profile", justify="center")
    t.add_column("Recommended Limit Tier", justify="center")

    from sentinelapi.features.Rate_Limiting.detector import is_sensitive_endpoint

    for ep in endpoints:
        method_style = "[bold green]GET[/bold green]" if ep.method == "GET" else f"[bold yellow]{ep.method}[/bold yellow]"
        if is_sensitive_endpoint(ep.path):
            sens_badge = "[bold red]CRITICAL / SENSITIVE[/bold red]"
            limit_tier = "[bold yellow]Strict: 5-10 req/min[/bold yellow]"
        elif "public" in ep.path.lower() or "health" in ep.path.lower():
            sens_badge = "[cyan]Public Baseline[/cyan]"
            limit_tier = "[dim]Permissive: 100-200 req/min[/dim]"
        else:
            sens_badge = "[yellow]Standard Business Route[/yellow]"
            limit_tier = "[bold cyan]Standard: 60-120 req/min[/bold cyan]"

        t.add_row(ep.path, method_style, sens_badge, limit_tier)

    console.print(t)
    try:
        input("\nPress Enter to return to menu...")
    except (KeyboardInterrupt, EOFError):
        pass
