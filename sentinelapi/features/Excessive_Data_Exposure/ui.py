"""Excessive Data Exposure (OWASP API3:2023) interactive assessment UI & live scanner."""
import time
import re
import json
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
import httpx
from rich.panel import Panel
from rich.table import Table
from rich.syntax import Syntax
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
import questionary
from prompt_toolkit.styles import Style

from sentinelapi.cli.theme import console
from sentinelapi.api_source.spec_parser import ParsedSpecification, APIEndpointInfo
from sentinelapi.features.Excessive_Data_Exposure.detector import analyze_endpoint_exposure

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


def run_excessive_data_flow(spec: ParsedSpecification):
    """Main interactive loop for Excessive Data Exposure assessment."""
    while True:
        console.clear()

        # Banner Header
        console.print(
            Panel(
                f"[bold white]Target API:[/bold white] [bold cyan]{spec.title}[/bold cyan] (v{spec.version})\n"
                f"[bold white]Base URL:[/bold white]   [yellow]{spec.base_url}[/yellow]\n"
                f"[bold white]Auth Scheme:[/bold white] {spec.auth_scheme}\n"
                f"[bold white]Total Routes:[/bold white] {len(spec.endpoints)} discovered\n"
                f"[dim]Tests endpoints for unnecessary exposure of PII, credentials, tokens, and internal properties.[/dim]",
                title="[bold magenta]OWASP API3:2023 — EXCESSIVE DATA EXPOSURE AUDITOR[/bold magenta]",
                border_style="magenta",
                padding=(1, 2),
            )
        )

        choices = [
            "1. Start Live API Scan",
            "2. Inspect Endpoints & Response Schemas",
            "3. Return to Security Test Menu",
        ]

        try:
            selection = questionary.select(
                "Select Excessive Data Exposure Action:",
                choices=choices,
                style=CUSTOM_STYLE,
            ).ask()
        except (KeyboardInterrupt, EOFError):
            return

        if not selection or "3. Return" in selection:
            return

        if "1. Start Live" in selection:
            config = configure_live_exposure_scan(spec)
            if config:
                run_live_exposure_scan(spec, config)
        elif "2. Inspect" in selection:
            inspect_exposure_endpoints(spec.endpoints)


def configure_live_exposure_scan(spec: ParsedSpecification) -> Optional[Dict[str, Any]]:
    """Prompts user in terminal for target URL, Bearer token, and auth headers."""
    console.print()
    console.print(
        Panel(
            "[bold white]Target Connection & Authentication Parameters[/bold white]\n"
            "[dim]A valid Bearer Token is required to inspect protected endpoints for leaked data.\n"
            "Unauthenticated endpoints will also be audited without tokens.[/dim]",
            title="[bold cyan]SCAN CONFIGURATION[/bold cyan]",
            border_style="cyan",
            padding=(0, 2),
        )
    )

    default_base = spec.base_url if spec.base_url and spec.base_url.startswith("http") else "http://localhost:8002"

    try:
        base_url = questionary.text(
            "Enter Target Base URL:",
            default=default_base,
            style=CUSTOM_STYLE,
        ).ask()
        if not base_url:
            return None

        # Choose Auth Mechanism: Bearer Token vs Browser Cookie vs None
        auth_choice = questionary.select(
            "Select Authentication Method for Scanning:",
            choices=[
                "1. Bearer Token (Authorization: Bearer <jwt>)",
                "2. Browser Cookie (Cookie: sb-access-token=...)",
                "3. Custom Header",
                "4. None (Unauthenticated / Public routes)",
            ],
            style=CUSTOM_STYLE,
        ).ask()

        auth_header = "Authorization"
        auth_token = ""

        # Auto-detect saved session if available
        auth_session_file = PROJECT_ROOT / "fluffwalks-test-case" / "auth_session.json"
        saved_session = {}
        if auth_session_file.exists():
            try:
                with open(auth_session_file) as f:
                    saved_session = json.load(f)
            except Exception:
                pass

        if auth_choice and "1. Bearer" in auth_choice:
            auth_header = "Authorization"
            default_tok = saved_session.get("bearer_token") or "test_token_101"
            token_val = questionary.text(
                "Enter Bearer Token / JWT (or paste token):",
                default=default_tok,
                style=CUSTOM_STYLE,
            ).ask()
            if token_val:
                token_val = token_val.strip()
                if not token_val.lower().startswith("bearer ") and not token_val.lower().startswith("basic "):
                    auth_token = f"Bearer {token_val}"
                else:
                    auth_token = token_val

        elif auth_choice and "2. Browser Cookie" in auth_choice:
            auth_header = "Cookie"
            default_cookie = saved_session.get("cookie_string", "")
            cookie_val = questionary.text(
                "Paste Cookie String (e.g. from DevTools / Application > Cookies):",
                default=default_cookie,
                style=CUSTOM_STYLE,
            ).ask()
            auth_token = (cookie_val or "").strip()

        elif auth_choice and "3. Custom" in auth_choice:
            auth_header = questionary.text(
                "Custom Header Name:",
                default="X-API-Key",
                style=CUSTOM_STYLE,
            ).ask() or "X-API-Key"
            auth_token = (questionary.text(
                f"Enter value for {auth_header}:",
                style=CUSTOM_STYLE,
            ).ask() or "").strip()

        # Parameter samples dictionary
        params = {}
        for ep in spec.endpoints:
            for p in ep.parameters:
                pname = p.get("name")
                if pname and pname not in params:
                    example = p.get("schema", {}).get("example") or p.get("example")
                    val = str(example) if example is not None else ("101" if "user" in pname.lower() or "id" in pname.lower() else "501")
                    params[pname] = val

        return {
            "base_url": base_url.rstrip("/"),
            "bearer_token": auth_token,
            "auth_header": auth_header,
            "params": params,
        }
    except (KeyboardInterrupt, EOFError):
        return None


def run_live_exposure_scan(spec: ParsedSpecification, config: Dict[str, Any]):
    """Executes live HTTP requests to detect excessive data exposure on API endpoints."""
    console.clear()
    console.print(
        Panel(
            f"[bold white]Target Base URL:[/bold white] [bold cyan]{config['base_url']}[/bold cyan]\n"
            f"[bold white]Auth Token:[/bold white]      [yellow]{config['bearer_token'][:25]}...[/yellow]\n"
            f"[bold white]Testing Strategy:[/bold white] Probing {len(spec.endpoints)} routes & inspecting response JSON bodies for sensitive leaks.",
            title="[bold magenta]EXECUTING LIVE EXCESSIVE DATA EXPOSURE SCAN[/bold magenta]",
            border_style="magenta",
            padding=(1, 2),
        )
    )

    results: List[Dict[str, Any]] = []

    with Progress(
        SpinnerColumn(spinner_name="dots"),
        TextColumn("[bold cyan]{task.description}[/bold cyan]"),
        BarColumn(bar_width=40, style="magenta", complete_style="bold green"),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("Auditing endpoints for data leakage...", total=len(spec.endpoints))

        with httpx.Client(timeout=10.0, follow_redirects=True) as client:
            for ep in spec.endpoints:
                progress.update(task, description=f"Inspecting [bold]{ep.method} {ep.path}[/bold]...")

                # Resolve URL with sample parameter values
                path_resolved = ep.path
                for pname, pval in config.get("params", {}).items():
                    path_resolved = path_resolved.replace(f"{{{pname}}}", str(pval))

                target_url = f"{config['base_url']}{path_resolved}"

                headers = {"Content-Type": "application/json"}
                if config.get("bearer_token"):
                    headers[config["auth_header"]] = config["bearer_token"]

                status_code = 0
                resp_json = None
                conn_err = None
                try:
                    resp = client.request(ep.method, target_url, headers=headers)
                    status_code = resp.status_code
                    raw_text = resp.text
                    try:
                        resp_json = resp.json()
                    except Exception:
                        resp_json = None
                except Exception as e:
                    status_code = 0
                    conn_err = str(e)
                    raw_text = f"Connection error: {conn_err}"

                # Run detector on response data only if we got a real response
                if resp_json is not None:
                    analysis = analyze_endpoint_exposure(resp_json)
                else:
                    analysis = {
                        "is_vulnerable": False,
                        "severity": "NONE",
                        "findings_count": 0,
                        "findings": [],
                        "declared_keys": [],
                    }

                results.append({
                    "endpoint": ep,
                    "target_url": target_url,
                    "status_code": status_code,
                    "response_json": resp_json,
                    "raw_text": raw_text,
                    "analysis": analysis,
                    "is_vulnerable": analysis["is_vulnerable"] and status_code > 0,
                    "probe_error": conn_err,
                })

                time.sleep(0.15)
                progress.advance(task)

    # Render results table
    return render_exposure_results_and_remediation(spec, results, config)


def render_exposure_results_and_remediation(
    spec: ParsedSpecification,
    results: List[Dict[str, Any]],
    config: Dict[str, Any],
):
    """Renders scan results, detailed findings, code PoCs, and prompts AI overview."""
    console.clear()

    # Results Table
    t = Table(title="[bold magenta]EXCESSIVE DATA EXPOSURE AUDIT MATRIX[/bold magenta]", border_style="magenta", header_style="bold cyan")
    t.add_column("Method", style="bold green", width=8)
    t.add_column("Endpoint Path", style="bold white", width=30)
    t.add_column("Status", width=12)
    t.add_column("Leaks Found", justify="center", width=14)
    t.add_column("Severity", width=12)
    t.add_column("Verdict", width=22)

    vuln_count = 0
    secured_count = 0
    error_count = 0

    for r in results:
        ep = r["endpoint"]
        ana = r["analysis"]
        is_vuln = r["is_vulnerable"]
        probe_err = r.get("probe_error")

        if probe_err or r["status_code"] == 0:
            error_count += 1
            verdict = "[bold red]ERROR (UNREACHABLE)[/bold red]"
            t.add_row(
                ep.method,
                ep.path,
                "[bold red]HTTP 0 (FAIL)[/bold red]",
                "[dim]-[/dim]",
                "[red]PROBE_ERROR[/red]",
                verdict,
            )
        elif is_vuln:
            vuln_count += 1
            sev = ana["severity"]
            sev_style = "bold red" if sev == "CRITICAL" else "bold yellow"
            verdict = f"[bold red]FAIL (LEAK)[/bold red]"
            t.add_row(
                ep.method,
                ep.path,
                f"HTTP {r['status_code']}",
                f"[{sev_style}]{ana['findings_count']} keys[/{sev_style}]",
                f"[{sev_style}]{sev}[/{sev_style}]",
                verdict,
            )
        else:
            secured_count += 1
            verdict = "[bold green]PASS (CLEAN)[/bold green]"
            t.add_row(
                ep.method,
                ep.path,
                f"HTTP {r['status_code']}",
                "[dim]0 keys[/dim]",
                "[green]NONE[/green]",
                verdict,
            )

    console.print(t)
    console.print()

    # Executive Summary Card (Fail-Closed)
    if error_count == len(results):
        overall_verdict = "[bold red]ERROR: TARGET UNREACHABLE (0 PROBES SUCCEEDED)[/bold red]"
        card_border = "red"
    elif vuln_count > 0:
        overall_verdict = "[bold red]CRITICAL RISK: SENSITIVE DATA EXPOSURE DETECTED (OWASP API3:2023)[/bold red]"
        card_border = "red"
    elif error_count > 0:
        overall_verdict = f"[bold yellow]INCOMPLETE: {error_count} PROBES FAILED / UNREACHABLE[/bold yellow]"
        card_border = "yellow"
    else:
        overall_verdict = "[bold green]COMPLIANT: ZERO SENSITIVE DATA EXPOSURE (PASSED)[/bold green]"
        card_border = "green"

    summary_text = (
        f" [bold white]Total Candidate Endpoints:[/bold white]   {len(results)}\n"
        f" [bold red]Vulnerabilities Identified:[/bold red]      {vuln_count} Data Exposure Flaws\n"
        f" [bold green]Clean Responses Verified:[/bold green]        {secured_count} Endpoints Inspected\n"
        f" [bold yellow]Probe Connection Failures:[/bold yellow]       {error_count} Unreachable / Failed\n"
        f" [bold white]Assessment Posture:[/bold white]             {overall_verdict}"
    )

    console.print(
        Panel(
            summary_text,
            title="[bold cyan]EXECUTIVE AUDIT SUMMARY[/bold cyan]",
            border_style=card_border,
            padding=(1, 2),
        )
    )

    # Detailed Findings
    if vuln_count > 0:
        console.print("\n[bold red]DETAILED SENSITIVE DATA EXPOSURE FINDINGS & REMEDIATION[/bold red]")
        for idx, r in enumerate(results, 1):
            if not r["is_vulnerable"]:
                continue

            ep = r["endpoint"]
            ana = r["analysis"]

            # Findings Table
            ft = Table(box=None, header_style="bold yellow", padding=(0, 2))
            ft.add_column("Exposed Property", style="bold red")
            ft.add_column("Category", style="cyan")
            ft.add_column("Severity", style="bold yellow")
            ft.add_column("Sample Leaked Value", style="white")

            for f in ana["findings"][:8]:  # show top 8
                ft.add_row(f["field_name"], f["category"], f"[{score_style}]{f['severity']}[/{score_style}]", f["preview"])

            # cURL PoC
            poc_curl = (
                f"curl -s -X {ep.method} \"{r['target_url']}\" \\\n"
                f"  -H \"{config.get('auth_header', 'Authorization')}: {config.get('bearer_token', 'Bearer <token>')}\" \\\n"
                f"  -H \"Content-Type: application/json\" | jq ."
            )

            poc_syntax = Syntax(poc_curl, "bash", theme="monokai", line_numbers=False)

            # Remediation Code (DTO Pattern)
            remed_code = (
                "// Secure Response DTO (Data Transfer Object) Projection\n"
                "// Never return full raw database model entities to clients\n"
                "function toPublicDTO(entity) {\n"
                "  return {\n"
                "    id: entity.id,\n"
                "    name: entity.name,\n"
                "    username: entity.username\n"
                "    // Exclude password_hash, ssn, internal_roles, secrets\n"
                "  };\n"
                "}\n\n"
                f"app.{ep.method.lower()}('{ep.path}', (req, res) => {{\n"
                "  const data = await db.find(req.params);\n"
                "  return res.json(toPublicDTO(data));\n"
                "});"
            )
            remed_syntax = Syntax(remed_code, "javascript", theme="monokai", line_numbers=False)

            panel_content = Panel(
                ft,
                title=f"[bold red]FINDING #{idx}: {ep.method} {ep.path} ({ana['severity']})[/bold red]",
                border_style="red",
                padding=(1, 2),
            )
            console.print(panel_content)
            console.print(Panel(poc_syntax, title="[bold yellow]Proof of Concept (PoC cURL)[/bold yellow]", border_style="yellow"))
            console.print(Panel(remed_syntax, title="[bold green]Recommended Fix (DTO Projection)[/bold green]", border_style="green"))
            console.print()

    # Automatically save scan results to markdown/ folder
    try:
        scan_md_file = save_exposure_scan_results_markdown(spec, results, config)
        console.print(f"[bold green]✓ Scan findings saved to markdown folder: [white]{scan_md_file}[/white][/bold green]\n")
    except Exception as e:
        console.print(f"[dim yellow]Warning: Could not save scan findings to markdown: {e}[/dim yellow]\n")

    # Step: Dynamic AI Security Overview & Remediation Synthesis
    present_exposure_ai_overview_step(spec, results, config)

    try:
        questionary.press_any_key_to_continue("Press any key to return to Excessive Data menu...").ask()
    except (KeyboardInterrupt, EOFError):
        pass

    return results


def save_exposure_scan_results_markdown(
    spec: ParsedSpecification,
    results: List[Dict[str, Any]],
    config: Dict[str, Any],
) -> Path:
    """Saves Excessive Data Exposure findings as a structured Markdown file in markdown/."""
    md_dir = get_markdown_dir()
    slug = re.sub(r"[^a-zA-Z0-9]+", "_", spec.title).strip("_").lower() or "api"
    timestamp = int(time.time())
    scan_file = md_dir / f"{slug}_excessive_data_scan_results_{timestamp}.md"

    vuln_results = [r for r in results if r.get("is_vulnerable")]
    passed_results = [r for r in results if not r.get("is_vulnerable")]

    lines = [
        f"# SentinelAPI Security Assessment: {spec.title}",
        "",
        f"- **Vulnerability Standard:** OWASP API3:2023 — Excessive Data Exposure",
        f"- **Date:** {time.ctime()}",
        f"- **Target Base URL:** `{config.get('base_url', spec.base_url)}`",
        f"- **Total Endpoints Tested:** {len(results)}",
        f"- **Vulnerable Routes Identified:** {len(vuln_results)}",
        f"- **Protected / Sanitized Routes:** {len(passed_results)}",
        f"- **Overall Risk:** {'CRITICAL RISK (OWASP API3:2023)' if vuln_results else 'LOW / ZERO RISK (PASSED)'}",
        "",
        "## Executive Summary",
        "",
        f"{'CRITICAL: Excessive Data Exposure detected. API endpoints return full unmasked database records containing credentials, PII, financial keys, or internal authorization privileges.' if vuln_results else 'CLEARANCE: No excessive data exposure detected. API endpoints properly sanitize output and enforce strict response DTOs.'}",
        "",
        "## Scan Results Matrix",
        "",
        "| Method | Endpoint Path | HTTP Status | Leaks Found | Highest Severity | Verdict |",
        "|---|---|---|---|---|---|",
    ]

    for r in results:
        ep = r["endpoint"]
        ana = r["analysis"]
        verdict = "**VULNERABLE (DATA LEAK)**" if r.get("is_vulnerable") else "PASSED (SECURE)"
        lines.append(f"| `{ep.method}` | `{ep.path}` | HTTP {r['status_code']} | {ana['findings_count']} keys | {ana['severity']} | {verdict} |")

    if vuln_results:
        lines.extend([
            "",
            "## Detailed Vulnerability Findings",
            "",
        ])
        for idx, res in enumerate(vuln_results, 1):
            ep = res["endpoint"]
            ana = res["analysis"]
            lines.extend([
                f"### Finding #{idx}: {ep.method} {ep.path}",
                "",
                f"- **Vulnerability Type:** OWASP API3:2023 - Excessive Data Exposure",
                f"- **Severity:** {ana['severity']}",
                f"- **Target URL:** `{res['target_url']}`",
                f"- **Total Exposed Keys:** {ana['findings_count']}",
                "",
                "| Exposed Property | Category | Severity | Sample Leaked Value |",
                "|---|---|---|---|",
            ])
            for f in ana["findings"]:
                lines.append(f"| `{f['field_name']}` | {f['category']} | {f['severity']} | `{f['preview']}` |")

            lines.extend([
                "",
                "#### Proof of Concept (PoC cURL)",
                "```bash",
                f"curl -s -X {ep.method} \"{res['target_url']}\" \\",
                f"  -H \"{config.get('auth_header', 'Authorization')}: {config.get('bearer_token', 'Bearer <token>')}\" \\",
                f"  -H \"Content-Type: application/json\" | jq .",
                "```",
                "",
                "#### Recommended Remediation (Response DTO)",
                "```javascript",
                "// Enforce strict response DTO filtering before returning records to clients",
                "function toPublicDTO(data) {",
                "  return {",
                "    id: data.id,",
                "    name: data.name,",
                "    username: data.username",
                "  };",
                "}",
                "```",
                "",
            ])

    with open(scan_file, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    return scan_file


def present_exposure_ai_overview_step(
    spec: ParsedSpecification,
    results: List[Dict[str, Any]],
    config: Dict[str, Any],
):
    """Presents dynamic token cost estimation and prompts user to generate AI Security Overview."""
    from rich.markdown import Markdown
    from sentinelapi.modals.ai_engine import (
        get_active_ai_config,
        estimate_token_usage,
        request_ai_overview,
    )

    ai_cfg = get_active_ai_config()

    # Build prompt tailored to Excessive Data Exposure
    prompt_text = build_exposure_ai_prompt(spec, results, config)
    usage = estimate_token_usage(prompt_text)

    console.print()
    t = Table(box=None, show_header=False, padding=(0, 2))
    t.add_column("Key", style="bold cyan")
    t.add_column("Val", style="bold white")

    t.add_row("Active AI Model:", f"[bold green]{ai_cfg['model']}[/bold green] [dim]({ai_cfg['provider']})[/dim]")
    t.add_row("Target API Scope:", f"{spec.title} ({len(results)} routes evaluated)")
    t.add_row("Context Included:", f"OpenAPI schema, detected leaked fields, response payloads, verdicts")
    t.add_row("Context Payload:", f"{usage['char_count']} characters [dim](full test telemetry)[/dim]")
    t.add_row("Estimated Prompt Cost:", f"[bold yellow]~{usage['prompt_tokens']} input tokens[/bold yellow]")
    t.add_row("Estimated Generation:", f"~{usage['estimated_output_tokens']} completion tokens")
    t.add_row("Estimated Total:", f"[bold cyan]~{usage['estimated_total_tokens']} tokens[/bold cyan]")

    console.print(
        Panel(
            t,
            title="[bold magenta]⚡ SENTINEL AI INTELLIGENCE OVERVIEW[/bold magenta]",
            border_style="magenta",
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

    # Call AI with live streaming progress spinner
    with Progress(
        SpinnerColumn(spinner_name="dots"),
        TextColumn("[bold cyan]{task.description}[/bold cyan]"),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        task = progress.add_task(f"Connecting to {ai_cfg['model']}...", total=None)

        def on_stream(toks: int):
            progress.update(task, description=f"Streaming intelligence via {ai_cfg['model']} ({toks} tokens received)...")

        success, ai_report = request_ai_overview(prompt_text, progress_callback=on_stream)

    if not success:
        console.print(
            Panel(
                f"[bold red]AI Generation Failed[/bold red]\n\n{ai_report}",
                title="[bold red]AI Engine Error[/bold red]",
                border_style="red",
                padding=(1, 2),
            )
        )
        return

    # Render AI Markdown cleanly with Rich
    console.clear()
    console.print(
        Panel(
            f"[bold white]Target API:[/bold white] [bold cyan]{spec.title}[/bold cyan] | "
            f"[bold white]Model:[/bold white] [bold green]{ai_cfg['model']}[/bold green] | "
            f"[bold white]Tokens Analyzed:[/bold white] [yellow]~{usage['prompt_tokens']}[/yellow]",
            title="[bold magenta]⚡ AI EXECUTIVE SECURITY BLUEPRINT & REMEDIATION (OWASP API3)[/bold magenta]",
            border_style="magenta",
            padding=(1, 2),
        )
    )
    console.print()

    md = Markdown(ai_report, code_theme="monokai")
    console.print(md)
    console.print()

    # Automatically save AI report in markdown/ folder
    md_dir = get_markdown_dir()
    slug = re.sub(r"[^a-zA-Z0-9]+", "_", spec.title).strip("_").lower() or "api"
    timestamp = int(time.time())
    ai_md_filename = md_dir / f"{slug}_excessive_data_ai_report_{timestamp}.md"

    try:
        with open(ai_md_filename, "w", encoding="utf-8") as f:
            f.write(f"# SentinelAPI Security Overview: {spec.title}\n\n")
            f.write(f"- Standard: OWASP API3:2023 — Excessive Data Exposure\n")
            f.write(f"- Date: {time.ctime()}\n")
            f.write(f"- Model: {ai_cfg['model']}\n")
            f.write(f"- Base URL: {config.get('base_url', spec.base_url)}\n\n")
            f.write(ai_report)
        console.print(f"[bold green]✓ AI Report automatically saved to markdown folder: [white]{ai_md_filename}[/white][/bold green]\n")
    except Exception as e:
        console.print(f"[dim yellow]Warning: Could not auto-save AI report to markdown: {e}[/dim yellow]\n")

    # Post-Report Options
    report_choices = [
        f"1. Save / Re-verify AI Report in markdown folder ({ai_md_filename.name})",
        "2. Continue to Excessive Data Menu",
    ]

    try:
        action = questionary.select("AI Report Options:", choices=report_choices, style=CUSTOM_STYLE).ask()
        if action and "1. Save" in action:
            with open(ai_md_filename, "w", encoding="utf-8") as f:
                f.write(f"# SentinelAPI Security Overview: {spec.title}\n\n")
                f.write(f"- Standard: OWASP API3:2023 — Excessive Data Exposure\n")
                f.write(f"- Date: {time.ctime()}\n")
                f.write(f"- Model: {ai_cfg['model']}\n")
                f.write(f"- Base URL: {config.get('base_url', spec.base_url)}\n\n")
                f.write(ai_report)

            console.print(f"\n[bold green]✓ Report saved in markdown folder: [white]{ai_md_filename}[/white][/bold green]\n")
            time.sleep(1.5)
    except (KeyboardInterrupt, EOFError):
        pass


def build_exposure_ai_prompt(
    spec: ParsedSpecification,
    results: List[Dict[str, Any]],
    config: Dict[str, Any],
) -> str:
    """Builds a targeted prompt for AI analysis of Excessive Data Exposure."""
    vuln_results = [r for r in results if r.get("is_vulnerable")]

    lines = [
        f"# TARGET API SECURITY TELEMETRY: {spec.title}",
        f"- Vulnerability Standard: OWASP API3:2023 — Excessive Data Exposure / Broken Object Property Level Authorization",
        f"- Target Base URL: {config.get('base_url', spec.base_url)}",
        f"- Total Routes Evaluated: {len(results)}",
        f"- Routes Leaking Sensitive Properties: {len(vuln_results)}",
        "",
        "## EXPOSED ROUTES & SENSITIVE KEYS:",
    ]

    for idx, r in enumerate(results, 1):
        ep = r["endpoint"]
        ana = r["analysis"]
        if r.get("is_vulnerable"):
            leaked_names = [f"{f['field_name']} ({f['category']})" for f in ana["findings"][:6]]
            lines.append(f"{idx}. {ep.method} {ep.path} -> STATUS: HTTP {r['status_code']} | SEVERITY: {ana['severity']}")
            lines.append(f"   Leaked Fields: {', '.join(leaked_names)}")
        else:
            lines.append(f"{idx}. {ep.method} {ep.path} -> STATUS: HTTP {r['status_code']} | VERDICT: CLEAN")

    lines.extend([
        "",
        "## INSTRUCTIONS FOR SECURITY INTELLIGENCE REPORT:",
        "Provide a concise, authoritative security report in structured GitHub Markdown with these sections:",
        "### 1. Executive Threat Posture (Data Exposure)",
        "Summarize the extent of sensitive data leakage identified.",
        "### 2. Leaked Property Impact Analysis",
        "Analyze the discovered fields (e.g. password hashes, PII, SSN, internal roles, vendor tokens) and explain real-world attacker threat vectors.",
        "### 3. Production-Ready Code Remediation (DTO / Data Projection)",
        "Provide concrete, clean code snippets (TypeScript/JavaScript or Python) implementing strict response DTO filtering.",
        "### 4. Zero-Trust Architecture Hardening",
        "2-3 strategic recommendations (e.g., GraphQL field-level resolvers, API gateway transformation, schema contract testing).",
    ])

    return "\n".join(lines)


def inspect_exposure_endpoints(endpoints: List[APIEndpointInfo]):
    """Displays detailed endpoint parameters and security schemas."""
    console.clear()
    console.print(
        Panel(
            "[bold white]Target Endpoints for Excessive Data Exposure Inspection[/bold white]\n"
            "[dim]Endpoints returning object entities should be audited for unadvertised or sensitive fields.[/dim]",
            title="[bold cyan]EXPOSURE ENDPOINT INSPECTOR[/bold cyan]",
            border_style="cyan",
            padding=(1, 2),
        )
    )

    for idx, ep in enumerate(endpoints, 1):
        t = Table(box=None, show_header=False, padding=(0, 2))
        t.add_column("Key", style="bold cyan")
        t.add_column("Val", style="bold white")

        t.add_row("Route:", f"[bold green]{ep.method}[/bold green] [bold white]{ep.path}[/bold white]")
        t.add_row("Summary:", ep.summary or "No summary provided in specification")
        t.add_row("Auth Required:", "[green]Yes (Bearer)[/green]" if ep.auth_required else "[yellow]No (Public)[/yellow]")

        console.print(Panel(t, title=f"[bold white]Endpoint #{idx}[/bold white]", border_style="cyan"))

    try:
        questionary.press_any_key_to_continue("Press any key to return...").ask()
    except (KeyboardInterrupt, EOFError):
        pass
