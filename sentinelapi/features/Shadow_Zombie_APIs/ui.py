"""Shadow & Zombie APIs (OWASP API9:2023 - Improper Inventory Management) interactive UI & live scanner."""

import os
import json
import time
from pathlib import Path
from typing import Dict, Any, List, Optional, Set
import httpx
from rich.table import Table
from rich.panel import Panel
from rich.syntax import Syntax
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
import questionary
from prompt_toolkit.styles import Style

from sentinelapi.cli.theme import console
from sentinelapi.api_source.spec_parser import ParsedSpecification
from sentinelapi.features.Shadow_Zombie_APIs.detector import (
    generate_shadow_zombie_vectors,
    evaluate_shadow_zombie_response,
    ShadowZombieFinding,
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


def run_shadow_zombie_flow(spec: ParsedSpecification):
    """Main interactive loop for Shadow & Zombie API Discovery."""
    while True:
        console.clear()

        console.print(
            Panel(
                f"[bold white]Target API:[/bold white]   [bold cyan]{spec.title}[/bold cyan] (v{spec.version})\n"
                f"[bold white]Base URL:[/bold white]     [yellow]{spec.base_url}[/yellow]\n"
                f"[bold white]Spec Inventory:[/bold white] {len(spec.endpoints)} declared routes\n"
                f"[dim]Discovers undocumented shadow endpoints, deprecated active zombie versions, and debug leaks.[/dim]",
                title="[bold yellow]OWASP API9:2023 — SHADOW & ZOMBIE API DISCOVERY[/bold yellow]",
                border_style="yellow",
                padding=(1, 2),
            )
        )

        menu_choices = [
            "1. Run Complete Shadow & Zombie Inventory Audit",
            "2. Inspect Declared vs Discovered Inventory Methodology",
            "3. Configure Target Base URL",
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
            config = {"base_url": spec.base_url}
            run_live_inventory_scan(spec, config)
        elif "2. Inspect Declared" in choice:
            display_inventory_methodology(spec)
        elif "3. Configure Target" in choice:
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


def display_inventory_methodology(spec: ParsedSpecification):
    """Explains how SentinelAPI detects Shadow and Zombie routes."""
    console.clear()
    t = Table(title="[bold yellow]API Inventory Discovery Matrix (OWASP API9:2023)[/bold yellow]", box=None, padding=(0, 2))
    t.add_column("Asset Classification", style="bold cyan")
    t.add_column("Discovery Heuristic", style="white")
    t.add_column("Security Risk", style="dim")

    t.add_row(
        "Zombie API (Deprecated)",
        "Version downgrades (/v2 -> /v1, /v0, /legacy) on declared routes",
        "Legacy code lacks current auth, 2FA, rate limiting, and input sanitization.",
    )
    t.add_row(
        "Shadow API (Undocumented)",
        "Probes /beta, /export, and resource-specific bulk dumps",
        "Endpoints operating outside API gateways, security monitoring, and WAF rules.",
    )
    t.add_row(
        "Exposed Diagnostics",
        "Probes /debug/*, /actuator/*, /metrics",
        "Leaks runtime environment, database connection strings, and secret keys.",
    )
    t.add_row(
        "Sensitive Backup Files",
        "Probes *.old, *.bak, /.env, /.git/HEAD",
        "Exposes source code, database dumps, and credentials in the web root.",
    )

    console.print(Panel(t, title="[bold white]INVENTORY METHODOLOGY[/bold white]", border_style="yellow", padding=(1, 2)))
    try:
        input("\nPress Enter to return...")
    except (KeyboardInterrupt, EOFError):
        pass


def run_live_inventory_scan(spec: ParsedSpecification, config: Dict[str, Any]):
    """Executes live network probes against candidate Shadow and Zombie routes."""
    console.print()
    console.print("[bold yellow]Deriving Shadow, Zombie, and Diagnostic candidates from specification...[/bold yellow]")

    vectors = generate_shadow_zombie_vectors(spec)
    declared_paths: Set[str] = {ep.path.rstrip("/") for ep in spec.endpoints}
    base_url = config.get("base_url", spec.base_url).rstrip("/")

    console.print(f"[dim]Generated [bold white]{len(vectors)}[/bold white] candidate probes against target server.[/dim]")

    findings: List[ShadowZombieFinding] = []

    with Progress(
        SpinnerColumn(spinner_name="dots", style="bold yellow"),
        TextColumn("[bold white]{task.description}[/bold white]"),
        BarColumn(bar_width=30, style="yellow", complete_style="bold green"),
        TextColumn("[bold cyan]{task.percentage:>3.0f}%[/bold cyan]"),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("Crawling live asset inventory...", total=len(vectors))

        with httpx.Client(timeout=6.0, verify=False, follow_redirects=True) as client:
            for vec in vectors:
                target_url = f"{base_url}/{vec.path.lstrip('/')}"
                progress.update(task, description=f"Probing candidate [bold cyan]{vec.method} {vec.path}[/bold cyan]")

                try:
                    res = client.request(vec.method, target_url)
                    finding = evaluate_shadow_zombie_response(
                        vector=vec,
                        status_code=res.status_code,
                        response_body=res.text[:1000],
                        headers=dict(res.headers),
                        base_url=base_url,
                        declared_paths=declared_paths,
                    )
                    findings.append(finding)
                except Exception as e:
                    findings.append(
                        ShadowZombieFinding(
                            path=vec.path,
                            method=vec.method,
                            test_id=vec.id,
                            test_name=vec.name,
                            category=vec.category,
                            status_code=0,
                            is_vulnerable=False,
                            severity="NONE",
                            reason=f"Connection Error: {str(e)}",
                            cwe=vec.cwe,
                            reproduction_curl=f"curl -X {vec.method} \"{target_url}\"",
                            response_snippet="Connection refused / Server unreachable",
                            remediation="Verify target host connectivity.",
                        )
                    )

                progress.advance(task)

    display_shadow_zombie_results(spec, findings, config)
    return findings


def display_shadow_zombie_results(
    spec: ParsedSpecification,
    findings: List[ShadowZombieFinding],
    config: Dict[str, Any],
):
    """Renders formatted inventory audit table, finding cards, and AI summary."""
    console.clear()

    vuln_findings = [f for f in findings if f.is_vulnerable]
    crit_count = sum(1 for f in vuln_findings if f.severity == "CRITICAL")
    high_count = sum(1 for f in vuln_findings if f.severity == "HIGH")
    med_count = sum(1 for f in vuln_findings if f.severity == "MEDIUM")
    conn_err_count = sum(1 for f in findings if f.status_code == 0)

    console.print()

    if conn_err_count == len(findings):
        status_label = "[bold red]FAILED — TARGET SERVER UNREACHABLE (CONNECTION REFUSED / SERVER OFFLINE)[/bold red]"
        border_col = "red"
    elif vuln_findings:
        status_label = "[bold red]ACTION REQUIRED — SHADOW / ZOMBIE ASSETS DETECTED IN PRODUCTION[/bold red]"
        border_col = "red"
    elif conn_err_count > 0:
        status_label = f"[bold yellow]INCOMPLETE — {conn_err_count} PROBES FAILED / UNREACHABLE[/bold yellow]"
        border_col = "yellow"
    else:
        status_label = "[bold green]COMPLIANT — CLEAN ASSET INVENTORY (ZERO SHADOW/ZOMBIE ROUTES)[/bold green]"
        border_col = "green"

    stats_panel = Panel(
        f"[bold white]Target API:[/bold white]          [bold cyan]{spec.title}[/bold cyan] ({config.get('base_url')})\n"
        f"[bold white]Standard:[/bold white]            OWASP API Security Top 10 — API9:2023 Improper Inventory Management\n"
        f"[bold white]Declared Endpoints:[/bold white]  {len(spec.endpoints)} documented in OpenAPI specification\n"
        f"[bold white]Probes Evaluated:[/bold white]    {len(findings)} candidate routes scanned\n"
        f"[bold white]Undocumented Assets:[/bold white] [bold red]{len(vuln_findings)} detected live[/bold red] "
        f"([bold magenta]{crit_count} Critical[/bold magenta], [bold red]{high_count} High[/bold red], [bold yellow]{med_count} Medium[/bold yellow])\n"
        f"[bold white]Probe Failures:[/bold white]      {conn_err_count} Unreachable\n"
        f"[bold white]Inventory Status:[/bold white]    {status_label}",
        title="[bold yellow]INVENTORY AUDIT SUMMARY — OWASP API9:2023[/bold yellow]",
        border_style=border_col,
        padding=(0, 2),
    )
    console.print(stats_panel)

    # Findings Table
    console.print()
    t = Table(title="[bold white]SHADOW & ZOMBIE API INVENTORY MATRIX[/bold white]", box=None, padding=(0, 1))
    t.add_column("Candidate Route", style="bold cyan", no_wrap=True)
    t.add_column("Asset Category", style="magenta")
    t.add_column("Audit Check", style="white")
    t.add_column("Status Code", justify="center")
    t.add_column("Verdict", justify="center")
    t.add_column("Severity", justify="center")

    for f in findings:
        sev_color = "magenta" if f.severity == "CRITICAL" else ("red" if f.severity == "HIGH" else "yellow")

        if f.is_vulnerable:
            status_style = f"[bold red]{f.status_code}[/bold red]"
            verdict_badge = f"[bold red]{f.category.upper()} DETECTED[/bold red]"
            sev_badge = f"[bold {sev_color}]{f.severity}[/]"
        elif f.status_code == 410:
            status_style = f"[bold green]{f.status_code}[/bold green]"
            verdict_badge = "[bold green]RETIRED (410 GONE)[/bold green]"
            sev_badge = "[dim]CLEARED[/dim]"
        elif f.status_code == 404:
            status_style = f"[dim]{f.status_code}[/dim]"
            verdict_badge = "[bold green]OFFLINE (404)[/bold green]"
            sev_badge = "[dim]NONE[/dim]"
        elif f.status_code == 0:
            status_style = "[bold red]ERR[/bold red]"
            verdict_badge = "[bold red]CONN FAILED[/bold red]"
            sev_badge = "[red]OFFLINE[/red]"
        else:
            status_style = f"[dim]{f.status_code}[/dim]"
            verdict_badge = "[cyan]PASS (Protected)[/cyan]"
            sev_badge = "[dim]NONE[/dim]"

        t.add_row(
            f"{f.method} {f.path}",
            f.category,
            f.test_name,
            status_style,
            verdict_badge,
            sev_badge,
        )

    console.print(t)

    # Detailed Vulnerability Finding Cards
    if vuln_findings:
        console.print()
        console.print("[bold red]🚨 DETAILED SHADOW & ZOMBIE API FINDINGS[/bold red]")

        for idx, vf in enumerate(vuln_findings, 1):
            sev_color = "magenta" if vf.severity == "CRITICAL" else ("red" if vf.severity == "HIGH" else "yellow")
            poc_card = Table(box=None, show_header=False, padding=(0, 1))
            poc_card.add_column("Key", style="bold cyan", width=18)
            poc_card.add_column("Val", style="white")

            poc_card.add_row("Finding #:", f"{idx} of {len(vuln_findings)}")
            poc_card.add_row("Endpoint:", f"[bold white]{vf.method} {vf.path}[/bold white]")
            poc_card.add_row("Asset Category:", vf.category)
            poc_card.add_row("Severity:", f"[bold {sev_color}]{vf.severity}[/]")
            poc_card.add_row("CWE Classification:", vf.cwe)
            poc_card.add_row("Security Risk:", f"[bold {sev_color}]{vf.reason}[/]")
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
        display_inventory_remediation()

    # Save markdown report
    md_path = save_shadow_zombie_markdown_report(spec, findings, config)
    console.print()
    console.print(f"[bold green]✔ Comprehensive audit report saved to:[/bold green] [underline cyan]{md_path}[/underline cyan]")

    # AI Security Analysis Flow
    prompt_ai_inventory_overview(spec, findings, config)

    try:
        input("\nPress Enter to return to menu...")
    except (KeyboardInterrupt, EOFError):
        pass


def display_inventory_remediation():
    """Renders production code fixes for API decommissioning and gateway filtering."""
    console.print()
    console.print(
        Panel(
            "[bold white]Production Remediation Blueprints[/bold white]\n"
            "[dim]Properly decommission retired versions and suppress unmapped routes.[/dim]",
            title="[bold green]🛠️ RECOMMENDED REMEDIATION CODE[/bold green]",
            border_style="green",
            padding=(0, 2),
        )
    )

    express_fix = """// Node.js / Express: Permanent Version Decommissioning (Sunset Header)
app.use("/api/v1", (req, res) => {
  // RFC 8594: Inform consumers that the endpoint is permanently retired
  res.setHeader("Sunset", "Wed, 01 Jan 2025 00:00:00 GMT");
  res.setHeader("Link", '</api/v2>; rel="successor-version"');
  return res.status(410).json({
    error: "Gone",
    message: "API version 1.0 has been permanently decommissioned. Please migrate to /api/v2/."
  });
});

// Prohibit diagnostic & debug endpoints in production
if (process.env.NODE_ENV === "production") {
  // Do NOT register /debug/*, /actuator/*, or *.old files
}"""

    fastapi_fix = """# Python / FastAPI: Retired Version Decommissioning
from fastapi import FastAPI, Response, status

app = FastAPI()

@app.api_route("/api/v1/{full_path:path}", methods=["GET", "POST", "PUT", "DELETE"])
def decommission_v1_handler(full_path: str):
    return Response(
        status_code=status.HTTP_410_GONE,
        headers={
            "Sunset": "Wed, 01 Jan 2025 00:00:00 GMT",
            "Link": '</api/v2>; rel="successor-version"',
        },
        content='{"error": "Gone", "message": "API v1 retired. Use /api/v2/"}',
        media_type="application/json",
    )"""

    console.print("[bold cyan]Node.js (Express) Decommissioning Fix:[/bold cyan]")
    console.print(Syntax(express_fix, "javascript", theme="monokai", line_numbers=True))
    console.print()
    console.print("[bold cyan]Python (FastAPI) Decommissioning Fix:[/bold cyan]")
    console.print(Syntax(fastapi_fix, "python", theme="monokai", line_numbers=True))


def save_shadow_zombie_markdown_report(
    spec: ParsedSpecification,
    findings: List[ShadowZombieFinding],
    config: Dict[str, Any],
) -> Path:
    """Saves structured markdown report in the root markdown/ directory."""
    md_dir = get_markdown_dir()
    slug = "".join([c if c.isalnum() else "_" for c in spec.title.lower()]).strip("_") or "api"
    filename = f"{slug}_shadow_zombie_api_scan_results_{int(time.time())}.md"
    file_path = md_dir / filename

    vuln_findings = [f for f in findings if f.is_vulnerable]

    lines = [
        "# OWASP API9:2023 — Shadow & Zombie APIs Audit Report",
        "",
        f"- **API Target:** {spec.title} (v{spec.version})",
        f"- **Base URL:** `{config.get('base_url')}`",
        f"- **Scan Timestamp:** {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}",
        f"- **Standard:** OWASP API Security Top 10 — API9:2023 Improper Inventory Management",
        f"- **Probes Evaluated:** {len(findings)}",
        f"- **Undocumented Assets Found:** {len(vuln_findings)}",
        "",
        "## Executive Summary",
        f"{'CRITICAL WARNING: Undocumented Shadow APIs, deprecated Zombie endpoints, or diagnostic interfaces were discovered actively running on the production host. These endpoints bypass standard security controls, lack monitoring, and expose confidential data.' if vuln_findings else 'CLEARANCE: Clean API inventory verified. Deprecated routes are either properly decommissioned (HTTP 410) or disabled (HTTP 404). Zero undocumented shadow assets detected.'}",
        "",
        "## Findings Matrix",
        "",
        "| Endpoint | Category | Audit Check | Status | Verdict | Severity |",
        "| :--- | :--- | :--- | :---: | :---: | :---: |",
    ]

    for f in findings:
        verdict = f"**{f.category.upper()}**" if f.is_vulnerable else ("RETIRED (410)" if f.status_code == 410 else "OFFLINE (404)")
        lines.append(f"| `{f.method} {f.path}` | {f.category} | {f.test_name} | `{f.status_code}` | {verdict} | {f.severity} |")

    if vuln_findings:
        lines.extend([
            "",
            "## Detailed Vulnerability Analysis & Proof of Concept",
            "",
        ])
        for idx, vf in enumerate(vuln_findings, 1):
            lines.extend([
                f"### Finding {idx}: {vf.test_name} on `{vf.method} {vf.path}`",
                f"- **Severity:** {vf.severity}",
                f"- **Asset Category:** {vf.category}",
                f"- **CWE Classification:** {vf.cwe}",
                f"- **HTTP Status Returned:** `{vf.status_code}`",
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


def prompt_ai_inventory_overview(
    spec: ParsedSpecification,
    findings: List[ShadowZombieFinding],
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
    prompt_text = build_inventory_ai_prompt(spec, findings, config)
    usage = estimate_token_usage(prompt_text)

    console.print()
    t = Table(box=None, show_header=False, padding=(0, 2))
    t.add_column("Key", style="bold cyan")
    t.add_column("Val", style="bold white")

    t.add_row("Active AI Model:", f"[bold green]{ai_cfg['model']}[/bold green] [dim]({ai_cfg['provider']})[/dim]")
    t.add_row("Target API Scope:", f"{spec.title} ({len(findings)} inventory candidates evaluated)")
    t.add_row("Context Included:", "Zombie API routes, shadow beta endpoints, diagnostic leaks, status codes")
    t.add_row("Context Payload:", f"{usage['char_count']} characters [dim](full test telemetry)[/dim]")
    t.add_row("Estimated Prompt Cost:", f"[bold yellow]~{usage['prompt_tokens']} input tokens[/bold yellow]")
    t.add_row("Estimated Generation:", f"~{usage['estimated_output_tokens']} completion tokens")
    t.add_row("Estimated Total:", f"[bold cyan]~{usage['estimated_total_tokens']} tokens[/bold cyan]")

    console.print(
        Panel(
            t,
            title="[bold yellow]🤖 AI INVENTORY & SHADOW API EXECUTIVE SUMMARY[/bold yellow]",
            border_style="yellow",
            padding=(0, 2),
        )
    )

    try:
        generate = questionary.confirm(
            f"Generate AI Inventory Management Security Blueprint with {ai_cfg['model']}?",
            default=False,
            style=CUSTOM_STYLE,
        ).ask()
    except (KeyboardInterrupt, EOFError):
        return

    if not generate:
        console.print("[dim]AI summary generation skipped.[/dim]")
        return

    with Progress(
        SpinnerColumn(spinner_name="dots"),
        TextColumn("[bold cyan]{task.description}[/bold cyan]"),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        task = progress.add_task(f"Connecting to {ai_cfg['model']}...", total=None)

        def update_spinner(count: int):
            progress.update(task, description=f"[bold green]Synthesizing Inventory Security Blueprint ({count} tokens)...[/bold green]")

        success, response_text = request_ai_overview(prompt_text, progress_callback=update_spinner)

    if not success or not response_text:
        console.print(f"[bold red]AI Generation Failed:[/bold red] {response_text}")
        return

    console.print()
    console.print(
        Panel(
            Markdown(response_text),
            title="[bold green]AI SECURITY EXECUTIVE SUMMARY & INVENTORY DECOMMISSIONING ROADMAP[/bold green]",
            border_style="green",
            padding=(1, 2),
        )
    )

    # Save AI report
    md_dir = get_markdown_dir()
    slug = "".join([c if c.isalnum() else "_" for c in spec.title.lower()]).strip("_") or "api"
    ai_report_file = md_dir / f"{slug}_shadow_zombie_ai_report_{int(time.time())}.md"
    try:
        with open(ai_report_file, "w", encoding="utf-8") as f:
            f.write(f"# AI Security Executive Summary: {spec.title}\n\n{response_text}")
        console.print(f"[dim green]✔ AI Executive Report saved to: {ai_report_file}[/dim green]")
    except Exception:
        pass


def build_inventory_ai_prompt(
    spec: ParsedSpecification,
    findings: List[ShadowZombieFinding],
    config: Dict[str, Any],
) -> str:
    """Builds prompt for LLM asset management analysis."""
    vulns = [f for f in findings if f.is_vulnerable]

    summary_data = {
        "api_title": spec.title,
        "base_url": config.get("base_url"),
        "declared_endpoints_in_spec": len(spec.endpoints),
        "total_probes_evaluated": len(findings),
        "undocumented_assets_found": len(vulns),
        "assets": [
            {
                "path": f"{f.method} {f.path}",
                "category": f.category,
                "test": f.test_name,
                "status_code": f.status_code,
                "severity": f.severity,
                "risk": f.reason,
                "remediation": f.remediation,
            }
            for f in vulns
        ],
    }

    return (
        "You are a premier application security architect specializing in OWASP API9:2023 (Improper Inventory Management).\n"
        "Analyze the following Shadow, Zombie, and Diagnostic discovery results for the target API:\n\n"
        f"{json.dumps(summary_data, indent=2)}\n\n"
        "Provide a high-impact executive security briefing covering:\n"
        "1. Executive Inventory Risk Assessment (Zombie APIs, undocumented shadow routes, diagnostic exposures)\n"
        "2. Attack Surface Analysis (Why deprecated v1 endpoints are high-value targets for attackers)\n"
        "3. Concrete Decommissioning Strategy (HTTP 410 Gone, Sunset RFC 8594 headers, Gateway routing rules)\n"
        "4. Continuous Inventory Governance (Automated OpenAPI spec synchronization, CI/CD schema verification)"
    )
