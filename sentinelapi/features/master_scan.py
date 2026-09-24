"""SentinelAPI Master Scan — Unified Full-Suite Security Assessment.

Orchestrates all 7 vulnerability modules in a single automated pipeline:
  1. BOLA / IDOR (Broken Object Level Authorization)
  2. Excessive Data Exposure
  3. Authentication Misconfiguration
  4. Rate Limiting & Resource Exhaustion
  5. BFLA & Privilege Escalation
  6. Security Misconfiguration (Headers & Cookies)
  7. Shadow & Zombie API Discovery

Collects ALL configuration once upfront, then runs every scanner back-to-back
with zero user interaction. Captures detailed live telemetry from every module
and produces a consolidated AI-powered security overview with complete remediation.
"""
import json
import time
import re
import builtins
from contextlib import contextmanager
from pathlib import Path
from typing import Dict, Any, Optional, List
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.markdown import Markdown
import questionary
from prompt_toolkit.styles import Style

from sentinelapi.cli.theme import console
from sentinelapi.api_source.spec_parser import ParsedSpecification

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
MARKDOWN_DIR = PROJECT_ROOT / "markdown"


# ──────────────────────────────────────────────────────
# Auto-answer helper: suppresses interactive prompts
# inside individual modules during automated master scan
# ──────────────────────────────────────────────────────
class _NoOpQuestion:
    """Fake questionary question that auto-returns a value without blocking."""
    def __init__(self, value):
        self._value = value
    def ask(self):
        return self._value


@contextmanager
def _auto_answer_prompts():
    """Temporarily monkeypatches questionary to auto-skip per-module AI confirmations and pauses.

    - questionary.confirm → auto-returns False (skip individual AI overviews)
    - questionary.press_any_key_to_continue → auto-returns immediately
    - builtins.input → auto-returns '' (for any raw input() pause calls)
    """
    orig_confirm = questionary.confirm
    orig_press = questionary.press_any_key_to_continue
    orig_input = builtins.input

    def fake_confirm(*args, **kwargs):
        console.print("[dim]  ↳ Sub-module AI skipped (master scan handles AI at the end)[/dim]")
        return _NoOpQuestion(False)

    def fake_press(*args, **kwargs):
        return _NoOpQuestion(None)

    def fake_input(*args, **kwargs):
        return ""

    questionary.confirm = fake_confirm
    questionary.press_any_key_to_continue = fake_press
    builtins.input = fake_input

    try:
        yield
    finally:
        questionary.confirm = orig_confirm
        questionary.press_any_key_to_continue = orig_press
        builtins.input = orig_input


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

# ──────────────────────────────────────────────────────
# Module Registry — all 7 OWASP Security Modules
# ──────────────────────────────────────────────────────
MODULE_REGISTRY = [
    {
        "id": "bola_idor",
        "name": "BOLA / IDOR (Broken Object Level Authorization)",
        "owasp": "API1:2023",
        "color": "magenta",
        "icon": "🔓",
    },
    {
        "id": "excessive_data",
        "name": "Excessive Data Exposure",
        "owasp": "API3:2023",
        "color": "magenta",
        "icon": "📡",
    },
    {
        "id": "auth_misconfig",
        "name": "Authentication Misconfiguration",
        "owasp": "API2:2023",
        "color": "yellow",
        "icon": "🔑",
    },
    {
        "id": "rate_limiting",
        "name": "Rate Limiting & Resource Exhaustion",
        "owasp": "API4:2023",
        "color": "red",
        "icon": "⏱",
    },
    {
        "id": "bfla",
        "name": "BFLA & Privilege Escalation",
        "owasp": "API5:2023",
        "color": "purple",
        "icon": "👑",
    },
    {
        "id": "sec_misconfig",
        "name": "Security Misconfiguration (Headers & Cookies)",
        "owasp": "API8:2023",
        "color": "yellow",
        "icon": "🛡",
    },
    {
        "id": "shadow_zombie",
        "name": "Shadow & Zombie API Discovery",
        "owasp": "API9:2023",
        "color": "yellow",
        "icon": "👻",
    },
]


def run_master_scan(spec: ParsedSpecification):
    """Orchestrates a full-suite security scan across all 7 OWASP modules."""
    console.clear()

    # ── Splash Banner ──
    console.print(
        Panel(
            "[bold white]╔══════════════════════════════════════════════════════════╗[/bold white]\n"
            "[bold white]║[/bold white]     [bold cyan]S E N T I N E L   A P I[/bold cyan]   [bold red]F U L L   S C A N[/bold red]       [bold white]║[/bold white]\n"
            "[bold white]╚══════════════════════════════════════════════════════════╝[/bold white]\n\n"
            f"[bold white]Target API:[/bold white]    [bold cyan]{spec.title}[/bold cyan] (v{spec.version})\n"
            f"[bold white]Base URL:[/bold white]      [yellow]{spec.base_url}[/yellow]\n"
            f"[bold white]Auth Scheme:[/bold white]   {spec.auth_scheme}\n"
            f"[bold white]Endpoints:[/bold white]     {len(spec.endpoints)} discovered\n"
            f"[bold white]Object IDs:[/bold white]    {len(spec.parameterized_endpoints)} parameterized routes\n"
            f"[bold white]Modules:[/bold white]       [bold green]{len(MODULE_REGISTRY)}[/bold green] OWASP security scanners\n\n"
            "[dim]This scan executes every security module sequentially against the target.\n"
            "All questions are asked ONCE upfront — then the scan runs fully automated.[/dim]",
            title="[bold red]⚡ SENTINELAPI FULL VULNERABILITY ASSESSMENT ⚡[/bold red]",
            border_style="red",
            padding=(1, 3),
        )
    )

    # Module overview table
    mod_table = Table(
        title="[bold cyan]Security Modules to Execute[/bold cyan]",
        box=None,
        padding=(0, 2),
        header_style="bold cyan",
    )
    mod_table.add_column("#", style="dim", width=3)
    mod_table.add_column("Module", style="bold white")
    mod_table.add_column("OWASP", style="yellow")
    mod_table.add_column("Status", style="dim")

    for idx, m in enumerate(MODULE_REGISTRY, 1):
        mod_table.add_row(str(idx), f"{m['icon']}  {m['name']}", m["owasp"], "[bold green]● QUEUED[/bold green]")

    console.print(mod_table)
    console.print()

    # ═══════════════════════════════════════════════════════
    # STEP 1: Ask ALL configuration questions upfront
    # ═══════════════════════════════════════════════════════
    config = configure_master_scan(spec)
    if not config:
        return

    console.clear()

    tok_display = f"{config['bearer_token'][:50]}..." if config['bearer_token'] else "(none)"

    # ── Execution Header ──
    console.print(
        Panel(
            f"[bold white]Target:[/bold white]     [bold cyan]{spec.title}[/bold cyan] ({config['base_url']})\n"
            f"[bold white]Token:[/bold white]      [dim]{tok_display}[/dim]\n"
            f"[bold white]Burst:[/bold white]      {config['burst_count']} requests/route\n"
            f"[bold white]AI Report:[/bold white]  {'[bold green]YES[/bold green]' if config['generate_ai'] else '[bold yellow]SKIPPED[/bold yellow]'}\n\n"
            "[bold green]Configuration locked. Running all 7 modules — zero interaction from here.[/bold green]",
            title="[bold cyan]MASTER SCAN CONFIGURATION LOCKED[/bold cyan]",
            border_style="cyan",
            padding=(1, 2),
        )
    )

    # ═══════════════════════════════════════════════════════
    # STEP 2: Run each module one by one (NO user interaction)
    #
    # Auto-answer all per-module questionary prompts (AI confirms,
    # press-any-key pauses) so the scan runs fully automated.
    # ═══════════════════════════════════════════════════════
    module_outcomes: List[Dict[str, Any]] = []

    with _auto_answer_prompts():
        for idx, mod in enumerate(MODULE_REGISTRY, 1):
            console.print()
            separator = "━" * 80
            console.print(f"[bold {mod['color']}]{separator}[/bold {mod['color']}]")
            console.print(
                Panel(
                    f"[bold white]Module {idx}/{len(MODULE_REGISTRY)}:[/bold white]  {mod['icon']}  [bold cyan]{mod['name']}[/bold cyan]\n"
                    f"[bold white]OWASP ID:[/bold white]        {mod['owasp']}\n"
                    f"[bold white]Target:[/bold white]          [yellow]{config['base_url']}[/yellow]",
                    title=f"[bold {mod['color']}]▶ EXECUTING MODULE {idx} OF {len(MODULE_REGISTRY)}[/bold {mod['color']}]",
                    border_style=mod["color"],
                    padding=(0, 2),
                )
            )

            try:
                raw_findings = execute_module(mod["id"], spec, config)
                module_outcomes.append({
                    "module": mod,
                    "status": "completed",
                    "findings": raw_findings or [],
                })
                console.print(f"[bold green]  ✓ {mod['name']} — COMPLETED[/bold green]")
            except KeyboardInterrupt:
                console.print(f"\n[bold yellow]  ⚠ {mod['name']} — INTERRUPTED (skipping)[/bold yellow]")
                module_outcomes.append({"module": mod, "status": "skipped", "findings": []})
            except Exception as e:
                console.print(f"\n[bold red]  ✖ {mod['name']} — ERROR: {str(e)[:100]}[/bold red]")
                module_outcomes.append({"module": mod, "status": "error", "findings": [], "error": str(e)})

    # ═══════════════════════════════════════════════════════
    # STEP 3: Consolidated Summary Dashboard
    # ═══════════════════════════════════════════════════════
    render_master_summary(spec, config, module_outcomes)

    # ═══════════════════════════════════════════════════════
    # STEP 4: AI Master Overview (if user opted in upfront)
    # ═══════════════════════════════════════════════════════
    if config["generate_ai"]:
        render_master_ai_overview(spec, config, module_outcomes)

    console.print()
    try:
        questionary.press_any_key_to_continue("Press any key to return to the main menu...").ask()
    except (KeyboardInterrupt, EOFError):
        pass


def configure_master_scan(spec: ParsedSpecification) -> Optional[Dict[str, Any]]:
    """Collects ALL configuration upfront in one shot — base URL, tokens, burst settings, AI preference."""
    console.print(
        Panel(
            "[bold white]Unified Scan Configuration[/bold white]\n\n"
            "[dim]Answer these questions once — the scan will then run fully automated\n"
            "across all 7 OWASP modules with zero further interaction.[/dim]",
            title="[bold cyan]🔧 MASTER SCAN CONFIGURATION (ALL QUESTIONS UPFRONT)[/bold cyan]",
            border_style="cyan",
            padding=(1, 2),
        )
    )

    default_base = spec.base_url if spec.base_url and spec.base_url.startswith("http") else "http://localhost:3000"

    # Auto-detect saved Fluffwalks session
    auth_session_file = PROJECT_ROOT / "fluffwalks-test-case" / "auth_session.json"
    saved_session = {}
    if auth_session_file.exists():
        try:
            with open(auth_session_file) as f:
                saved_session = json.load(f)
            console.print("[bold green]✓[/bold green] Auto-detected saved Fluffwalks auth session.\n")
        except Exception:
            pass

    try:
        # ── Q1: Base URL ──
        base_url = questionary.text(
            "Q1. Target Base URL:",
            default=default_base,
            style=CUSTOM_STYLE,
        ).ask()
        if not base_url:
            return None

        # ── Q2: Bearer Token ──
        default_tok = saved_session.get("bearer_token") or ""
        token_input = questionary.text(
            "Q2. Bearer Token / JWT (press Enter for saved session):",
            default=default_tok,
            style=CUSTOM_STYLE,
        ).ask()
        if token_input:
            token_input = token_input.strip()
            if not token_input.lower().startswith("bearer "):
                token_input = f"Bearer {token_input}"

        # ── Q3: Cookie ──
        default_cookie = saved_session.get("cookie_string") or ""
        cookie_input = questionary.text(
            "Q3. Browser Cookie (press Enter for saved session, leave empty to skip):",
            default=default_cookie,
            style=CUSTOM_STYLE,
        ).ask()

        # ── Q4: Burst Intensity ──
        burst_choice = questionary.select(
            "Q4. Rate Limit Burst Intensity:",
            choices=[
                "Standard (20 rapid requests per route)",
                "Gentle (10 rapid requests per route)",
                "Aggressive (30 rapid requests per route)",
            ],
            style=CUSTOM_STYLE,
        ).ask()

        burst_count = 20
        if burst_choice and "10" in burst_choice:
            burst_count = 10
        elif burst_choice and "30" in burst_choice:
            burst_count = 30

        # ── Q5: AI Overview ──
        generate_ai = questionary.confirm(
            "Q5. Generate AI Security Intelligence Report at the end?",
            default=True,
            style=CUSTOM_STYLE,
        ).ask()

        # Build parameter samples from endpoints
        params = {}
        for ep in spec.endpoints:
            for p in ep.parameters:
                pname = p.get("name")
                if pname and pname not in params:
                    example = p.get("schema", {}).get("example") or p.get("example")
                    val = str(example) if example is not None else ("101" if "user" in pname.lower() or "id" in pname.lower() else "501")
                    params[pname] = val

        # Extract raw JWT for auth misconfig testing
        base_token = token_input or ""
        if base_token.lower().startswith("bearer "):
            base_token = base_token[7:].strip()

        console.print()
        console.print("[bold green]━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/bold green]")
        console.print("[bold green]✓ All questions answered. Configuration locked.[/bold green]")
        console.print(f"  [dim]Target:[/dim]  {base_url}")
        console.print(f"  [dim]Token:[/dim]   {token_input[:50]}..." if token_input and len(token_input) > 50 else f"  [dim]Token:[/dim]   {token_input or '(none)'}")
        console.print(f"  [dim]Burst:[/dim]   {burst_count} req/route")
        console.print(f"  [dim]AI:[/dim]      {'Yes' if generate_ai else 'No'}")
        console.print("[bold green]━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/bold green]")
        console.print()

        confirm = questionary.confirm(
            "Launch Full-Suite Security Assessment now? (7 modules, zero interaction)",
            default=True,
            style=CUSTOM_STYLE,
        ).ask()

        if not confirm:
            return None

        return {
            "base_url": base_url.rstrip("/"),
            "bearer_token": token_input or "",
            "cookie_string": (cookie_input or "").strip(),
            "burst_count": burst_count,
            "params": params,
            "user_token": token_input or "",
            "base_token": base_token,
            "generate_ai": generate_ai if generate_ai is not None else True,
        }

    except (KeyboardInterrupt, EOFError):
        return None


def execute_module(module_id: str, spec: ParsedSpecification, config: Dict[str, Any]) -> Any:
    """Dispatches to each module's DIRECT live scan function and returns raw findings."""

    if module_id == "bola_idor":
        return _run_bola_direct(spec, config)

    elif module_id == "excessive_data":
        from sentinelapi.features.Excessive_Data_Exposure.ui import run_live_exposure_scan
        mod_config = {
            "base_url": config["base_url"],
            "bearer_token": config["bearer_token"],
            "auth_header": "Authorization" if config["bearer_token"] else "Cookie",
            "params": config.get("params", {}),
        }
        if not config["bearer_token"] and config.get("cookie_string"):
            mod_config["bearer_token"] = config["cookie_string"]
            mod_config["auth_header"] = "Cookie"
        return run_live_exposure_scan(spec, mod_config)

    elif module_id == "auth_misconfig":
        from sentinelapi.features.Authentication_Misconfiguration.ui import run_live_auth_scan
        mod_config = {
            "base_url": config["base_url"],
            "base_token": config.get("base_token", ""),
            "vector_choice": "1. All Test Vectors (Missing Auth, alg:none, Tampered Sig, Expired Token, Malformed)",
        }
        return run_live_auth_scan(spec, mod_config)

    elif module_id == "rate_limiting":
        from sentinelapi.features.Rate_Limiting.ui import run_live_rate_limit_scan
        headers = {}
        if config.get("bearer_token"):
            headers["Authorization"] = config["bearer_token"]
        mod_config = {
            "base_url": config["base_url"],
            "burst_count": config.get("burst_count", 20),
            "headers": headers,
        }
        return run_live_rate_limit_scan(spec, mod_config)

    elif module_id == "bfla":
        from sentinelapi.features.BFLA.ui import run_live_bfla_scan
        mod_config = {
            "base_url": config["base_url"],
            "user_token": config.get("bearer_token") or "Bearer user_token_101",
        }
        return run_live_bfla_scan(spec, mod_config)

    elif module_id == "sec_misconfig":
        from sentinelapi.features.Security_Misconfiguration.ui import run_full_sec_misconfig_audit
        mod_config = {
            "base_url": config["base_url"],
            "auth_header": config.get("bearer_token") or "",
        }
        return run_full_sec_misconfig_audit(spec, mod_config)

    elif module_id == "shadow_zombie":
        from sentinelapi.features.Shadow_Zombie_APIs.ui import run_live_inventory_scan
        mod_config = {
            "base_url": config["base_url"],
        }
        return run_live_inventory_scan(spec, mod_config)

    return []


def _run_bola_direct(spec: ParsedSpecification, config: Dict[str, Any]) -> Any:
    """Runs BOLA/IDOR scan directly without the interactive menu loop."""
    from sentinelapi.features.bola_idor.ui import (
        infer_dynamic_bola_context,
        check_target_online,
        run_assessment,
    )

    bola_config = infer_dynamic_bola_context(spec)

    if config.get("bearer_token"):
        bola_config["victim_token"] = config["bearer_token"]
        bola_config["attacker_token"] = "Bearer token-00000000-0000-0000-0000-000000000002"

    param_endpoints = spec.parameterized_endpoints
    is_live = check_target_online(spec.base_url)

    return run_assessment(spec, param_endpoints, bola_config, is_live)


def _format_module_findings_for_summary(mo: Dict[str, Any]) -> str:
    """Extracts a human-readable finding summary for a module."""
    mod = mo["module"]
    findings = mo.get("findings", [])
    status = mo.get("status")

    if status != "completed":
        return f"[yellow]{status.upper()}[/yellow]"

    if not findings:
        return "[green]0 Vulnerabilities Detected (Clean)[/green]"

    vuln_count = 0
    if mod["id"] == "bola_idor":
        vuln_count = sum(1 for f in findings if isinstance(f, dict) and f.get("vulnerable"))
    elif mod["id"] == "excessive_data":
        vuln_count = sum(1 for f in findings if isinstance(f, dict) and f.get("analysis", {}).get("is_vulnerable"))
    else:
        vuln_count = sum(1 for f in findings if getattr(f, "is_vulnerable", False) or (isinstance(f, dict) and f.get("is_vulnerable")))

    if vuln_count > 0:
        return f"[bold red]{vuln_count} Vulnerabilities Confirmed[/bold red]"
    return "[bold green]✓ 0 Vulnerabilities (PASSED)[/bold green]"


def render_master_summary(
    spec: ParsedSpecification,
    config: Dict[str, Any],
    module_outcomes: List[Dict[str, Any]],
):
    """Renders a consolidated summary dashboard after all modules have finished."""
    console.print()
    console.print()

    completed = sum(1 for m in module_outcomes if m["status"] == "completed")
    skipped = sum(1 for m in module_outcomes if m["status"] == "skipped")
    errored = sum(1 for m in module_outcomes if m["status"] == "error")

    total_vulns = 0
    for mo in module_outcomes:
        findings = mo.get("findings", [])
        if mo["module"]["id"] == "bola_idor":
            total_vulns += sum(1 for f in findings if isinstance(f, dict) and f.get("vulnerable"))
        elif mo["module"]["id"] == "excessive_data":
            total_vulns += sum(1 for f in findings if isinstance(f, dict) and f.get("analysis", {}).get("is_vulnerable"))
        else:
            total_vulns += sum(1 for f in findings if getattr(f, "is_vulnerable", False) or (isinstance(f, dict) and f.get("is_vulnerable")))

    separator = "━" * 80
    console.print(f"[bold red]{separator}[/bold red]")

    # Summary Table
    summary = Table(
        title="[bold red]⚡ SENTINELAPI MASTER SCAN — LIVE AUDIT DASHBOARD ⚡[/bold red]",
        border_style="red",
        header_style="bold cyan",
        padding=(0, 2),
    )
    summary.add_column("#", style="dim", width=3)
    summary.add_column("Security Module", style="bold white")
    summary.add_column("OWASP", style="yellow")
    summary.add_column("Findings Telemetry", justify="left")
    summary.add_column("Status", justify="center")

    for idx, mo in enumerate(module_outcomes, 1):
        mod = mo["module"]
        status = mo["status"]
        if status == "completed":
            badge = "[bold green]✓ COMPLETED[/bold green]"
        elif status == "skipped":
            badge = "[bold yellow]⚠ SKIPPED[/bold yellow]"
        else:
            badge = "[bold red]✖ ERROR[/bold red]"

        finding_str = _format_module_findings_for_summary(mo)
        summary.add_row(str(idx), f"{mod['icon']}  {mod['name']}", mod["owasp"], finding_str, badge)

    console.print(summary)

    # Overall Posture
    if total_vulns > 0:
        posture = f"[bold red]CRITICAL: {total_vulns} ACTIVE VULNERABILITY FINDINGS IDENTIFIED[/bold red]"
        border = "red"
    elif completed == len(MODULE_REGISTRY):
        posture = "[bold green]ALL 7 MODULES EXECUTED — ZERO CRITICAL VULNERABILITIES[/bold green]"
        border = "green"
    else:
        posture = f"[bold yellow]{skipped} MODULE(S) SKIPPED / {errored} ERRORED[/bold yellow]"
        border = "yellow"

    console.print()
    console.print(
        Panel(
            f"[bold white]Target API:[/bold white]          [bold cyan]{spec.title}[/bold cyan]\n"
            f"[bold white]Base URL:[/bold white]            [yellow]{config['base_url']}[/yellow]\n"
            f"[bold white]Total Vulnerabilities:[/bold white] [bold red]{total_vulns}[/bold red]\n"
            f"[bold white]Modules Completed:[/bold white]     [bold green]{completed}[/bold green] / {len(MODULE_REGISTRY)}\n"
            f"[bold white]Assessment Verdict:[/bold white]    {posture}",
            title="[bold red]⚡ CONSOLIDATED SECURITY POSTURE ⚡[/bold red]",
            border_style=border,
            padding=(1, 2),
        )
    )
    console.print(f"[bold red]{separator}[/bold red]")


def _build_rich_telemetry_prompt(
    spec: ParsedSpecification,
    config: Dict[str, Any],
    module_outcomes: List[Dict[str, Any]],
) -> str:
    """Builds a comprehensive, context-dense prompt containing ALL real live telemetry from all 7 modules."""
    lines = [
        f"# SENTINELAPI MASTER SECURITY ASSESSMENT REPORT: {spec.title}",
        f"- Target Base URL: {config['base_url']}",
        f"- Specification: {spec.spec_type} (Version: {spec.version})",
        f"- Auth Scheme: {spec.auth_scheme}",
        f"- Total Endpoints in Inventory: {len(spec.endpoints)}",
        f"- Parameterized Routes Tested: {len(spec.parameterized_endpoints)}",
        "",
        "## DETAILED LIVE TEST TELEMETRY BY OWASP CATEGORY:",
    ]

    for mo in module_outcomes:
        mod = mo["module"]
        findings = mo.get("findings", [])
        status = mo.get("status")

        lines.append(f"\n### [{mod['owasp']}] {mod['name']}")
        lines.append(f"Execution Status: {status}")

        if not findings:
            lines.append("Telemetry: No findings recorded or module skipped.")
            continue

        if mod["id"] == "bola_idor":
            vulns = [f for f in findings if isinstance(f, dict) and f.get("vulnerable")]
            lines.append(f"- Total Candidate Object Endpoints Tested: {len(findings)}")
            lines.append(f"- Vulnerabilities Confirmed: {len(vulns)}")
            for idx, f in enumerate(findings, 1):
                ep = f.get("endpoint")
                ep_str = f"{ep.method} {ep.path}" if ep else "Route"
                is_v = "VULNERABLE (BOLA LEAK)" if f.get("vulnerable") else "SECURED (403/401 DENIED)"
                lines.append(f"  {idx}. {ep_str} -> Baseline: {f.get('baseline_status')} | Attack: {f.get('attack_status')} | Verdict: {is_v}")

        elif mod["id"] == "excessive_data":
            vulns = [f for f in findings if isinstance(f, dict) and f.get("analysis", {}).get("is_vulnerable")]
            lines.append(f"- Total Endpoints Inspected for Data Overexposure: {len(findings)}")
            lines.append(f"- Endpoints Leaking Sensitive/Excessive Data: {len(vulns)}")
            for idx, f in enumerate(findings, 1):
                ep = f.get("endpoint")
                ep_str = f"{ep.method} {ep.path}" if ep else "Route"
                ana = f.get("analysis", {})
                if ana.get("is_vulnerable"):
                    lines.append(f"  {idx}. [LEAK DETECTED] {ep_str} (HTTP {f.get('status_code')}) - Severity: {ana.get('severity')}")
                    for fd in ana.get("findings", []):
                        lines.append(f"     * Leaked Field: `{fd.get('key')}` (Value snippet: {str(fd.get('value'))[:60]}) -> {fd.get('reason')}")
                else:
                    lines.append(f"  {idx}. [CLEAN] {ep_str} (HTTP {f.get('status_code')}) - No sensitive fields leaked")

        elif mod["id"] == "auth_misconfig":
            vulns = [f for f in findings if getattr(f, "is_vulnerable", False)]
            lines.append(f"- Total Authentication Test Vectors Evaluated: {len(findings)}")
            lines.append(f"- Broken Authentication Vectors: {len(vulns)}")
            for idx, f in enumerate(findings, 1):
                is_v = "BYPASS SUCCESS (VULNERABLE)" if getattr(f, "is_vulnerable", False) else "PROPERLY REJECTED (PASS)"
                lines.append(f"  {idx}. {getattr(f, 'endpoint', '')} | Vector: {getattr(f, 'test_name', '')} | Verdict: {is_v} (HTTP {getattr(f, 'status_code', '')})")
                if getattr(f, "is_vulnerable", False):
                    lines.append(f"     Reason: {getattr(f, 'reason', '')}")

        elif mod["id"] == "rate_limiting":
            vulns = [f for f in findings if getattr(f, "is_vulnerable", False)]
            lines.append(f"- Total Routes Tested for Rate Limiting / Burst Exhaustion: {len(findings)}")
            lines.append(f"- Unrestricted Endpoints (Missing Rate Limit): {len(vulns)}")
            for idx, f in enumerate(findings, 1):
                is_v = "UNRESTRICTED (VULNERABLE)" if getattr(f, "is_vulnerable", False) else "RATE LIMITED (429 ENFORCED)"
                lines.append(f"  {idx}. {getattr(f, 'endpoint', '')} -> Total Requests: {getattr(f, 'requests_sent', 20)} | Successful: {getattr(f, 'success_count', '')} | 429 Responses: {getattr(f, 'rate_limited_count', '')} | Verdict: {is_v}")

        elif mod["id"] == "bfla":
            vulns = [f for f in findings if getattr(f, "is_vulnerable", False)]
            lines.append(f"- Total Privileged / Administrative Endpoints Tested: {len(findings)}")
            lines.append(f"- Privilege Escalation Vulnerabilities: {len(vulns)}")
            for idx, f in enumerate(findings, 1):
                is_v = "PRIVILEGE ESCALATION BYPASS (VULNERABLE)" if getattr(f, "is_vulnerable", False) else "PROPERLY BLOCKED (403 FORBIDDEN)"
                lines.append(f"  {idx}. {getattr(f, 'method', '')} {getattr(f, 'endpoint', '')} -> Status: {getattr(f, 'status_code', '')} | Verdict: {is_v}")

        elif mod["id"] == "sec_misconfig":
            vulns = [f for f in findings if getattr(f, "is_vulnerable", False)]
            lines.append(f"- Security Header & Cookie Misconfiguration Checks: {len(findings)}")
            lines.append(f"- Misconfigurations / Missing Headers: {len(vulns)}")
            for idx, f in enumerate(findings, 1):
                if getattr(f, "is_vulnerable", False):
                    lines.append(f"  * [{getattr(f, 'severity', 'MEDIUM')}] {getattr(f, 'endpoint', '')} -> {getattr(f, 'test_name', '')}: {getattr(f, 'reason', '')}")

        elif mod["id"] == "shadow_zombie":
            vulns = [f for f in findings if getattr(f, "is_vulnerable", False)]
            lines.append(f"- Total Shadow / Zombie / Hidden Candidate Routes Probed: {len(findings)}")
            lines.append(f"- Undocumented / Zombie Endpoints Discovered Live: {len(vulns)}")
            for idx, f in enumerate(findings, 1):
                if getattr(f, "is_vulnerable", False):
                    lines.append(f"  * [EXPOSED ASSET] {getattr(f, 'method', '')} {getattr(f, 'path', '')} (HTTP {getattr(f, 'status_code', '')}) - {getattr(f, 'category', '')}: {getattr(f, 'reason', '')}")

    lines.extend([
        "",
        "## INSTRUCTIONS FOR MASTER AI SECURITY REPORT:",
        "You are SentinelAPI Core Security Intelligence Engine. You are analyzing the REAL LIVE test findings provided above.",
        "Produce an authoritative, complete, comprehensive security intelligence report in structured GitHub Markdown.",
        "Ensure ALL sections below are thoroughly detailed without omitting anything or stopping abruptly:",
        "",
        "### 1. Executive Threat Posture & Assessment Overview",
        "Summarize the overall security health of this API based on the real findings across all 7 OWASP categories.",
        "",
        "### 2. Consolidated Vulnerability Breakdown (By OWASP Category)",
        "Detail the exact findings for each of the 7 modules tested, referencing specific endpoints and parameters from the live telemetry above.",
        "",
        "### 3. Critical Risk Matrix",
        "Provide a markdown table ranking the identified risks with columns: Rank, Vulnerability, OWASP Category, Affected Endpoints, Severity (CRITICAL/HIGH/MEDIUM/LOW), Likelihood, Impact, Mitigation Priority.",
        "",
        "### 4. Real-World Attack Chain Scenarios",
        "Describe step-by-step how an adversary could chain these specific vulnerabilities together (e.g. using excessive data exposure to find user IDs, then exploiting BFLA or rate limits).",
        "",
        "### 5. Production Code Hardening & Remediation Blueprint",
        "Provide concrete, production-ready code fixes (Node.js/Express or Python/FastAPI) for the top vulnerabilities discovered.",
        "",
        "### 6. Compliance & Regulatory Audit Summary",
        "Map these specific findings to regulatory frameworks: PCI-DSS v4.0, GDPR Article 32, and SOC 2 Type II.",
    ])

    return "\n".join(lines)


def render_master_ai_overview(
    spec: ParsedSpecification,
    config: Dict[str, Any],
    module_outcomes: List[Dict[str, Any]],
):
    """Generates and renders a unified AI security overview across all modules."""
    console.print()

    prompt_text = _build_rich_telemetry_prompt(spec, config, module_outcomes)

    console.print(
        Panel(
            "[bold cyan]Synthesizing live vulnerability findings across all 7 OWASP modules...[/bold cyan]\n"
            "[dim]Feeding real HTTP response telemetry, sensitive field leaks, and bypass proofs to AI engine.[/dim]",
            title="[bold cyan]🧠 AI SECURITY INTELLIGENCE ENGINE (FULL SUITE)[/bold cyan]",
            border_style="cyan",
            padding=(0, 2),
        )
    )

    try:
        from sentinelapi.modals.ai_engine import (
            request_ai_overview,
            estimate_token_usage,
            get_active_ai_config,
        )

        ai_cfg = get_active_ai_config()
        if not ai_cfg["is_configured"]:
            console.print("[bold yellow]⚠ No AI provider configured. Skipping AI overview.[/bold yellow]")
            console.print("[dim]Configure CUSTOM_LLM_API_KEY in .env to enable AI security reports.[/dim]")
            return

        token_est = estimate_token_usage(prompt_text)
        console.print(f"[dim]Model: {ai_cfg['model']} | Telemetry Payload: {token_est['char_count']} chars (~{token_est['prompt_tokens']} tokens)[/dim]")

        with Progress(
            SpinnerColumn(spinner_name="dots"),
            TextColumn("[bold cyan]{task.description}[/bold cyan]"),
            console=console,
        ) as progress:
            task = progress.add_task("Generating Full-Suite AI Security Intelligence Report...", total=None)

            def update_spinner(count):
                progress.update(task, description=f"AI Engine streaming report... ({count} tokens received)")

            success, response_text = request_ai_overview(
                prompt_text,
                progress_callback=update_spinner,
                max_tokens=4000,
            )

        if success and response_text:
            console.print()
            console.print(
                Panel(
                    Markdown(response_text),
                    title="[bold green]⚡ SENTINELAPI CONSOLIDATED AI SECURITY INTELLIGENCE REPORT ⚡[/bold green]",
                    border_style="green",
                    padding=(1, 2),
                )
            )

            # Save to markdown
            MARKDOWN_DIR.mkdir(parents=True, exist_ok=True)
            timestamp = time.strftime("%Y%m%d_%H%M%S")
            report_file = MARKDOWN_DIR / f"master_scan_report_{timestamp}.md"
            with open(report_file, "w", encoding="utf-8") as f:
                f.write(f"# SentinelAPI Full-Suite Security Assessment Report\n")
                f.write(f"**Target:** {spec.title} ({config['base_url']})\n")
                f.write(f"**Generated:** {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                f.write(response_text)
            console.print(f"\n[bold green]✓[/bold green] Complete report saved → [bold cyan]{report_file}[/bold cyan]")
        else:
            console.print(f"\n[bold yellow]⚠ AI report generation failed:[/bold yellow] {response_text}")

    except Exception as e:
        console.print(f"\n[bold red]✖ AI engine error:[/bold red] {str(e)}")
