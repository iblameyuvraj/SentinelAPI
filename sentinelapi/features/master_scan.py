"""SentinelAPI Master Scan — Result-First Architecture.

Orchestrates all 7 vulnerability modules into a unified pipeline:
  1. BOLA / IDOR (Broken Object Level Authorization - OWASP API1:2023)
  2. Excessive Data Exposure (OWASP API3:2023)
  3. Authentication Misconfiguration (OWASP API2:2023)
  4. Rate Limiting & Resource Exhaustion (OWASP API4:2023)
  5. BFLA & Privilege Escalation (OWASP API5:2023)
  6. Security Misconfiguration - Headers & Cookies (OWASP API8:2023)
  7. Shadow & Zombie API Discovery (OWASP API9:2023)

Architecture:
  - Collects all user configuration once upfront
  - Executes every scanner and captures typed, structured ScanResult models
  - Aggregates findings into a MasterScanResult
  - Renders live CLI summary with accurate pass/fail counts
  - Streams full AI Security Intelligence Report with concrete remediation
  - Exports both Markdown and structured JSON reports
"""
import json
import time
import re
import builtins
from contextlib import contextmanager
from pathlib import Path
from typing import Dict, Any, Optional, List, Tuple
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.markdown import Markdown
from rich.syntax import Syntax
import questionary
from prompt_toolkit.styles import Style

from sentinelapi.cli.theme import console
from sentinelapi.api_source.spec_parser import ParsedSpecification
from sentinelapi.core.models import Finding, ScanResult, MasterScanResult, Severity, ProbeError, ScanStatus

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
MARKDOWN_DIR = PROJECT_ROOT / "markdown"


# ──────────────────────────────────────────────────────
# Prompt Interceptor: suppresses per-module blocking prompts
# during automated master scan runs
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
        console.print("[dim]  ↳ Sub-module AI skipped (master scan aggregates at the end)[/dim]")
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


def run_master_scan(
    spec: ParsedSpecification,
    config_override: Optional[Dict[str, Any]] = None,
) -> MasterScanResult:
    """Main entrypoint: executes all 7 security scanners and returns a structured MasterScanResult."""
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
            "[dim]Result-First Engine: Executes all 7 scanners back-to-back with zero prompts,\n"
            "captures structured vulnerability telemetry, and compiles an actionable AI report.[/dim]",
            title="[bold red]⚡ SENTINELAPI FULL-SUITE SECURITY ASSESSMENT ⚡[/bold red]",
            border_style="red",
            padding=(1, 3),
        )
    )

    # ── Step 1: Upfront Configuration (Asked ONCE or overridden) ──
    if config_override:
        config = config_override
    else:
        config = configure_master_scan(spec)
        if not config:
            return MasterScanResult(
                target_title=spec.title,
                base_url=spec.base_url,
                spec_version=spec.version,
                auth_scheme=spec.auth_scheme,
                total_endpoints=len(spec.endpoints),
            )

    console.clear()
    tok_display = f"{config['bearer_token'][:45]}..." if config.get('bearer_token') else "(none)"

    console.print(
        Panel(
            f"[bold white]Target:[/bold white]     [bold cyan]{spec.title}[/bold cyan] ({config['base_url']})\n"
            f"[bold white]Token:[/bold white]      [dim]{tok_display}[/dim]\n"
            f"[bold white]Burst:[/bold white]      {config.get('burst_count', 20)} requests/route\n"
            f"[bold white]AI Report:[/bold white]  {'[bold green]YES (Full Synthesis)[/bold green]' if config.get('generate_ai', True) else '[bold yellow]SKIPPED[/bold yellow]'}\n\n"
            "[bold green]Configuration locked. Launching all 7 scanners — zero interaction from here.[/bold green]",
            title="[bold cyan]MASTER SCAN PIPELINE ACTIVE[/bold cyan]",
            border_style="cyan",
            padding=(1, 2),
        )
    )

    master_result = MasterScanResult(
        target_title=spec.title,
        base_url=config["base_url"],
        spec_version=spec.version,
        auth_scheme=spec.auth_scheme,
        total_endpoints=len(spec.endpoints),
        start_time=time.strftime("%Y-%m-%d %H:%M:%S"),
    )

    # ── Step 2: Execute Scanners in Automated Mode ──
    with _auto_answer_prompts():
        for idx, mod in enumerate(MODULE_REGISTRY, 1):
            console.print()
            separator = "━" * 80
            console.print(f"[bold {mod['color']}]{separator}[/bold {mod['color']}]")
            console.print(
                Panel(
                    f"[bold white]Module {idx}/{len(MODULE_REGISTRY)}:[/bold white]  {mod['icon']}  [bold cyan]{mod['name']}[/bold cyan]\n"
                    f"[bold white]OWASP Standard:[/bold white]  {mod['owasp']}\n"
                    f"[bold white]Target Server:[/bold white]   [yellow]{config['base_url']}[/yellow]",
                    title=f"[bold {mod['color']}]▶ EXECUTING SCANNER {idx} OF {len(MODULE_REGISTRY)}[/bold {mod['color']}]",
                    border_style=mod["color"],
                    padding=(0, 2),
                )
            )

            start_t = time.time()
            try:
                raw_out = execute_module(mod["id"], spec, config)
                dur = time.time() - start_t
                scan_res = _convert_to_scan_result(mod, raw_out, dur, config=config)
                master_result.module_results[mod["id"]] = scan_res

                st = scan_res.status
                if st == ScanStatus.FAIL.value:
                    console.print(f"[bold red]  ✖ {mod['name']} — {len(scan_res.vulnerable_findings)} VULNERABILITIES CONFIRMED ({dur:.1f}s)[/bold red]")
                elif st == ScanStatus.ERROR.value:
                    console.print(f"[bold red]  ✖ {mod['name']} — ERROR: HOST UNREACHABLE / 0 PROBES SUCCEEDED ({dur:.1f}s)[/bold red]")
                elif st == ScanStatus.INCOMPLETE.value:
                    console.print(f"[bold yellow]  ⚠ {mod['name']} — INCOMPLETE COVERAGE ({scan_res.successful_probes}/{scan_res.planned_probes} probes ok) ({dur:.1f}s)[/bold yellow]")
                else:
                    console.print(f"[bold green]  ✓ {mod['name']} — PASS / 0 VULNERABILITIES DETECTED ({dur:.1f}s)[/bold green]")

            except KeyboardInterrupt:
                console.print(f"\n[bold yellow]  ⚠ {mod['name']} — SKIPPED BY USER[/bold yellow]")
                master_result.module_results[mod["id"]] = ScanResult(
                    scanner_id=mod["id"],
                    scanner_name=mod["name"],
                    owasp_category=mod["owasp"],
                    planned_probes=0,
                    successful_probes=0,
                    failed_probes=0,
                    errors=["User skipped scanner"],
                )
            except Exception as e:
                console.print(f"\n[bold red]  ✖ {mod['name']} — ERROR: {str(e)[:120]}[/bold red]")
                master_result.module_results[mod["id"]] = ScanResult(
                    scanner_id=mod["id"],
                    scanner_name=mod["name"],
                    owasp_category=mod["owasp"],
                    planned_probes=0,
                    successful_probes=0,
                    failed_probes=0,
                    errors=[str(e)],
                )

    master_result.end_time = time.strftime("%Y-%m-%d %H:%M:%S")

    # ── Step 3: Consolidated Summary Dashboard ──
    render_master_summary_dashboard(master_result)

    # ── Step 4: AI Master Report Synthesis ──
    if config.get("generate_ai", True):
        ai_report_text = generate_and_render_ai_master_report(spec, config, master_result)
        master_result.ai_report_markdown = ai_report_text

    # ── Step 5: Save Structured JSON & Markdown Artifacts ──
    _save_scan_artifacts(master_result)

    if not config_override:
        console.print()
        try:
            questionary.press_any_key_to_continue("Press any key to return to the main menu...").ask()
        except (KeyboardInterrupt, EOFError):
            pass

    return master_result


def configure_master_scan(spec: ParsedSpecification) -> Optional[Dict[str, Any]]:
    """Collects ALL configuration upfront in one shot — base URL, tokens, burst settings, AI preference."""
    console.print(
        Panel(
            "[bold white]Unified Scan Configuration[/bold white]\n\n"
            "[dim]Answer these questions once — the scan will then run fully automated\n"
            "across all 7 OWASP modules with zero further prompts.[/dim]",
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
        console.print(f"  [dim]Token:[/dim]   {token_input[:45]}..." if token_input and len(token_input) > 45 else f"  [dim]Token:[/dim]   {token_input or '(none)'}")
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
    """Runs BOLA/IDOR scan directly without the interactive menu loop.

    Guarantees:
      - Uses user-configured config["base_url"]
      - Forbids automatic simulation mode (fails closed if offline)
      - Probes live host availability using config["base_url"]
    """
    from sentinelapi.features.bola_idor.ui import (
        infer_dynamic_bola_context,
        check_target_online,
        run_assessment,
    )

    bola_config = infer_dynamic_bola_context(spec)
    target_base = config.get("base_url", spec.base_url).rstrip("/")
    bola_config["base_url"] = target_base
    bola_config["allow_simulation"] = False  # NEVER simulate in automated/master scan

    if config.get("bearer_token"):
        bola_config["victim_token"] = config["bearer_token"]
        bola_config["attacker_token"] = "Bearer token-00000000-0000-0000-0000-000000000002"

    param_endpoints = spec.parameterized_endpoints
    is_live = check_target_online(target_base)

    return run_assessment(spec, param_endpoints, bola_config, is_live)


def _convert_to_scan_result(
    mod: Dict[str, Any],
    raw_output: Any,
    duration_seconds: float,
    config: Optional[Dict[str, Any]] = None,
) -> ScanResult:
    """Converts the heterogeneous outputs of each scanner into a normalized ScanResult
    with strict probe accounting and fail-closed telemetry.
    """
    mod_id = mod["id"]
    base_url = (config.get("base_url") if config else "") or ""
    findings: List[Finding] = []
    probe_errors: List[ProbeError] = []
    errors: List[str] = []
    successful_probes = 0
    failed_probes = 0

    if not raw_output or not isinstance(raw_output, list):
        err_msg = f"{mod['name']} returned no probe results or failed execution"
        return ScanResult(
            scanner_id=mod_id,
            scanner_name=mod["name"],
            owasp_category=mod["owasp"],
            planned_probes=0,
            successful_probes=0,
            failed_probes=0,
            errors=[err_msg],
            duration_seconds=duration_seconds,
        )

    planned_probes = len(raw_output)

    # 1. BOLA / IDOR Converter
    if mod_id == "bola_idor":
        for idx, item in enumerate(raw_output, 1):
            if not isinstance(item, dict):
                continue
            ep = item.get("endpoint")
            ep_path = ep.path if ep else "/route"
            ep_method = ep.method if ep else "GET"
            target_url = item.get("target_url", f"{base_url}{ep_path}")
            attack_status = item.get("attack_status", 0)
            probe_err = item.get("probe_error")
            is_vuln = bool(item.get("vulnerable"))

            if probe_err or attack_status == 0:
                failed_probes += 1
                probe_errors.append(
                    ProbeError(
                        endpoint=ep_path,
                        method=ep_method,
                        error_message=str(probe_err or f"Host unreachable (HTTP {attack_status})"),
                        target_url=target_url,
                        status_code=attack_status,
                    )
                )
                findings.append(
                    Finding(
                        id=f"BOLA-{idx:02d}",
                        title="BOLA Probe Connection Error",
                        description=f"Probe failed to reach `{ep_method} {ep_path}`: {probe_err or 'Host unreachable'}",
                        severity="INFO",
                        endpoint=ep_path,
                        method=ep_method,
                        owasp_category=mod["owasp"],
                        evidence=f"Connection Error: {probe_err or 'HTTP 0'}",
                        status_code=attack_status,
                        is_vulnerable=False,
                    )
                )
            else:
                successful_probes += 1
                findings.append(
                    Finding(
                        id=f"BOLA-{idx:02d}",
                        title="Broken Object Level Authorization (IDOR)",
                        description=(
                            f"Object-level authorization check bypassed on `{ep_method} {ep_path}`. "
                            "Attacker token retrieved victim data."
                            if is_vuln
                            else f"Object-level authorization enforced on `{ep_method} {ep_path}`."
                        ),
                        severity="CRITICAL" if is_vuln else "INFO",
                        endpoint=ep_path,
                        method=ep_method,
                        owasp_category="API1:2023 - Broken Object Level Authorization",
                        cwe="CWE-639: Authorization Bypass Through User-Controlled Key",
                        evidence=(
                            f"Attacker probe received HTTP {attack_status} (Expected 403 Forbidden)"
                            if is_vuln
                            else f"Protected with HTTP {attack_status}"
                        ),
                        status_code=attack_status,
                        reproduction_curl=item.get("reproduction_curl"),
                        remediation="Verify that the authenticated user owns the requested resource ID at the data layer before returning data.",
                        is_vulnerable=is_vuln,
                    )
                )

    # 2. Excessive Data Exposure Converter
    elif mod_id == "excessive_data":
        for idx, item in enumerate(raw_output, 1):
            if not isinstance(item, dict):
                continue
            ep = item.get("endpoint")
            ep_path = ep.path if ep else "/route"
            ep_method = ep.method if ep else "GET"
            target_url = item.get("target_url", f"{base_url}{ep_path}")
            status_code = item.get("status_code", 0)
            probe_err = item.get("probe_error")
            ana = item.get("analysis", {})
            is_vuln = bool(item.get("is_vulnerable")) and status_code > 0

            if probe_err or status_code == 0:
                failed_probes += 1
                probe_errors.append(
                    ProbeError(
                        endpoint=ep_path,
                        method=ep_method,
                        error_message=str(probe_err or f"Connection error (HTTP {status_code})"),
                        target_url=target_url,
                        status_code=status_code,
                    )
                )
                findings.append(
                    Finding(
                        id=f"DATA-EXP-{idx:02d}",
                        title="Excessive Data Probe Connection Error",
                        description=f"Probe failed to reach `{ep_method} {ep_path}`: {probe_err or 'Host unreachable'}",
                        severity="INFO",
                        endpoint=ep_path,
                        method=ep_method,
                        owasp_category=mod["owasp"],
                        evidence=f"Connection Error: {probe_err or 'HTTP 0'}",
                        status_code=status_code,
                        is_vulnerable=False,
                    )
                )
            else:
                successful_probes += 1
                leaked_fields = [f.get("key") for f in ana.get("findings", []) if isinstance(f, dict)]
                findings.append(
                    Finding(
                        id=f"DATA-EXP-{idx:02d}",
                        title=f"Excessive Data Exposure ({ana.get('severity', 'HIGH')})" if is_vuln else "Sanitized Data Response",
                        description=(
                            f"Endpoint returns sensitive fields ({', '.join(leaked_fields)}) without DTO filtering."
                            if is_vuln
                            else f"Endpoint returns sanitized response payload (HTTP {status_code})."
                        ),
                        severity=ana.get("severity", "HIGH") if is_vuln else "INFO",
                        endpoint=ep_path,
                        method=ep_method,
                        owasp_category="API3:2023 - Excessive Data Exposure",
                        cwe="CWE-213: Exposure of Sensitive Information Due to Incompatible Policies",
                        evidence=(
                            f"Response payload exposed {len(leaked_fields)} sensitive field(s): {', '.join(leaked_fields)}"
                            if is_vuln
                            else f"Clean response payload (HTTP {status_code})"
                        ),
                        status_code=status_code,
                        reproduction_curl=ana.get("poc_curl"),
                        remediation="Implement response DTOs / projections to filter out internal or PII attributes before serialization.",
                        is_vulnerable=is_vuln,
                    )
                )

    # 3. Standard Object Finding Converters (Auth Misconfig, Rate Limiting, BFLA, Sec Misconfig, Shadow/Zombie)
    else:
        for idx, item in enumerate(raw_output, 1):
            is_dict = isinstance(item, dict)
            is_vuln = item.get("is_vulnerable", False) if is_dict else getattr(item, "is_vulnerable", False)
            status_code = item.get("status_code", None) if is_dict else getattr(item, "status_code", None)
            reason = item.get("reason", item.get("description", "")) if is_dict else getattr(item, "reason", getattr(item, "description", ""))
            endpoint = item.get("endpoint", item.get("path", "/route")) if is_dict else getattr(item, "endpoint", getattr(item, "path", "/route"))
            method = item.get("method", "GET") if is_dict else getattr(item, "method", "GET")
            test_id = item.get("test_id", item.get("id", f"{mod_id.upper()}-{idx:02d}")) if is_dict else getattr(item, "test_id", getattr(item, "id", f"{mod_id.upper()}-{idx:02d}"))
            test_name = item.get("test_name", item.get("title", mod["name"])) if is_dict else getattr(item, "test_name", getattr(item, "title", mod["name"]))
            severity = item.get("severity", "HIGH" if is_vuln else "INFO") if is_dict else getattr(item, "severity", "HIGH" if is_vuln else "INFO")
            cwe = item.get("cwe") if is_dict else getattr(item, "cwe", None)
            repro_curl = item.get("reproduction_curl") if is_dict else getattr(item, "reproduction_curl", None)
            remed = item.get("remediation") if is_dict else getattr(item, "remediation", None)
            target_url = item.get("target_url", f"{base_url}{endpoint}") if is_dict else getattr(item, "target_url", f"{base_url}{endpoint}")

            # Specific check for Rate Limiting burst total failure
            is_rate_limit_fail = False
            if mod_id == "rate_limiting":
                prim_status = item.get("primary_status", -1) if is_dict else getattr(item, "primary_status", -1)
                deliv_cnt = item.get("delivered_count", -1) if is_dict else getattr(item, "delivered_count", -1)
                if prim_status == 0 or deliv_cnt == 0 or "Connection Error" in str(reason):
                    is_rate_limit_fail = True

            is_probe_failure = (
                status_code == 0
                or is_rate_limit_fail
                or str(test_id) == "SEC-00-CONN-ERR"
                or "Connection Error" in str(reason)
                or "Probe failed to reach" in str(reason)
            )

            if is_probe_failure:
                failed_probes += 1
                probe_errors.append(
                    ProbeError(
                        endpoint=str(endpoint),
                        method=str(method).upper(),
                        error_message=str(reason or "Probe connection error"),
                        target_url=str(target_url),
                        status_code=status_code or 0,
                    )
                )
                findings.append(
                    Finding(
                        id=str(test_id),
                        title=str(test_name),
                        description=str(reason),
                        severity="INFO",
                        endpoint=str(endpoint),
                        method=str(method).upper(),
                        owasp_category=mod["owasp"],
                        cwe=str(cwe) if cwe else None,
                        evidence=f"Connection Error: {reason}",
                        status_code=status_code or 0,
                        reproduction_curl=str(repro_curl) if repro_curl else None,
                        remediation=str(remed) if remed else None,
                        is_vulnerable=False,
                    )
                )
            else:
                successful_probes += 1
                findings.append(
                    Finding(
                        id=str(test_id),
                        title=str(test_name),
                        description=str(reason),
                        severity=str(severity),
                        endpoint=str(endpoint),
                        method=str(method).upper(),
                        owasp_category=mod["owasp"],
                        cwe=str(cwe) if cwe else None,
                        evidence=str(reason) if is_vuln else f"Passed: HTTP {status_code}",
                        status_code=status_code,
                        reproduction_curl=str(repro_curl) if repro_curl else None,
                        remediation=str(remed) if remed else None,
                        is_vulnerable=bool(is_vuln),
                    )
                )

    return ScanResult(
        scanner_id=mod_id,
        scanner_name=mod["name"],
        owasp_category=mod["owasp"],
        planned_probes=planned_probes,
        successful_probes=successful_probes,
        failed_probes=failed_probes,
        findings=findings,
        probe_errors=probe_errors,
        errors=errors,
        duration_seconds=duration_seconds,
    )


def render_master_summary_dashboard(master_result: MasterScanResult):
    """Renders a clear, truthful audit dashboard showing exact vulnerability counts and probe coverage per module."""
    console.print()
    console.print()

    separator = "━" * 80
    console.print(f"[bold red]{separator}[/bold red]")

    summary = Table(
        title="[bold red]⚡ SENTINELAPI MASTER SCAN — LIVE AUDIT DASHBOARD ⚡[/bold red]",
        border_style="red",
        header_style="bold cyan",
        padding=(0, 2),
    )
    summary.add_column("#", style="dim", width=3)
    summary.add_column("Security Module", style="bold white")
    summary.add_column("OWASP", style="yellow")
    summary.add_column("Probes (OK / Plan)", justify="center")
    summary.add_column("Vulnerabilities Confirmed", justify="left")
    summary.add_column("Status", justify="center")

    total_checks = 0
    for idx, mod in enumerate(MODULE_REGISTRY, 1):
        mod_res = master_result.module_results.get(mod["id"])
        if not mod_res:
            summary.add_row(str(idx), f"{mod['icon']}  {mod['name']}", mod["owasp"], "-", "[yellow]NOT RUN[/yellow]", "[yellow]SKIPPED[/yellow]")
            continue

        total_checks += mod_res.successful_probes
        vulns = mod_res.vulnerable_findings

        # Coverage string
        if mod_res.failed_probes > 0:
            cov_str = f"[bold green]{mod_res.successful_probes}[/bold green] / {mod_res.planned_probes} [red]({mod_res.failed_probes} err)[/red]"
        else:
            cov_str = f"[bold green]{mod_res.successful_probes}[/bold green] / {mod_res.planned_probes}"

        # Status badge & Findings text based on strict fail-closed state
        st = mod_res.status
        if st == ScanStatus.FAIL.value:
            badge = "[bold red]FAIL (VULNERABLE)[/bold red]"
            finding_text = f"[bold red]{len(vulns)} Finding(s)[/bold red] [dim]({mod_res.critical_count} Crit, {mod_res.high_count} High)[/dim]"
        elif st == ScanStatus.ERROR.value:
            badge = "[bold red]ERROR (UNREACHABLE)[/bold red]"
            finding_text = f"[red]Host Unreachable (0/{mod_res.planned_probes} probes succeeded)[/red]"
        elif st == ScanStatus.INCOMPLETE.value:
            badge = "[bold yellow]INCOMPLETE[/bold yellow]"
            if len(vulns) > 0:
                finding_text = f"[bold red]{len(vulns)} Finding(s)[/bold red] [yellow]({mod_res.failed_probes} probes failed)[/yellow]"
            else:
                finding_text = f"[yellow]0 Vulns, but {mod_res.failed_probes} probes failed[/yellow]"
        else:  # PASS
            badge = "[bold green]PASS (SECURE)[/bold green]"
            finding_text = "[bold green]✓ 0 Vulnerabilities (All Verified)[/bold green]"

        summary.add_row(
            str(idx),
            f"{mod['icon']}  {mod['name']}",
            mod["owasp"],
            cov_str,
            finding_text,
            badge,
        )

    console.print(summary)

    # Master Verdict based on master_result.status
    total_vulns = len(master_result.all_vulnerable_findings)
    mst = master_result.status
    if mst == ScanStatus.FAIL.value:
        verdict = f"[bold red]CRITICAL ALERT: {total_vulns} ACTIVE VULNERABILITY FINDINGS IDENTIFIED[/bold red]"
        border_col = "red"
        status_badge = "[bold red]FAIL[/bold red]"
    elif mst == ScanStatus.ERROR.value:
        verdict = "[bold red]FATAL ERROR: TARGET HOST UNREACHABLE OR 0 PROBES SUCCEEDED (AUDIT FAILED CLOSED)[/bold red]"
        border_col = "red"
        status_badge = "[bold red]ERROR (UNREACHABLE)[/bold red]"
    elif mst == ScanStatus.INCOMPLETE.value:
        verdict = f"[bold yellow]WARNING: INCOMPLETE COVERAGE — {master_result.total_failed_probes} PROBES FAILED (CANNOT CERTIFY AS SECURE)[/bold yellow]"
        border_col = "yellow"
        status_badge = "[bold yellow]INCOMPLETE[/bold yellow]"
    else:  # PASS
        verdict = "[bold green]EXCELLENT: ALL EVALUATED ROUTES PASSED ZERO-TRUST BOUNDARY CHECKS[/bold green]"
        border_col = "green"
        status_badge = "[bold green]PASS (ALL PROBES VERIFIED)[/bold green]"

    console.print()
    console.print(
        Panel(
            f"[bold white]Target API:[/bold white]          [bold cyan]{master_result.target_title}[/bold cyan]\n"
            f"[bold white]Base URL:[/bold white]            [yellow]{master_result.base_url}[/yellow]\n"
            f"[bold white]Probe Coverage:[/bold white]      {master_result.total_successful_probes}/{master_result.total_planned_probes} successful probes ({master_result.total_failed_probes} failed)\n"
            f"[bold white]Audit Outcome:[/bold white]       {status_badge}  [dim](CI Exit Code: {master_result.exit_code})[/dim]\n"
            f"[bold white]Total Vulnerabilities:[/bold white] [bold red]{total_vulns}[/bold red] "
            f"([bold magenta]{master_result.total_critical} Critical[/bold magenta], [bold red]{master_result.total_high} High[/bold red], [bold yellow]{master_result.total_medium} Medium[/bold yellow], [bold blue]{master_result.total_low} Low[/bold blue])\n"
            f"[bold white]Final Assessment:[/bold white]     {verdict}",
            title="[bold red]⚡ MASTER SECURITY AUDIT POSTURE ⚡[/bold red]",
            border_style=border_col,
            padding=(1, 2),
        )
    )
    console.print(f"[bold red]{separator}[/bold red]")


def _build_rich_telemetry_prompt(
    spec: ParsedSpecification,
    config: Dict[str, Any],
    master_result: MasterScanResult,
) -> str:
    """Builds a comprehensive, context-dense prompt containing ALL real live telemetry from all 7 modules."""
    lines = [
        f"# SENTINELAPI MASTER SECURITY ASSESSMENT REPORT: {spec.title}",
        f"- Target Base URL: {config['base_url']}",
        f"- Specification: {spec.spec_type} (Version: {spec.version})",
        f"- Auth Scheme: {spec.auth_scheme}",
        f"- Total Endpoints in Inventory: {len(spec.endpoints)}",
        f"- Parameterized Routes: {len(spec.parameterized_endpoints)}",
        f"- Assessment Status: {master_result.status} (Exit Code: {master_result.exit_code})",
        f"- Probe Coverage: {master_result.total_successful_probes}/{master_result.total_planned_probes} succeeded ({master_result.total_failed_probes} probe errors)",
        f"- Total Vulnerabilities Found: {len(master_result.all_vulnerable_findings)}",
        "",
    ]

    # Critical context injection to prevent AI hallucinations:
    if master_result.status == ScanStatus.ERROR.value or master_result.total_successful_probes == 0:
        lines.extend([
            "### CRITICAL AUDIT STATUS: TARGET UNREACHABLE / AUDIT FAILED CLOSED",
            "WARNING: The target API server was unreachable or offline during this assessment (0 successful HTTP probes).",
            "You MUST NOT state that the API is secure, safe, or passed testing.",
            "You MUST state clearly that the assessment failed closed because the target host was unreachable,",
            "explaining that SentinelAPI refuses to grant a false clean bill of health when no live tests could execute.",
            "",
        ])
    elif master_result.status == ScanStatus.INCOMPLETE.value:
        lines.extend([
            "### AUDIT STATUS: INCOMPLETE COVERAGE",
            f"WARNING: {master_result.total_failed_probes} probes failed due to network connectivity issues.",
            "You MUST state that coverage is incomplete and that the API cannot be certified as fully secure.",
            "",
        ])

    lines.append("## DETAILED LIVE TEST FINDINGS BY OWASP CATEGORY:")

    for mod in MODULE_REGISTRY:
        mod_res = master_result.module_results.get(mod["id"])
        if not mod_res:
            continue

        lines.append(f"\n### [{mod['owasp']}] {mod['name']}")
        lines.append(f"- Module Status: {mod_res.status}")
        lines.append(f"- Probes Succeeded: {mod_res.successful_probes}/{mod_res.planned_probes} (Failed: {mod_res.failed_probes})")
        lines.append(f"- Vulnerabilities Confirmed: {len(mod_res.vulnerable_findings)}")

        if mod_res.probe_errors:
            lines.append("  Probe Errors / Unreachable Endpoints:")
            for pe in mod_res.probe_errors[:5]:
                lines.append(f"  - {pe.method} {pe.endpoint}: {pe.error_message}")

        if not mod_res.findings:
            lines.append("  (No findings recorded)")
            continue

        for idx, f in enumerate(mod_res.findings, 1):
            if f.is_vulnerable:
                lines.append(f"  {idx}. [FAIL - {f.severity}] {f.method} {f.endpoint} -> {f.title}")
                lines.append(f"     Evidence: {f.evidence}")
                if f.cwe:
                    lines.append(f"     CWE: {f.cwe}")
            elif f.status_code == 0 or "Error" in f.title:
                lines.append(f"  {idx}. [PROBE ERROR] {f.method} {f.endpoint} -> {f.title} ({f.evidence})")
            else:
                lines.append(f"  {idx}. [PASS] {f.method} {f.endpoint} -> {f.title} ({f.evidence})")

    lines.extend([
        "",
        "## INSTRUCTIONS FOR MASTER AI SECURITY REPORT:",
        "You are SentinelAPI Core Security Intelligence Engine. Analyze the REAL LIVE findings above.",
        "Produce an authoritative, complete, comprehensive security intelligence report in structured GitHub Markdown.",
        "Ensure ALL sections below are thoroughly detailed without stopping halfway:",
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


def generate_and_render_ai_master_report(
    spec: ParsedSpecification,
    config: Dict[str, Any],
    master_result: MasterScanResult,
) -> Optional[str]:
    """Streams and renders the comprehensive AI master report with 4000 token budget."""
    console.print()

    prompt_text = _build_rich_telemetry_prompt(spec, config, master_result)

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
            return None

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
            return response_text
        else:
            console.print(f"\n[bold yellow]⚠ AI report generation failed:[/bold yellow] {response_text}")
            return None

    except Exception as e:
        console.print(f"\n[bold red]✖ AI engine error:[/bold red] {str(e)}")
        return None


def _save_scan_artifacts(master_result: MasterScanResult):
    """Saves both human-readable Markdown and machine-readable JSON artifacts."""
    MARKDOWN_DIR.mkdir(parents=True, exist_ok=True)
    timestamp = time.strftime("%Y%m%d_%H%M%S")

    # 1. Save Structured JSON for CI/CD & tools
    json_path = MARKDOWN_DIR / f"master_scan_results_{timestamp}.json"
    try:
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(master_result.to_dict(), f, indent=2)
        console.print(f"[bold green]✓[/bold green] Machine-readable JSON saved → [bold cyan]{json_path}[/bold cyan]")
    except Exception as e:
        console.print(f"[dim yellow]Warning: Could not save JSON report: {e}[/dim yellow]")

    # 2. Save Markdown Report
    md_path = MARKDOWN_DIR / f"master_scan_report_{timestamp}.md"
    try:
        with open(md_path, "w", encoding="utf-8") as f:
            f.write(f"# SentinelAPI Full-Suite Security Assessment Report\n")
            f.write(f"**Target:** {master_result.target_title} ({master_result.base_url})\n")
            f.write(f"**Generated:** {master_result.start_time}\n")
            f.write(f"**Total Vulnerabilities:** {len(master_result.all_vulnerable_findings)}\n\n")

            if master_result.ai_report_markdown:
                f.write(master_result.ai_report_markdown)
            else:
                f.write("## Live Vulnerability Findings Summary\n\n")
                for mod_id, mod_res in master_result.module_results.items():
                    f.write(f"### {mod_res.scanner_name} ({mod_res.owasp_category})\n")
                    for finding in mod_res.findings:
                        status_str = "VULNERABLE" if finding.is_vulnerable else "PROTECTED"
                        f.write(f"- [{status_str}] `{finding.method} {finding.endpoint}`: {finding.title} — {finding.evidence}\n")
                    f.write("\n")

        console.print(f"[bold green]✓[/bold green] Complete Markdown report saved → [bold cyan]{md_path}[/bold cyan]")
    except Exception as e:
        console.print(f"[dim yellow]Warning: Could not save Markdown report: {e}[/dim yellow]")
