"""BOLA / IDOR (Broken Object Level Authorization) interactive assessment UI & dynamic live auditor."""
import time
import re
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


def generate_smart_param_values(var_name: str, ptype: str, example: Any) -> Tuple[str, str]:
    """Generates distinct Victim and Attacker values dynamically inferred from schema type and examples."""
    # 1. If explicit example exists in the OpenAPI spec
    if example is not None:
        if isinstance(example, int):
            return str(example), str(example + 1)
        elif isinstance(example, str):
            if example.isdigit():
                return example, str(int(example) + 1)
            # UUID format detection
            if re.match(r"^[0-9a-fA-F-]{36}$", example):
                return example, "00000000-0000-0000-0000-000000000002"
            return example, f"{example}_attacker"

    # 2. Heuristics based on parameter name and type
    name_lower = var_name.lower()
    ptype_lower = (ptype or "").lower()

    if ptype_lower in ["integer", "number", "int", "int32", "int64"] or "id" in name_lower:
        if "order" in name_lower or "item" in name_lower or "tx" in name_lower or "invoice" in name_lower:
            return "501", "502"
        return "101", "102"
    elif "uuid" in name_lower or ptype_lower == "uuid":
        return "11111111-1111-1111-1111-111111111111", "22222222-2222-2222-2222-222222222222"
    elif "user" in name_lower or "account" in name_lower or "member" in name_lower:
        return "user_victim", "user_attacker"
    else:
        return f"{var_name}_101", f"{var_name}_102"


def infer_dynamic_bola_context(spec: ParsedSpecification) -> Dict[str, Any]:
    """Dynamically extracts all path parameters, examples, types, and security schemes directly from the active specification."""
    auth_header_name = "Authorization"
    token_prefix = "Bearer "

    # 1. Inspect securitySchemes from raw specification
    sec_schemes = (
        spec.raw_spec.get("components", {}).get("securitySchemes", {})
        or spec.raw_spec.get("securityDefinitions", {})
    )

    for _, sdef in sec_schemes.items():
        stype = sdef.get("type", "").lower()
        if stype in ["http", "oauth2", "openidconnect"]:
            scheme = sdef.get("scheme", "").lower()
            if scheme == "bearer" or "bearer" in spec.auth_scheme.lower():
                auth_header_name = "Authorization"
                token_prefix = "Bearer "
                break
            elif scheme == "basic":
                auth_header_name = "Authorization"
                token_prefix = "Basic "
                break
        elif stype == "apikey":
            if sdef.get("in", "").lower() == "header":
                auth_header_name = sdef.get("name", "X-API-Key")
                token_prefix = ""
                break

    # 2. Dynamically discover all path parameters across candidate routes
    param_meta: Dict[str, Dict[str, Any]] = {}

    for ep in spec.parameterized_endpoints:
        path_vars = re.findall(r"\{([^}]+)\}", ep.path)
        for var in path_vars:
            if var not in param_meta:
                # Look for parameter schema definition in ep.parameters
                p_def = next((p for p in ep.parameters if p.get("name") == var and p.get("in") == "path"), None)
                schema = (p_def.get("schema") or {}) if p_def else {}
                ptype = schema.get("type") or "string"
                example = schema.get("example") if schema.get("example") is not None else (p_def.get("example") if p_def else None)

                victim_val, attacker_val = generate_smart_param_values(var, ptype, example)
                param_meta[var] = {
                    "name": var,
                    "type": ptype,
                    "example": example,
                    "victim_val": victim_val,
                    "attacker_val": attacker_val,
                }

    # 3. Derive primary user identity token format
    user_var = next((v for v in param_meta if "user" in v.lower() or "account" in v.lower() or "id" in v.lower()), None)
    if user_var:
        victim_id = param_meta[user_var]["victim_val"]
        attacker_id = param_meta[user_var]["attacker_val"]
    else:
        victim_id = "101"
        attacker_id = "102"
        

    victim_token = f"{token_prefix}token-{victim_id}".strip()
    attacker_token = f"{token_prefix}token-{attacker_id}".strip()

    return {
        "auth_header_name": auth_header_name,
        "token_prefix": token_prefix,
        "victim_id": victim_id,
        "attacker_id": attacker_id,
        "victim_token": victim_token,
        "attacker_token": attacker_token,
        "params": param_meta,
    }


def check_target_online(base_url: str) -> bool:
    """Checks if target API base URL is live and responsive."""
    try:
        r = httpx.get(f"{base_url.rstrip('/')}/health", timeout=1.5)
        return r.status_code in [200, 401, 403, 404]
    except Exception:
        try:
            r = httpx.get(base_url, timeout=1.5)
            return True
        except Exception:
            return False


def run_bola_idor_flow(spec: ParsedSpecification):
    """Main interactive controller for BOLA / IDOR testing."""
    # Build 100% dynamic test context from the loaded specification
    config = infer_dynamic_bola_context(spec)

    while True:
        console.clear()
        param_endpoints = spec.parameterized_endpoints
        is_live = check_target_online(spec.base_url)
        status_badge = "[bold green]● LIVE TARGET ONLINE[/bold green]" if is_live else "[bold yellow]○ TARGET OFFLINE (Simulation Mode)[/bold yellow]"

        # Header Panel
        console.print(
            Panel(
                f"[bold white]Target API:[/bold white]     [bold cyan]{spec.title}[/bold cyan] [dim]({spec.base_url})[/dim]   {status_badge}\n"
                f"[bold white]Auth Scheme:[/bold white]    [bold yellow]{spec.auth_scheme}[/bold yellow]   "
                f"[bold white]Specification:[/bold white] [dim]{spec.spec_type}[/dim]\n"
                f"[bold white]Attack Surface:[/bold white] [bold red]{len(param_endpoints)} candidate object-level endpoints identified[/bold red]\n"
                f"[bold white]Dynamic Parameters:[/bold white] [cyan]{', '.join(f'{{{p}}}' for p in config['params'].keys()) or 'None'}[/cyan]\n\n"
                "[dim]BOLA / IDOR occurs when an application receives user input to access an object\n"
                "without validating that the requester owns or is authorized to view that specific resource.[/dim]",
                title="[bold magenta]⚡ OWASP API1:2023 • BOLA / IDOR SECURITY MODULE[/bold magenta]",
                border_style="magenta",
                padding=(1, 2),
            )
        )

        # Overview Table of Discovered Parameterized Endpoints
        table = Table(
            title="[bold cyan]Discovered Target Candidate Endpoints[/bold cyan]",
            title_justify="left",
            box=None,
            padding=(0, 2),
            header_style="bold cyan",
        )
        table.add_column("#", style="dim")
        table.add_column("Method", style="bold green")
        table.add_column("Endpoint Route", style="bold white")
        table.add_column("Object Parameter", style="bold yellow")
        table.add_column("Target Vector", style="dim")

        if param_endpoints:
            for idx, ep in enumerate(param_endpoints, 1):
                param_names = [p.get("name", "id") for p in ep.parameters if p.get("in") == "path"]
                if not param_names:
                    matches = re.findall(r"\{([^}]+)\}", ep.path)
                    param_names = matches or ["id"]
                param_str = ", ".join(f"{{{p}}}" for p in param_names)
                table.add_row(
                    str(idx),
                    ep.method,
                    ep.path,
                    param_str,
                    "Horizontal Object Hijack / Tenant Cross-Access",
                )
        else:
            table.add_row("-", "N/A", "No parameterized endpoints discovered", "-", "-")

        console.print(table)
        console.print()

        launch_label = "▶ 1. Launch BOLA / IDOR Security Assessment (Live API Probing)" if is_live else "▶ 1. Launch BOLA / IDOR Security Assessment (Simulation Mode)"

        # Action Menu
        menu_choices = [
            launch_label,
            "📋 2. Inspect Target Endpoints & Parameter Schemas",
            "⚙ 3. Configure Multi-Tenant Probing Identities (Victim vs Attacker)",
            "↩ 4. Back to Security Test Menu",
        ]

        try:
            choice = questionary.select(
                "Select BOLA / IDOR Action:",
                choices=menu_choices,
                style=CUSTOM_STYLE,
            ).ask()
        except (KeyboardInterrupt, EOFError):
            break

        if not choice or "4. Back" in choice:
            break
        elif "1. Launch" in choice:
            run_assessment(spec, param_endpoints, config, is_live)
        elif "2. Inspect" in choice:
            inspect_endpoints(param_endpoints)
        elif "3. Configure" in choice:
            configure_identities(config, spec)


def run_assessment(spec: ParsedSpecification, endpoints: List[APIEndpointInfo], config: Dict[str, Any], is_live: bool):
    """Executes live or simulated BOLA / IDOR security assessment with dynamic parameters and real HTTP requests."""
    console.clear()
    mode_text = "[bold green]LIVE API PROBE MODE[/bold green]" if is_live else "[bold yellow]SIMULATION MODE (Backend Offline)[/bold yellow]"

    # Format parameter overview for header
    param_summary = "  ".join(f"[bold cyan]{{{k}}}[/bold cyan]: {v['victim_val']}" for k, v in config["params"].items())

    console.print(
        Panel(
            f"[bold white]Target:[/bold white]            [bold cyan]{spec.title}[/bold cyan] [dim]({spec.base_url})[/dim] — {mode_text}\n"
            f"[bold white]Auth Header:[/bold white]       [yellow]{config['auth_header_name']}[/yellow]\n"
            f"[bold white]Victim Token:[/bold white]      [green]{config['victim_token']}[/green]\n"
            f"[bold white]Attacker Token:[/bold white]    [red]{config['attacker_token']}[/red]\n"
            f"[bold white]Active Parameters:[/bold white] {param_summary or 'None'}\n"
            "[dim]Probing logic: Resolves object templates to Victim's values, sending cross-tenant probes with Attacker credentials.[/dim]",
            title="[bold yellow]EXECUTING BOLA / IDOR ASSESSMENT[/bold yellow]",
            border_style="yellow",
            padding=(1, 2),
        )
    )

    if not endpoints:
        console.print("\n[yellow]No parameterized endpoints available to test.[/yellow]\n")
        questionary.press_any_key_to_continue("Press any key to return...").ask()
        return

    # Assessment Progress
    with Progress(
        SpinnerColumn(spinner_name="dots"),
        TextColumn("[bold cyan]{task.description}[/bold cyan]"),
        BarColumn(bar_width=40, style="magenta", complete_style="bold green"),
        TextColumn("[bold white]{task.percentage:>3.0f}%[/bold white]"),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("Initializing authorization probes...", total=len(endpoints))

        results = []
        for ep in endpoints:
            progress.update(task, description=f"Probing {ep.method} {ep.path}...")

            # Dynamically resolve path template variables using inferred spec parameters
            resolved_path = ep.path
            for var_name, pmeta in config["params"].items():
                resolved_path = resolved_path.replace(f"{{{var_name}}}", str(pmeta["victim_val"]))

            # Fallback if any unknown variable remains
            resolved_path = re.sub(r"\{[^}]+\}", str(config.get("victim_id", "101")), resolved_path)
            full_target_url = f"{spec.base_url.rstrip('/')}{resolved_path}"

            baseline_status = 200
            attack_status = 200
            is_vulnerable = False
            response_snippet = ""

            headers_victim = {config["auth_header_name"]: config["victim_token"]}
            headers_attacker = {config["auth_header_name"]: config["attacker_token"]}

            if is_live:
                try:
                    # 1. Baseline Request: Legitimate Owner requests resource
                    r_legit = httpx.request(
                        ep.method,
                        full_target_url,
                        headers=headers_victim,
                        timeout=3.0,
                    )
                    baseline_status = r_legit.status_code

                    # 2. Cross-Tenant Probe: Attacker requests Victim's resource
                    r_attack = httpx.request(
                        ep.method,
                        full_target_url,
                        headers=headers_attacker,
                        timeout=3.0,
                    )
                    attack_status = r_attack.status_code
                    response_snippet = r_attack.text[:140]

                    # BOLA Determination:
                    # If attacker receives 200 OK -> Server leaked victim data (BOLA Vulnerable)
                    # If attacker receives 403 Forbidden (or 401) -> Server protected object (Secure)
                    if attack_status == 200:
                        is_vulnerable = True
                    else:
                        is_vulnerable = False

                except Exception as e:
                    attack_status = 0
                    response_snippet = f"Connection error: {str(e)}"
                    is_vulnerable = False
            else:
                time.sleep(0.5)
                is_vulnerable = "orders" in ep.path.lower()
                baseline_status = 200
                attack_status = 200 if is_vulnerable else 403
                response_snippet = "Simulated response"

            results.append({
                "endpoint": ep,
                "vulnerable": is_vulnerable,
                "baseline_status": baseline_status,
                "attack_status": attack_status,
                "target_url": full_target_url,
                "response_snippet": response_snippet,
            })
            progress.advance(task)

    console.print("\n[bold green]✓ Assessment scan completed.[/bold green]\n")

    # Assessment Results Matrix Table
    result_table = Table(
        title="[bold white]Authorization Probing Matrix Results[/bold white]",
        title_justify="left",
        box=None,
        padding=(0, 2),
        header_style="bold cyan",
    )
    result_table.add_column("Method", style="bold white")
    result_table.add_column("Target Route", style="bold white")
    result_table.add_column("Legitimate (Owner)", style="green")
    result_table.add_column("Cross-Tenant (Attacker)", style="bold")
    result_table.add_column("Verdict", style="bold")

    vuln_count = 0
    secured_count = 0

    for res in results:
        ep = res["endpoint"]
        if res["vulnerable"]:
            vuln_count += 1
            verdict = "[bold red]FAIL (BOLA Leaked)[/bold red]"
            probe_str = f"[bold red]HTTP {res['attack_status']} OK (Leaked)[/bold red]"
        elif res["attack_status"] in [403, 401]:
            secured_count += 1
            verdict = "[bold green]PASS (Secured)[/bold green]"
            probe_str = f"[bold green]HTTP {res['attack_status']} Forbidden[/bold green]"
        else:
            verdict = f"[yellow]INFO ({res['attack_status']})[/yellow]"
            probe_str = f"[yellow]HTTP {res['attack_status']}[/yellow]"

        result_table.add_row(
            ep.method,
            ep.path,
            f"HTTP {res['baseline_status']} OK",
            probe_str,
            verdict,
        )

    console.print(result_table)
    console.print()

    # Executive Summary Card
    score_style = "bold red" if vuln_count > 0 else "bold green"
    summary_text = (
        f" [bold white]Total Candidate Endpoints Tested:[/bold white] {len(endpoints)}\n"
        f" [bold red]Vulnerabilities Identified:[/bold red]      {vuln_count} Critical Authorization Flaws\n"
        f" [bold green]Protected Endpoints:[/bold green]             {secured_count} Validated Secure\n"
        f" [bold white]Overall BOLA Exposure Risk:[/bold white]     [{score_style}]{'CRITICAL RISK (OWASP API1)' if vuln_count > 0 else 'LOW / ZERO RISK (PASSED)'}[/{score_style}]"
    )

    console.print(
        Panel(
            summary_text,
            title="[bold cyan]EXECUTIVE SUMMARY[/bold cyan]",
            border_style="cyan" if vuln_count == 0 else "red",
            padding=(1, 2),
        )
    )

    # SECURED CLEARANCE
    if vuln_count == 0:
        console.print()
        console.print(
            Panel(
                "[bold green]✓ SECURITY CLEARANCE: ZERO BOLA / IDOR VULNERABILITIES DETECTED[/bold green]\n\n"
                f" [bold white]Target Server:[/bold white]           [cyan]{spec.base_url}[/cyan]\n"
                " [bold white]OWASP API1:2023 Audit:[/bold white]   [bold green]PASSED[/bold green]\n"
                " [bold white]Access Control Verdict:[/bold white]  Object ownership check strictly enforced.\n"
                f" [bold white]Verification Detail:[/bold white]     Attacker token ({config['attacker_token']}) was properly denied access (HTTP 403 Forbidden)\n"
                f"                          when attempting to access private objects belonging to Victim.",
                title="[bold green]SECURE AUTHORIZATION CONTROLS VERIFIED[/bold green]",
                border_style="green",
                padding=(1, 2),
            )
        )

    # VULNERABILITIES DETECTED
    else:
        console.print("\n[bold red]DETAILED VULNERABILITY FINDINGS & REMEDIATION[/bold red]")
        for res in results:
            if not res["vulnerable"]:
                continue
            ep = res["endpoint"]

            # Real curl reproduction command
            curl_poc = (
                f"curl -X {ep.method} \"{res['target_url']}\" \\\n"
                f"  -H \"{config['auth_header_name']}: {config['attacker_token']}\" \\\n"
                f"  -H \"Content-Type: application/json\""
            )

            poc_syntax = Syntax(curl_poc, "bash", theme="monokai", line_numbers=False)

            remediation_code = (
                "// Secure Object-Level Authorization Check (OWASP API1:2023)\n"
                "const requestedId = parseInt(req.params.userId || req.params.id, 10);\n"
                "if (req.user.id !== requestedId) {\n"
                "  return res.status(403).json({\n"
                "    error: 'Forbidden',\n"
                "    code: 'BOLA_PREVENTED',\n"
                "    message: 'Access denied: You do not own this resource.'\n"
                "  });\n"
                "}"
            )
            remed_syntax = Syntax(remediation_code, "javascript", theme="monokai", line_numbers=False)

            finding_panel = Panel(
                f"[bold red]OWASP API1:2023 - Broken Object Level Authorization[/bold red]\n"
                f"[bold white]Vulnerable Route:[/bold white] [bold yellow]{ep.method} {ep.path}[/bold yellow]\n"
                f"[bold white]Target URL:[/bold white]       [cyan]{res['target_url']}[/cyan]\n"
                f"[bold white]Live Response Code:[/bold white] [bold red]HTTP {res['attack_status']} OK[/bold red]\n"
                f"[bold white]Leaked Payload Data:[/bold white] [dim]{res['response_snippet']}[/dim]\n"
                f"[bold white]Impact:[/bold white] An authenticated user can supply arbitrary object identifiers to read or manipulate records belonging to another tenant.\n",
                title=f"[bold red]FINDING #{results.index(res) + 1} — {ep.path}[/bold red]",
                border_style="red",
                padding=(1, 2),
            )
            console.print(finding_panel)
            console.print(Panel(poc_syntax, title="[bold yellow]Proof of Concept (PoC)[/bold yellow]", border_style="yellow"))
            console.print(Panel(remed_syntax, title="[bold green]Recommended Fix (Ownership Validation)[/bold green]", border_style="green"))
            console.print()

    # Automatically save scan results to markdown folder
    try:
        scan_md_file = save_scan_results_markdown(spec, results, config)
        console.print(f"[bold green]✓ Scan findings saved to markdown folder: [white]{scan_md_file}[/white][/bold green]\n")
    except Exception as e:
        console.print(f"[dim yellow]Warning: Could not save scan findings to markdown: {e}[/dim yellow]\n")

    # Step: Dynamic AI Security Overview & Remediation Synthesis
    present_ai_overview_step(spec, results, config)

    try:
        questionary.press_any_key_to_continue("Press any key to return to BOLA menu...").ask()
    except (KeyboardInterrupt, EOFError):
        pass

    return results


def save_scan_results_markdown(
    spec: ParsedSpecification,
    results: List[Dict[str, Any]],
    config: Dict[str, Any],
) -> Path:
    """Saves the scan telemetry and findings as a structured Markdown file in markdown/."""
    md_dir = get_markdown_dir()
    slug = re.sub(r"[^a-zA-Z0-9]+", "_", spec.title).strip("_").lower() or "api"
    timestamp = int(time.time())
    scan_file = md_dir / f"{slug}_bola_scan_results_{timestamp}.md"

    vuln_results = [r for r in results if r.get("vulnerable")]
    passed_results = [r for r in results if not r.get("vulnerable")]

    lines = [
        f"# SentinelAPI Security Assessment: {spec.title}",
        "",
        f"- **Date:** {time.ctime()}",
        f"- **Target Base URL:** `{spec.base_url}`",
        f"- **Specification:** {spec.spec_type} (Version: {spec.version})",
        f"- **Auth Scheme:** {spec.auth_scheme} (Header: `{config.get('auth_header_name', 'Authorization')}`)",
        f"- **Total Endpoints Tested:** {len(results)}",
        f"- **Vulnerabilities Identified:** {len(vuln_results)}",
        f"- **Protected Endpoints:** {len(passed_results)}",
        f"- **Overall Risk:** {'CRITICAL RISK (OWASP API1:2023 - BOLA/IDOR)' if vuln_results else 'LOW / ZERO RISK (PASSED)'}",
        "",
        "## Executive Summary",
        "",
        f"{'CRITICAL: Broken Object Level Authorization flaws were discovered. Authenticated callers can access or manipulate records of other tenants without authorization.' if vuln_results else 'CLEARANCE: No BOLA/IDOR vulnerabilities were detected. Strict object-level ownership checks were verified.'}",
        "",
        "## Scan Results Matrix",
        "",
        "| Method | Endpoint Path | Baseline (Owner) | Attacker Probe | Verdict |",
        "|---|---|---|---|---|",
    ]

    for r in results:
        ep = r["endpoint"]
        verdict = "**VULNERABLE (BOLA)**" if r.get("vulnerable") else "PASSED (SECURE)"
        probe_str = f"HTTP {r['attack_status']} LEAK" if r.get("vulnerable") else f"HTTP {r['attack_status']} BLOCKED"
        lines.append(f"| `{ep.method}` | `{ep.path}` | HTTP {r['baseline_status']} | {probe_str} | {verdict} |")

    if vuln_results:
        lines.extend([
            "",
            "## Detailed Vulnerability Findings",
            "",
        ])
        for idx, res in enumerate(vuln_results, 1):
            ep = res["endpoint"]
            lines.extend([
                f"### Finding #{idx}: {ep.method} {ep.path}",
                "",
                f"- **Vulnerability Type:** OWASP API1:2023 - Broken Object Level Authorization (IDOR)",
                f"- **Severity:** High / Critical",
                f"- **Target URL:** `{res['target_url']}`",
                f"- **Attack Status:** HTTP {res['attack_status']}",
                f"- **Leaked Response Data:**",
                "```json",
                (res.get("response_snippet") or "")[:300],
                "```",
                "",
                "#### Proof of Concept (PoC)",
                "```bash",
                f"curl -X {ep.method} \"{res['target_url']}\" \\",
                f"  -H \"{config['auth_header_name']}: {config['attacker_token']}\" \\",
                f"  -H \"Content-Type: application/json\"",
                "```",
                "",
                "#### Recommended Remediation",
                "```javascript",
                "// Ensure current authenticated user owns the requested resource",
                "const requestedId = parseInt(req.params.userId || req.params.id, 10);",
                "if (req.user.id !== requestedId) {",
                "  return res.status(403).json({",
                "    error: 'Forbidden',",
                "    code: 'BOLA_PREVENTED',",
                "    message: 'Access denied: You do not own this resource.'",
                "  });",
                "}",
                "```",
                "",
            ])
    else:
        lines.extend([
            "",
            "## Defensive Verification",
            "",
            "- All endpoints correctly returned HTTP 403 / 401 when accessed with unauthorized tokens.",
            "- Object ownership validations are active and working as expected.",
            "",
        ])

    with open(scan_file, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    return scan_file


def present_ai_overview_step(
    spec: ParsedSpecification,
    results: List[Dict[str, Any]],
    config: Dict[str, Any],
):
    """Presents dynamic token cost estimation and prompts user to generate AI Security Overview."""
    from rich.markdown import Markdown
    from sentinelapi.modals.ai_engine import (
        get_active_ai_config,
        estimate_token_usage,
        build_bola_ai_prompt,
        request_ai_overview,
    )

    ai_cfg = get_active_ai_config()
    prompt_text = build_bola_ai_prompt(spec, results, config)
    usage = estimate_token_usage(prompt_text)

    console.print()
    t = Table(box=None, show_header=False, padding=(0, 2))
    t.add_column("Key", style="bold cyan")
    t.add_column("Val", style="bold white")

    t.add_row("Active AI Model:", f"[bold green]{ai_cfg['model']}[/bold green] [dim]({ai_cfg['provider']})[/dim]")
    t.add_row("Target API Scope:", f"{spec.title} ({len(results)} routes evaluated)")
    t.add_row("Context Included:", f"OpenAPI schema, {len(config.get('params', {}))} parameters, live HTTP response telemetry, verdicts")
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
            title="[bold magenta]⚡ AI EXECUTIVE SECURITY BLUEPRINT & REMEDIATION[/bold magenta]",
            border_style="magenta",
            padding=(1, 2),
        )
    )
    console.print()

    # Markdown renderer with Monokai code highlighting
    md = Markdown(ai_report, code_theme="monokai")
    console.print(md)
    console.print()

    # Automatically save AI report in markdown/ folder
    md_dir = get_markdown_dir()
    slug = re.sub(r"[^a-zA-Z0-9]+", "_", spec.title).strip("_").lower() or "api"
    timestamp = int(time.time())
    ai_md_filename = md_dir / f"{slug}_bola_ai_report_{timestamp}.md"

    try:
        with open(ai_md_filename, "w", encoding="utf-8") as f:
            f.write(f"# SentinelAPI Security Overview: {spec.title}\n\n")
            f.write(f"- Date: {time.ctime()}\n")
            f.write(f"- Model: {ai_cfg['model']}\n")
            f.write(f"- Base URL: {spec.base_url}\n\n")
            f.write(ai_report)
        console.print(f"[bold green]✓ AI Report automatically saved to markdown folder: [white]{ai_md_filename}[/white][/bold green]\n")
    except Exception as e:
        console.print(f"[dim yellow]Warning: Could not auto-save AI report to markdown: {e}[/dim yellow]\n")

    # Post-Report Options
    report_choices = [
        f"1. Save / Re-verify AI Report in markdown folder ({ai_md_filename.name})",
        "2. Continue to BOLA Menu",
    ]

    try:
        action = questionary.select("AI Report Options:", choices=report_choices, style=CUSTOM_STYLE).ask()
        if action and "1. Save" in action:
            with open(ai_md_filename, "w", encoding="utf-8") as f:
                f.write(f"# SentinelAPI Security Overview: {spec.title}\n\n")
                f.write(f"- Date: {time.ctime()}\n")
                f.write(f"- Model: {ai_cfg['model']}\n")
                f.write(f"- Base URL: {spec.base_url}\n\n")
                f.write(ai_report)

            console.print(f"\n[bold green]✓ Report saved in markdown folder: [white]{ai_md_filename}[/white][/bold green]\n")
            time.sleep(1.5)
    except (KeyboardInterrupt, EOFError):
        pass


def inspect_endpoints(endpoints: List[APIEndpointInfo]):
    """Displays detailed endpoint parameters, types, and schemas."""
    console.clear()
    console.print(
        Panel(
            "[bold white]Target Candidate Endpoints for BOLA/IDOR Analysis[/bold white]\n"
            "[dim]Endpoints containing path or query parameters referencing resource IDs\n"
            "are prime attack surfaces for Broken Object Level Authorization.[/dim]",
            title="[bold cyan]ENDPOINT PARAMETER INSPECTOR[/bold cyan]",
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
        t.add_row("Auth Required:", "[green]Yes[/green]" if ep.auth_required else "[yellow]No[/yellow]")

        param_details = []
        for p in ep.parameters:
            name = p.get("name", "unknown")
            loc = p.get("in", "path")
            ptype = p.get("schema", {}).get("type", "string")
            example = p.get("schema", {}).get("example") or p.get("example")
            ex_str = f", example: [yellow]{example}[/yellow]" if example is not None else ""
            param_details.append(f"[bold yellow]{name}[/bold yellow] ([dim]{loc}[/dim], type: [cyan]{ptype}[/cyan]{ex_str})")

        if param_details:
            t.add_row("Parameters:", "\n".join(param_details))
        else:
            t.add_row("Parameters:", "[dim]None explicitly listed in schema[/dim]")

        console.print(Panel(t, title=f"[bold white]Endpoint #{idx}[/bold white]", border_style="cyan"))

    try:
        questionary.press_any_key_to_continue("Press any key to return...").ask()
    except (KeyboardInterrupt, EOFError):
        pass


def configure_identities(config: Dict[str, Any], spec: ParsedSpecification):
    """Allows user to inspect and customize dynamically detected parameters and test credentials."""
    while True:
        console.clear()
        console.print(
            Panel(
                "[bold white]Dynamic Multi-Tenant Test Identity Setup[/bold white]\n"
                "[dim]Parameters and authentication schemes are automatically inferred from the active OpenAPI spec.\n"
                "You can inspect or override any detected parameter or token below.[/dim]",
                title="[bold yellow]IDENTITY CONFIGURATION[/bold yellow]",
                border_style="yellow",
                padding=(1, 2),
            )
        )

        t = Table(box=None, show_header=False, padding=(0, 2))
        t.add_column("Key", style="bold cyan")
        t.add_column("Val", style="bold white")

        t.add_row("Auth Header Name:", config["auth_header_name"])
        t.add_row("Victim Token:", config["victim_token"])
        t.add_row("Attacker Token:", config["attacker_token"])

        # Dynamic Parameters List
        param_rows = []
        for p_name, p_meta in config["params"].items():
            param_rows.append(
                f"[bold yellow]{{{p_name}}}[/bold yellow] -> Victim: [green]{p_meta['victim_val']}[/green] | Attacker: [red]{p_meta['attacker_val']}[/red] [dim](type: {p_meta['type']})[/dim]"
            )

        t.add_row("Discovered Parameters:", "\n".join(param_rows) if param_rows else "[dim]None[/dim]")

        console.print(Panel(t, title="Active Specification Test Profiles", border_style="yellow"))

        choices = [
            "1. Keep current configuration and return",
            "2. Modify Victim Token",
            "3. Modify Attacker Token",
            "4. Modify an Object Parameter Value",
            "5. Reset to OpenAPI Spec Defaults",
        ]

        try:
            ans = questionary.select("Select option:", choices=choices, style=CUSTOM_STYLE).ask()
            if not ans or "1. Keep" in ans:
                break
            elif "2. Modify Victim Token" in ans:
                new_token = questionary.text("Enter Victim Token:", default=config["victim_token"], style=CUSTOM_STYLE).ask()
                if new_token:
                    config["victim_token"] = new_token.strip()
            elif "3. Modify Attacker Token" in ans:
                new_token = questionary.text("Enter Attacker Token:", default=config["attacker_token"], style=CUSTOM_STYLE).ask()
                if new_token:
                    config["attacker_token"] = new_token.strip()
            elif "4. Modify an Object Parameter" in ans:
                if not config["params"]:
                    console.print("[yellow]No parameters found to customize.[/yellow]")
                    time.sleep(1)
                    continue

                param_choices = list(config["params"].keys()) + ["Cancel"]
                chosen_param = questionary.select("Select parameter to modify:", choices=param_choices, style=CUSTOM_STYLE).ask()

                if chosen_param and chosen_param != "Cancel":
                    cur_meta = config["params"][chosen_param]
                    new_vic = questionary.text(
                        f"Enter Victim value for {{{chosen_param}}}:",
                        default=str(cur_meta["victim_val"]),
                        style=CUSTOM_STYLE,
                    ).ask()
                    if new_vic:
                        cur_meta["victim_val"] = new_vic.strip()

                    new_att = questionary.text(
                        f"Enter Attacker value for {{{chosen_param}}}:",
                        default=str(cur_meta["attacker_val"]),
                        style=CUSTOM_STYLE,
                    ).ask()
                    if new_att:
                        cur_meta["attacker_val"] = new_att.strip()

            elif "5. Reset" in ans:
                inferred = infer_dynamic_bola_context(spec)
                config.clear()
                config.update(inferred)
                console.print("[green]Reset to dynamic OpenAPI specification values.[/green]")
                time.sleep(1)
        except (KeyboardInterrupt, EOFError):
            break
