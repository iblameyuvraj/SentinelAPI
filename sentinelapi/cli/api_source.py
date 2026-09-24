"""Interactive API Source selection and specification ingestion screen."""
import os
import time
from pathlib import Path
from typing import Optional, Dict, Any
from rich.panel import Panel
from rich.table import Table
import questionary
from prompt_toolkit.styles import Style

from sentinelapi.cli.theme import console

from sentinelapi.api_source.spec_parser import (
    validate_and_parse_spec,
    clean_input_path,
    ParsedSpecification,
)

# Custom Questionary styling matching cyber theme
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


def render_api_source_menu() -> Optional[ParsedSpecification]:
    """Displays the API Source selection screen and executes the ingestion flow."""
    console.print()
    console.print(
        Panel(
            "[bold white]How do you want to provide the API?[/bold white]\n\n"
            "  [bold cyan]1. OpenAPI / Swagger[/bold cyan]  [dim]• Automated parsing (.json, .yaml, .yml)[/dim]\n"
            "  [bold cyan]2. API Documentation[/bold cyan]  [dim]• AI-assisted doc ingestion (.md, .txt, .pdf)[/dim]\n"
            "  [bold cyan]3. Live API[/bold cyan]           [dim]• Target base URL & remote OpenAPI[/dim]\n"
            "  [bold cyan]4. Manual Endpoint[/bold cyan]     [dim]• Single endpoint custom probe[/dim]\n\n"
            "[dim]Supported formats: .json  .yaml  .yml  .md  .txt  .pdf[/dim]",
            title="[bold cyan]API SOURCE[/bold cyan]",
            border_style="cyan",
            padding=(1, 2),
        )
    )

    choices = [
        "1. OpenAPI / Swagger",
        "2. API Documentation",
        "3. Live API",
        "4. Manual Endpoint",
        "5. Back",
    ]

    try:
        selected = questionary.select(
            "Select API Source:",
            choices=choices,
            style=CUSTOM_STYLE,
        ).ask()
    except (KeyboardInterrupt, EOFError):
        return None

    if not selected or "5. Back" in selected:
        return None

    if "1. OpenAPI / Swagger" in selected:
        return handle_openapi_flow()
    elif "2. API Documentation" in selected:
        return handle_documentation_flow()
    elif "3. Live API" in selected:
        return handle_live_api_flow()
    elif "4. Manual Endpoint" in selected:
        return handle_manual_endpoint_flow()

    return None


def handle_openapi_flow() -> Optional[ParsedSpecification]:
    """Interactive drag-and-drop / path input and immediate validation for OpenAPI specs."""
    console.print()
    console.print(
        Panel(
            "[bold white]Provide your API specification[/bold white]\n\n"
            " [dim]• Drag & drop your specification file directly into the terminal[/dim]\n"
            " [dim]• Or type the relative/absolute file path below[/dim]\n\n"
            "[dim]Supported: .json  .yaml  .yml[/dim]",
            title="[bold cyan]OPENAPI / SWAGGER SPECIFICATION[/bold cyan]",
            border_style="cyan",
            padding=(1, 2),
        )
    )

    while True:
        try:
            raw_input = questionary.text(
                "File path / Drag & drop:",
                style=CUSTOM_STYLE,
            ).ask()
        except (KeyboardInterrupt, EOFError):
            return None

        if not raw_input or raw_input.strip().lower() in ["exit", "q", "back"]:
            return None

        file_path = clean_input_path(raw_input)

        console.print("\n[bold cyan]Loading and validating specification...[/bold cyan]\n")
        time.sleep(0.15)

        is_valid, spec, logs = validate_and_parse_spec(file_path)

        for log in logs:
            if log.startswith("✓"):
                console.print(f" [bold green]{log}[/bold green]")
            elif "Warning" in log:
                console.print(f" [bold yellow]⚠ {log}[/bold yellow]")
            else:
                console.print(f" [dim]• {log}[/dim]")

        if not is_valid or not spec:
            console.print(f"\n[bold red]✖ Specification validation failed.[/bold red]")
            retry = questionary.confirm("Would you like to try another file path?", default=True, style=CUSTOM_STYLE).ask()
            if not retry:
                return None
            continue

        # Display validated specification summary card
        console.print()
        summary_table = Table(box=None, show_header=False, padding=(0, 2))
        summary_table.add_column("Key", style="bold cyan")
        summary_table.add_column("Val", style="bold white")

        summary_table.add_row("API Title:", spec.title)
        summary_table.add_row("Version:", spec.version)
        summary_table.add_row("Standard:", spec.spec_type)
        summary_table.add_row("Base URL:", spec.base_url)
        summary_table.add_row("Auth Scheme:", spec.auth_scheme)
        summary_table.add_row("Endpoints:", f"{len(spec.endpoints)} discovered")
        summary_table.add_row("Object IDs:", f"{len(spec.parameterized_endpoints)} parameterized routes")

        console.print(
            Panel(
                summary_table,
                title="[bold green]✓ Specification Verified[/bold green]",
                border_style="green",
                padding=(1, 2),
            )
        )

        confirm = questionary.confirm("Continue to API analysis & security testing?", default=True, style=CUSTOM_STYLE).ask()
        if confirm:
            render_vulnerability_menu(spec)
            return spec
        return None


def render_vulnerability_menu(spec: ParsedSpecification):
    """Clears terminal after confirmation, displays specification header, and lists testable vulnerabilities."""
    from sentinelapi.bola_idor.ui import run_bola_idor_flow

    file_name = Path(spec.source).name if spec.source else "OpenAPI Specification"

    while True:
        console.clear()

        # Persistent Specification Details Header
        summary_table = Table(box=None, show_header=False, padding=(0, 2))
        summary_table.add_column("Key", style="bold cyan")
        summary_table.add_column("Val", style="bold white")

        summary_table.add_row("File Name:", file_name)
        summary_table.add_row("API Title:", spec.title)
        summary_table.add_row("Version:", spec.version)
        summary_table.add_row("Standard:", spec.spec_type)
        summary_table.add_row("Base URL:", spec.base_url)
        summary_table.add_row("Auth Scheme:", spec.auth_scheme)
        summary_table.add_row("Endpoints:", f"{len(spec.endpoints)} discovered")
        summary_table.add_row("Object IDs:", f"{len(spec.parameterized_endpoints)} parameterized routes")

        console.print(
            Panel(
                summary_table,
                title="[bold cyan]SPECIFICATION LOADED[/bold cyan]",
                border_style="cyan",
                padding=(1, 2),
            )
        )

        # Vulnerability selection menu
        vuln_choices = [
            "1. Scan all vulnerabilities",
            "2. BOLA / IDOR (Broken Object Level Authorization)",
            "3. Excessive Data Exposure",
            "4. Authentication Misconfiguration",
            "5. Rate Limiting",
            "6. Back to API Source",
        ]

        try:
            chosen_test = questionary.select(
                "Select Security Test to Execute:",
                choices=vuln_choices,
                style=CUSTOM_STYLE,
            ).ask()
        except (KeyboardInterrupt, EOFError):
            return

        if not chosen_test or "6. Back" in chosen_test:
            return

        if "2. BOLA / IDOR" in chosen_test:
            run_bola_idor_flow(spec)
            continue

        if "3. Excessive Data Exposure" in chosen_test:
            from sentinelapi.Excessive_Data_Exposure import run_excessive_data_flow
            run_excessive_data_flow(spec)
            continue

        # UI Preview Card for remaining modules
        console.print()
        preview_table = Table(box=None, show_header=False, padding=(0, 2))
        preview_table.add_column("Key", style="bold cyan")
        preview_table.add_column("Val", style="bold white")

        preview_table.add_row("Selected Test:", chosen_test)
        preview_table.add_row("Target API:", f"{spec.title} ({spec.base_url})")
        preview_table.add_row(
            "Target Endpoints:",
            f"{len(spec.parameterized_endpoints)} routes" if "BOLA" in chosen_test else f"{len(spec.endpoints)} routes",
        )
        preview_table.add_row("Status:", "[bold yellow]Ready for AI Test Generation & Execution[/bold yellow]")

        console.print(
            Panel(
                preview_table,
                title="[bold yellow]AI TEST EXECUTION PREVIEW[/bold yellow]",
                border_style="yellow",
                padding=(1, 2),
            )
        )
        console.print("[dim]UI mode active. Ready for scanning logic integration.[/dim]\n")
        try:
            questionary.press_any_key_to_continue("Press any key to continue...").ask()
        except (KeyboardInterrupt, EOFError):
            pass


def handle_documentation_flow() -> Optional[ParsedSpecification]:
    """Ingests unstructured documentation (.md, .txt, .pdf) for AI extraction."""
    console.print()
    console.print(
        Panel(
            "[bold white]AI-Powered API Documentation Ingestion[/bold white]\n\n"
            " [dim]SentinelAPI AI engine will read the unstructured documentation,\n"
            " identify endpoints, extract parameter schemas, and infer auth boundaries.[/dim]\n\n"
            "[dim]Supported: .md  .txt  .pdf[/dim]",
            title="[bold cyan]API DOCUMENTATION[/bold cyan]",
            border_style="cyan",
            padding=(1, 2),
        )
    )

    try:
        raw_path = questionary.text("Documentation file path / Drag & drop:", style=CUSTOM_STYLE).ask()
    except (KeyboardInterrupt, EOFError):
        return None

    if not raw_path:
        return None

    clean_p = clean_input_path(raw_path)
    if not os.path.exists(clean_p):
        console.print(f"[bold red]✖ File not found: {clean_p}[/bold red]\n")
        return None

    try:
        with open(clean_p, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
        word_count = len(content.split())
        console.print(f"\n [bold green]✓[/bold green] Documentation loaded: [bold white]{Path(clean_p).name}[/bold white]")
        console.print(f" [bold green]✓[/bold green] Size: [bold cyan]{word_count:,}[/bold cyan] words")
        console.print(" [bold green]✓[/bold green] Ready for AI Endpoint Extraction\n")
    except Exception as e:
        console.print(f"[bold red]Error reading document:[bold red] {e}")
        return None

    return None


def handle_live_api_flow() -> Optional[ParsedSpecification]:
    """Ingests a running API base URL and optional remote OpenAPI specification."""
    console.print()
    console.print(
        Panel(
            "[bold white]Live API Target[/bold white]\n\n"
            " [dim]Provide the base URL of your target service or sandboxed API.[/dim]",
            title="[bold cyan]LIVE API TARGET[/bold cyan]",
            border_style="cyan",
            padding=(1, 2),
        )
    )

    try:
        base_url = questionary.text(
            "Target Base URL:",
            default="http://localhost:8000",
            style=CUSTOM_STYLE,
        ).ask()
        
        openapi_url = questionary.text(
            "OpenAPI URL (optional, press Enter to skip):",
            default="http://localhost:8000/openapi.json",
            style=CUSTOM_STYLE,
        ).ask()
    except (KeyboardInterrupt, EOFError):
        return None

    if not base_url:
        return None

    if openapi_url and openapi_url.strip():
        console.print("\n[bold cyan]Fetching remote OpenAPI specification...[/bold cyan]")
        is_valid, spec, logs = validate_and_parse_spec(openapi_url.strip())
        for log in logs:
            if log.startswith("✓"):
                console.print(f" [bold green]{log}[/bold green]")
            else:
                console.print(f" [dim]• {log}[/dim]")
        if is_valid and spec:
            spec.base_url = base_url.rstrip("/")
            console.print(f"\n [bold green]✓[/bold green] Remote specification loaded successfully!")
            return spec

    return None


def handle_manual_endpoint_flow() -> Optional[ParsedSpecification]:
    """Allows manual specification of a single target route."""
    console.print()
    console.print(
        Panel(
            "[bold white]Manual Endpoint Probe[/bold white]\n\n"
            " [dim]Specify a single route and parameter to assess directly.[/dim]",
            title="[bold cyan]MANUAL ENDPOINT[/bold cyan]",
            border_style="cyan",
            padding=(1, 2),
        )
    )

    try:
        method = questionary.select(
            "HTTP Method:",
            choices=["GET", "POST", "PUT", "DELETE", "PATCH"],
            style=CUSTOM_STYLE,
        ).ask()

        path = questionary.text(
            "Endpoint Path (e.g. /users/{userId}/orders):",
            default="/users/{userId}/orders",
            style=CUSTOM_STYLE,
        ).ask()

        base_url = questionary.text(
            "Target Base URL:",
            default="http://localhost:8000",
            style=CUSTOM_STYLE,
        ).ask()
    except (KeyboardInterrupt, EOFError):
        return None

    if not path or not base_url:
        return None

    console.print(f"\n [bold green]✓[/bold green] Manual route configured: [bold cyan]{method} {path}[/bold cyan]")
    return None
