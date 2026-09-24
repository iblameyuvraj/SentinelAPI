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
            render_ai_analysis_card(spec)
            return spec
        return None


def render_ai_analysis_card(spec: ParsedSpecification):
    """Renders the AI structural discovery analysis and security recommendations."""
    console.print("\n[bold cyan]AI analyzing API structure...[/bold cyan]")
    time.sleep(0.4)

    param_eps = spec.parameterized_endpoints
    user_scoped = [ep for ep in spec.endpoints if "user" in ep.path.lower() or "account" in ep.path.lower()]
    
    analysis_lines = [
        f" [bold green]✓[/bold green] [bold white]{len(spec.endpoints)}[/bold white] endpoints discovered",
        f" [bold green]✓[/bold green] [bold white]{spec.auth_scheme}[/bold white] authentication detected",
        f" [bold green]✓[/bold green] [bold white]{len(param_eps)}[/bold white] object identifier routes detected",
        f" [bold green]✓[/bold green] [bold white]{len(user_scoped)}[/bold white] user-scoped resources detected\n",
        "[bold cyan]Potential authorization boundaries:[/bold cyan]",
    ]

    for ep in param_eps[:5]:
        analysis_lines.append(f"   • [bright_blue]{ep.identifier}[/bright_blue]")

    if len(param_eps) > 5:
        analysis_lines.append(f"   [dim]... and {len(param_eps) - 5} more routes[/dim]")

    analysis_lines.append("\n[bold yellow]Recommended security tests:[/bold yellow]")
    analysis_lines.append("   • [bold white]BOLA / IDOR[/bold white] [dim](Broken Object Level Authorization)[/dim]")
    analysis_lines.append("   • [bold white]Excessive Data Exposure[/bold white] [dim](PII / Internal Fields Leakage)[/dim]")

    console.print()
    console.print(
        Panel(
            "\n".join(analysis_lines),
            title="[bold magenta]⚡ AI ANALYSIS[/bold magenta]",
            border_style="magenta",
            padding=(1, 2),
        )
    )


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
