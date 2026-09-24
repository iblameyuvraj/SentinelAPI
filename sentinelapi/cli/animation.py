"""Startup loading animation and branded console intro for SentinelAPI."""
import sys
import time
from rich.panel import Panel
from rich.progress import (
    Progress,
    BarColumn,
    TextColumn,
    TaskProgressColumn,
    SpinnerColumn,
)
from rich.align import Align
from sentinelapi.cli.theme import console, BANNER_ART, TAGLINE, VERSION_TAG
from sentinelapi.modals.configuration import (
    get_active_provider,
    prompt_first_time_setup,
    is_configured,
    get_selected_model,
    prompt_model_selection,
)


def display_banner():
    """Prints the SentinelAPI ASCII banner and tagline."""
    console.print(Align.center(BANNER_ART))
    console.print(Align.center(f"{TAGLINE} • {VERSION_TAG}\n"))


def run_startup_animation(skip_sleep: bool = False):
    """Executes the high-tech terminal startup sequence.
    
    Shows:
    1. Branded banner
    2. Progress loading bar (100%)
    3. Checked default green steps:
       - Scanner engine loaded
       - Vulnerability modules loaded
       - Configuration check & first-time AI provider setup prompt
    """
    display_banner()

    console.print("[bold cyan]Initializing SentinelAPI...[/bold cyan]\n")

    # Interactive progress bar using solid blocks
    with Progress(
        TextColumn("[bold blue]{task.description}"),
        BarColumn(
            bar_width=32,
            complete_style="cyan",
            finished_style="bold green",
            pulse_style="bold cyan",
        ),
        TaskProgressColumn(),
        console=console,
        transient=False,
    ) as progress:
        task = progress.add_task("[dim]Loading modules...", total=100)
        
        increments = [15, 30, 25, 20, 10] if not skip_sleep else [100]
        delay = 0.08 if not skip_sleep else 0.0

        for inc in increments:
            if not skip_sleep:
                time.sleep(delay)
            progress.update(task, advance=inc)

    console.print()

    # Default Green Step 1: Scanner engine
    if not skip_sleep:
        time.sleep(0.18)
    console.print(" [bold green]✓[/bold green] [bold green]Scanner engine loaded[/bold green]")

    # Default Green Step 2: Vulnerability modules
    if not skip_sleep:
        time.sleep(0.18)
    console.print(" [bold green]✓[/bold green] [bold green]Vulnerability modules loaded[/bold green]")

    # Step 3: Configuration Loading & First-time Check
    if not skip_sleep:
        time.sleep(0.18)

    provider_info = get_active_provider()

    if not provider_info:
        # First time: Prompt user for API keys & Provider configuration
        console.print(" [bold yellow]⚠[/bold yellow] [bold yellow]Configuration not detected[/bold yellow] [dim](First-time launch)[/dim]")
        prompt_first_time_setup()
        provider_info = get_active_provider()

    active_provider_name = provider_info[1] if provider_info else "Manual .env mode"
    active_pid = provider_info[0] if provider_info else "custom"

    # Check if AI model has been selected
    active_model = get_selected_model()
    if not active_model and provider_info:
        active_model = prompt_model_selection(active_pid)

    if active_model:
        console.print(f" [bold green]✓[/bold green] [bold green]Configuration loaded[/bold green] [dim cyan]({active_provider_name} • {active_model})[/dim cyan]")
    else:
        console.print(f" [bold green]✓[/bold green] [bold green]Configuration loaded[/bold green] [dim cyan]({active_provider_name})[/dim cyan]")

    if not skip_sleep:
        time.sleep(0.25)
    console.print("\n[dim]────────────────────────────────────────────────────────────[/dim]\n")


if __name__ == "__main__":
    run_startup_animation()
