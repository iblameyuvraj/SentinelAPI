"""SentinelAPI Entry Point."""
import sys
from sentinelapi.cli.animation import run_startup_animation
from sentinelapi.cli.api_source import render_api_source_menu
from sentinelapi.cli.theme import console


def main():
    # 1. Startup animation & AI configuration check
    run_startup_animation()

    # 2. API Source Selection Screen
    spec = render_api_source_menu()

    if spec:
        console.print(f"\n[bold green]Ready for AI Analysis & Security Testing on [white]{spec.title}[/white]![/bold green]\n")
    else:
        console.print("\n[dim cyan]SentinelAPI session ended.[/dim cyan]")


if __name__ == "__main__":
    main()
