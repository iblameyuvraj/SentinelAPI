"""SentinelAPI Entry Point."""
import sys
import argparse
from pathlib import Path
from sentinelapi.cli.animation import run_startup_animation
from sentinelapi.cli.api_source import render_api_source_menu
from sentinelapi.cli.theme import console
from sentinelapi.api_source.spec_parser import validate_and_parse_spec
from sentinelapi.features.master_scan import run_master_scan


def main():
    parser = argparse.ArgumentParser(
        description="SentinelAPI — AI-Powered OWASP API Security Testing & Pentesting Engine"
    )
    parser.add_argument(
        "--spec",
        type=str,
        help="Path or URL to OpenAPI / Swagger specification file",
    )
    parser.add_argument(
        "--base-url",
        type=str,
        help="Target API base URL (e.g. http://localhost:3000 or https://api.target.com)",
    )
    parser.add_argument(
        "--token",
        type=str,
        default="",
        help="Bearer token for authenticated endpoint testing",
    )
    parser.add_argument(
        "--cookie",
        type=str,
        default="",
        help="Cookie string for authenticated endpoint testing",
    )
    parser.add_argument(
        "--burst",
        type=int,
        default=20,
        help="Burst request count for rate limiting tests (default: 20)",
    )
    parser.add_argument(
        "--no-ai",
        action="store_true",
        help="Skip AI report generation",
    )
    parser.add_argument(
        "--ci",
        action="store_true",
        help="CI mode: Fail-closed non-zero exit code on FAIL, ERROR, or INCOMPLETE",
    )

    args = parser.parse_args()

    # Headless / CI Mode
    if args.spec:
        is_valid, spec, logs = validate_and_parse_spec(args.spec)
        if not is_valid or not spec:
            console.print(f"[bold red]✖ Error parsing specification '{args.spec}':[/bold red]")
            for log in logs:
                console.print(f"  {log}")
            sys.exit(2)

        base_url = (args.base_url or spec.base_url or "http://localhost:3000").rstrip("/")
        config = {
            "base_url": base_url,
            "bearer_token": args.token,
            "cookie_string": args.cookie,
            "burst_count": args.burst,
            "params": {},
            "user_token": args.token,
            "base_token": args.token,
            "generate_ai": not args.no_ai,
        }

        console.print(f"[bold cyan]Launching automated SentinelAPI master scan against {base_url}...[/bold cyan]\n")
        master_result = run_master_scan(spec, config_override=config)

        # Fail closed for CI/CD
        console.print(f"\n[dim]Audit finished with status: [bold]{master_result.status}[/bold] (Exit Code: {master_result.exit_code})[/dim]")
        sys.exit(master_result.exit_code)

    # Interactive Mode
    run_startup_animation()
    spec = render_api_source_menu()
    if spec:
        console.print(f"\n[bold green]Ready for AI Analysis & Security Testing on [white]{spec.title}[/white]![/bold green]\n")
    else:
        console.print("\n[dim cyan]SentinelAPI session ended.[/dim cyan]")


if __name__ == "__main__":
    main()
