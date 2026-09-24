"""Theme and styling configuration for SentinelAPI."""
from rich.console import Console
from rich.theme import Theme

# Custom security-focused cyber theme
SENTINEL_THEME = Theme({
    "info": "cyan",
    "warning": "bold yellow",
    "danger": "bold red",
    "success": "bold green",
    "muted": "dim white",
    "accent": "bold magenta",
    "highlight": "bold cyan",
    "header": "bold white on blue",
    "brand": "bold cyan",
    "endpoint": "bright_blue",
    "poc": "bold yellow",
    "high": "bold red",
    "medium": "bold yellow",
    "low": "bold cyan",
})

console = Console(theme=SENTINEL_THEME)

BANNER_ART = r"""
[bold cyan]
 ███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗            █████╗ ██████╗ ██╗
 ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║           ██╔══██╗██╔══██╗██║
 ███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║       -   ███████║██████╔╝██║
 ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║       -   ██╔══██║██╔═══╝ ██║
 ███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗      ██║  ██║██║     ██║
 ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝      ╚═╝  ╚═╝╚═╝     ╚═╝
[/bold cyan]
"""

TAGLINE = "[dim]API Security/Vulnerability Scanner ✦ Exploit Reproducer [/dim]"
VERSION_TAG = "[dim cyan]v1.0[/dim cyan]"
