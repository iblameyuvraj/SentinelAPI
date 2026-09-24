"""SentinelAPI Configuration Manager & AI Provider Setup Guide.

================================================================================
                    SENTINELAPI CONFIGURATION GUIDE
================================================================================

This module handles configuration loading, environment variables, and AI provider
integrations for SentinelAPI.

You can configure your AI intelligence provider in two ways:
  1. Interactive terminal setup on first launch.
  2. Directly editing the `.env` file in the project root directory.

--------------------------------------------------------------------------------
SUPPORTED AI PROVIDERS & ENVIRONMENT VARIABLES:
--------------------------------------------------------------------------------
1. OpenAI:
   OPENAI_API_KEY="sk-..."
   OPENAI_MODEL="gpt-4o"  # optional (default: gpt-4o)

2. Claude (Anthropic):
   ANTHROPIC_API_KEY="sk-ant-..."
   CLAUDE_MODEL="claude-3-5-sonnet-latest"  # optional

3. xAI (Grok):
   XAI_API_KEY="xai-..."
   XAI_MODEL="grok-beta"  # optional

4. Gemini (Google):
   GEMINI_API_KEY="AIza..."
   GEMINI_MODEL="gemini-2.5-flash"  # optional

5. Custom Provider (Local / Ollama / vLLM / LiteLLM / OpenAI-compatible):
   CUSTOM_LLM_BASE_URL="http://localhost:11434/v1"
   CUSTOM_LLM_API_KEY="optional_key_or_none"
   CUSTOM_LLM_MODEL="llama3.1"  # optional
================================================================================
"""

import os
from pathlib import Path
from typing import Optional, Tuple, Dict, List
from dotenv import load_dotenv, set_key

# Root project directory and .env path
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
ENV_FILE = PROJECT_ROOT / ".env"

# Load environment on module import
load_dotenv(dotenv_path=ENV_FILE)

PROVIDERS = {
    "openai": {
        "name": "OpenAI",
        "key_env": "OPENAI_API_KEY",
        "default_model": "gpt-4o",
    },
    "claude": {
        "name": "Claude (Anthropic)",
        "key_env": "ANTHROPIC_API_KEY",
        "default_model": "claude-3-5-sonnet-latest",
    },
    "xai": {
        "name": "xAI (Grok)",
        "key_env": "XAI_API_KEY",
        "default_model": "grok-beta",
    },
    "gemini": {
        "name": "Gemini (Google)",
        "key_env": "GEMINI_API_KEY",
        "default_model": "gemini-2.5-flash",
    },
    "custom": {
        "name": "Custom Provider",
        "key_env": "CUSTOM_LLM_API_KEY",
        "base_url_env": "CUSTOM_LLM_BASE_URL",
        "default_model": "custom-model",
    },
}


def get_active_provider() -> Optional[Tuple[str, str]]:
    """Checks if any AI provider is configured in environment or .env.
    
    Returns:
        (provider_key, display_name) or None
    """
    load_dotenv(dotenv_path=ENV_FILE, override=True)

    for p_id, p_info in PROVIDERS.items():
        val = os.getenv(p_info["key_env"], "").strip()
        # Also check custom base url if key is empty
        if p_id == "custom":
            custom_url = os.getenv("CUSTOM_LLM_BASE_URL", "").strip()
            if val or custom_url:
                return (p_id, p_info["name"])
        elif val:
            return (p_id, p_info["name"])

    return None


def is_configured() -> bool:
    """Returns True if at least one provider has been configured."""
    return get_active_provider() is not None


def save_env_variable(key: str, value: str):
    """Writes an environment variable to the root .env file."""
    if not ENV_FILE.exists():
        ENV_FILE.touch()
    set_key(str(ENV_FILE), key, value)
    os.environ[key] = value


def prompt_first_time_setup() -> Optional[str]:
    """Interactive terminal wizard to prompt user for AI Provider configuration."""
    from rich.panel import Panel
    from rich.console import Console
    import questionary
    from prompt_toolkit.styles import Style

    console = Console()

    # Sleek cyber style matching theme
    custom_style = Style(
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

    console.print()
    console.print(
        Panel(
            "[bold cyan]AI Intelligence Provider Setup[/bold cyan]\n\n"
            "[dim]SentinelAPI utilizes LLM models to analyze complex API logic flaws,\n"
            "evaluate data exposure, and generate zero-trust exploit PoCs.\n"
            "Configure your provider below (saved to [bold white].env[/bold white]).[/dim]",
            title="[bold yellow]⚡ Configuration Notice[/bold yellow]",
            border_style="cyan",
            padding=(1, 2),
        )
    )

    choices = [
        "1. OpenAI (GPT-4o)",
        "2. Claude (Anthropic Claude 3.5)",
        "3. xAI (Grok)",
        "4. Gemini (Google Gemini)",
        "5. Custom Provider (Local / Ollama / vLLM / OpenAI-compatible)",
        "6. Skip for now (Manual .env configuration)",
    ]

    try:
        selected = questionary.select(
            "Select your AI provider:",
            choices=choices,
            style=custom_style,
        ).ask()
    except (KeyboardInterrupt, EOFError):
        selected = None

    if not selected or "6. Skip" in selected:
        console.print("[dim yellow]Setup skipped. You can configure keys anytime in [bold].env[/bold] or [bold]configuration.py[/bold][/dim yellow]\n")
        save_env_variable("SENTINEL_AI_PROVIDER", "custom_skipped")
        return None

    try:
        if "1. OpenAI" in selected:
            key = questionary.password("Enter OPENAI_API_KEY:", style=custom_style).ask()
            if key:
                save_env_variable("OPENAI_API_KEY", key.strip())
                save_env_variable("SENTINEL_AI_PROVIDER", "openai")
                console.print(" [bold green]✓[/bold green] Saved [bold white]OPENAI_API_KEY[/bold white] to [cyan].env[/cyan]")
                return "OpenAI"

        elif "2. Claude" in selected:
            key = questionary.password("Enter ANTHROPIC_API_KEY:", style=custom_style).ask()
            if key:
                save_env_variable("ANTHROPIC_API_KEY", key.strip())
                save_env_variable("SENTINEL_AI_PROVIDER", "claude")
                console.print(" [bold green]✓[/bold green] Saved [bold white]ANTHROPIC_API_KEY[/bold white] to [cyan].env[/cyan]")
                return "Claude"

        elif "3. xAI" in selected:
            key = questionary.password("Enter XAI_API_KEY:", style=custom_style).ask()
            if key:
                save_env_variable("XAI_API_KEY", key.strip())
                save_env_variable("SENTINEL_AI_PROVIDER", "xai")
                console.print(" [bold green]✓[/bold green] Saved [bold white]XAI_API_KEY[/bold white] to [cyan].env[/cyan]")
                return "xAI"

        elif "4. Gemini" in selected:
            key = questionary.password("Enter GEMINI_API_KEY:", style=custom_style).ask()
            if key:
                save_env_variable("GEMINI_API_KEY", key.strip())
                save_env_variable("SENTINEL_AI_PROVIDER", "gemini")
                console.print(" [bold green]✓[/bold green] Saved [bold white]GEMINI_API_KEY[/bold white] to [cyan].env[/cyan]")
                return "Gemini"

        elif "5. Custom" in selected:
            base_url = questionary.text(
                "Enter Custom API Base URL (e.g. http://localhost:11434/v1):",
                default="http://localhost:11434/v1",
                style=custom_style,
            ).ask()
            key = questionary.text(
                "Enter Custom API Key (optional, press Enter to leave blank):",
                default="",
                style=custom_style,
            ).ask()
            if base_url:
                save_env_variable("CUSTOM_LLM_BASE_URL", base_url.strip())
            if key:
                save_env_variable("CUSTOM_LLM_API_KEY", key.strip())
            save_env_variable("SENTINEL_AI_PROVIDER", "custom")
            console.print(" [bold green]✓[/bold green] Saved Custom Provider configuration to [cyan].env[/cyan]")
            return "Custom Provider"
    except (KeyboardInterrupt, EOFError):
        console.print("[dim yellow]Input cancelled.[/dim yellow]")
        return None

    return None


def get_selected_model() -> Optional[str]:
    """Retrieves the currently selected AI model from environment or .env."""
    load_dotenv(dotenv_path=ENV_FILE, override=True)
    return (
        os.getenv("SENTINEL_AI_MODEL")
        or os.getenv("CUSTOM_LLM_MODEL")
        or os.getenv("OPENAI_MODEL")
        or os.getenv("CLAUDE_MODEL")
        or os.getenv("XAI_MODEL")
        or os.getenv("GEMINI_MODEL")
    )


def fetch_available_models(provider_id: str) -> List[str]:
    """Fetches list of available models from provider API or returns standard models."""
    import httpx

    load_dotenv(dotenv_path=ENV_FILE, override=True)

    if provider_id == "custom":
        base_url = os.getenv("CUSTOM_LLM_BASE_URL", "").rstrip("/")
        api_key = os.getenv("CUSTOM_LLM_API_KEY", "")
        headers = {}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"

        if base_url:
            try:
                resp = httpx.get(f"{base_url}/models", headers=headers, timeout=8.0)
                if resp.status_code == 200:
                    data = resp.json()
                    models = [m.get("id") for m in data.get("data", []) if isinstance(m, dict) and "id" in m]
                    if models:
                        return sorted(models)
            except Exception:
                pass
        return [
            "meta/llama-3.3-70b-instruct",
            "meta/llama-3.1-405b-instruct",
            "meta/llama-3.1-70b-instruct",
            "meta/llama-3.1-8b-instruct",
            "deepseek-ai/deepseek-r1",
            "mistralai/mistral-large-2-instruct",
            "nvidia/llama-3.1-nemotron-70b-instruct",
            "microsoft/phi-4",
            "google/gemma-2-27b-it",
        ]

    elif provider_id == "openai":
        api_key = os.getenv("OPENAI_API_KEY", "")
        if api_key:
            try:
                resp = httpx.get("https://api.openai.com/v1/models", headers={"Authorization": f"Bearer {api_key}"}, timeout=6.0)
                if resp.status_code == 200:
                    data = resp.json()
                    models = [m.get("id") for m in data.get("data", []) if "gpt" in m.get("id", "").lower() or "o1" in m.get("id", "").lower() or "o3" in m.get("id", "").lower()]
                    if models:
                        return sorted(models)
            except Exception:
                pass
        return ["gpt-4o", "gpt-4o-mini", "o1", "o1-mini", "o3-mini", "gpt-4-turbo"]

    elif provider_id == "xai":
        api_key = os.getenv("XAI_API_KEY", "")
        if api_key:
            try:
                resp = httpx.get("https://api.x.ai/v1/models", headers={"Authorization": f"Bearer {api_key}"}, timeout=6.0)
                if resp.status_code == 200:
                    data = resp.json()
                    models = [m.get("id") for m in data.get("data", [])]
                    if models:
                        return sorted(models)
            except Exception:
                pass
        return ["grok-2-latest", "grok-2-vision-latest", "grok-beta"]

    elif provider_id == "claude":
        return [
            "claude-3-5-sonnet-latest",
            "claude-3-5-haiku-latest",
            "claude-3-opus-latest",
            "claude-3-sonnet-20240229",
            "claude-3-haiku-20240307",
        ]

    elif provider_id == "gemini":
        return [
            "gemini-2.5-flash",
            "gemini-2.5-pro",
            "gemini-1.5-flash",
            "gemini-1.5-pro",
            "gemini-1.0-pro",
        ]

    return ["default-model"]


def prompt_model_selection(provider_id: Optional[str] = None, force: bool = False) -> Optional[str]:
    """Prompts user to select from available models with live type-to-filter and arrow navigation."""
    from rich.panel import Panel
    from rich.console import Console
    import questionary
    from prompt_toolkit.styles import Style

    console = Console()

    if not provider_id:
        active = get_active_provider()
        provider_id = active[0] if active else "custom"

    # Check if model already set and not forced
    existing_model = get_selected_model()
    if existing_model and not force:
        return existing_model

    custom_style = Style(
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

    console.print()
    with console.status("[bold cyan]Fetching available models from provider API...[/bold cyan]"):
        models = fetch_available_models(provider_id)

    console.print(
        Panel(
            f"[bold white]Provider:[/bold white] [bold cyan]{provider_id.upper()}[/bold cyan]\n"
            f"[bold white]Available Models:[/bold white] [bold green]{len(models)} models discovered[/bold green]\n\n"
            "[dim]• [bold white]Type to live-filter[/bold white] models (e.g. 'llama', 'deepseek', 'gpt', 'mistral')\n"
            "• Use [bold white]↑ / ↓ Arrow keys[/bold white] to browse the full list\n"
            "• Press [bold white]Enter[/bold white] to select[/dim]",
            title="[bold cyan]AI MODEL SELECTION[/bold cyan]",
            border_style="cyan",
            padding=(1, 2),
        )
    )

    choices = list(models)
    choices.append("[Type custom model name manually]")

    try:
        chosen = questionary.select(
            "Select AI Model:",
            choices=choices,
            use_search_filter=True,
            use_jk_keys=False,
            instruction="(Type to filter / ↑↓ arrows)",
            style=custom_style,
        ).ask()
    except (KeyboardInterrupt, EOFError):
        return None

    if not chosen:
        return None

    if chosen == "[Type custom model name manually]":
        try:
            chosen = questionary.text("Enter model ID/name:", style=custom_style).ask()
        except (KeyboardInterrupt, EOFError):
            return None

    if chosen and chosen.strip():
        model_name = chosen.strip()
        save_env_variable("SENTINEL_AI_MODEL", model_name)
        if provider_id == "custom":
            save_env_variable("CUSTOM_LLM_MODEL", model_name)
        elif provider_id == "openai":
            save_env_variable("OPENAI_MODEL", model_name)

        console.print()
        console.print(
            Panel(
                f"[bold green]✓[/bold green] [bold white]{model_name}[/bold white]\n"
                f"[dim]Provider: {provider_id.upper()} • Saved to .env[/dim]",
                title="[bold green]AI MODEL SELECTED[/bold green]",
                border_style="green",
                padding=(0, 2),
            )
        )
        return model_name

    return None

