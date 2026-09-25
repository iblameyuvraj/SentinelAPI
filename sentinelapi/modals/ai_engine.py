"""SentinelAPI Core AI Intelligence Engine.

Provides unified LLM communication, dynamic token estimation, security prompt
synthesis, and streaming AI security overviews across configured providers.
"""
import os
import json
import time
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple, Callable
import httpx
from dotenv import load_dotenv

from sentinelapi.cli.theme import console
from sentinelapi.api_source.spec_parser import ParsedSpecification

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
ENV_FILE = PROJECT_ROOT / ".env"


def get_active_ai_config() -> Dict[str, Any]:
    """Retrieves current AI provider configuration from environment or .env file."""
    load_dotenv(dotenv_path=ENV_FILE, override=True)

    provider = os.getenv("SENTINEL_AI_PROVIDER", "custom").strip().strip("'\"").lower()
    model = (
        os.getenv("SENTINEL_AI_MODEL")
        or os.getenv("CUSTOM_LLM_MODEL")
        or os.getenv("OPENAI_MODEL")
        or os.getenv("CLAUDE_MODEL")
        or os.getenv("GEMINI_MODEL")
        or os.getenv("XAI_MODEL")
        or "openai/gpt-oss-20b"
    ).strip().strip("'\"")

    base_url = (
        os.getenv("CUSTOM_LLM_BASE_URL")
        or "https://integrate.api.nvidia.com/v1"
    ).strip().strip("'\"").rstrip("/")

    api_key = (
        os.getenv("CUSTOM_LLM_API_KEY")
        or os.getenv("OPENAI_API_KEY")
        or os.getenv("ANTHROPIC_API_KEY")
        or os.getenv("GEMINI_API_KEY")
        or os.getenv("XAI_API_KEY")
        or ""
    ).strip().strip("'\"")

    return {
        "provider": provider,
        "model": model,
        "base_url": base_url,
        "api_key": api_key,
        "is_configured": bool(api_key or "localhost" in base_url or "127.0.0.1" in base_url),
    }


def estimate_token_usage(prompt_text: str) -> Dict[str, Any]:
    """Dynamically estimates token counts and payload context sizes."""
    char_count = len(prompt_text)
    # Industry standard rule of thumb: ~3.8 characters per token for English & code
    prompt_tokens = max(1, int(char_count / 3.8))
    estimated_output_tokens = 650
    estimated_total_tokens = prompt_tokens + estimated_output_tokens

    return {
        "char_count": char_count,
        "prompt_tokens": prompt_tokens,
        "estimated_output_tokens": estimated_output_tokens,
        "estimated_total_tokens": estimated_total_tokens,
    }


def build_bola_ai_prompt(
    spec: ParsedSpecification,
    results: List[Dict[str, Any]],
    config: Dict[str, Any],
) -> str:
    """Constructs a concise, context-rich security telemetry prompt for the LLM."""
    vuln_results = [r for r in results if r.get("vulnerable")]
    passed_results = [r for r in results if not r.get("vulnerable")]

    lines = [
        f"# TARGET API SECURITY TELEMETRY: {spec.title}",
        f"- Target Base URL: {spec.base_url}",
        f"- Specification: {spec.spec_type} (Version: {spec.version})",
        f"- Auth Scheme: {spec.auth_scheme} (Header: `{config.get('auth_header_name', 'Authorization')}`)",
        "",
        "## TEST IDENTITY CONTEXT",
        f"- Victim (User A): ID `{config.get('victim_id', '101')}`",
        f"- Attacker (User B): ID `{config.get('attacker_id', '102')}`",
        "- Tested Parameters: " + ", ".join(f"`{{{k}}}`={v.get('victim_val')}" for k, v in config.get("params", {}).items()),
        "",
        "## SCAN RESULTS SUMMARY",
        f"- Total Endpoints Probed: {len(results)}",
        f"- Vulnerabilities Confirmed: {len(vuln_results)} (OWASP API1:2023 - BOLA/IDOR)",
        f"- Protected Routes: {len(passed_results)} (Enforcing Object Ownership)",
        "",
        "## PROBED ROUTES & HTTP TELEMETRY:",
    ]

    for idx, r in enumerate(results, 1):
        ep = r["endpoint"]
        verdict = "FAIL (BOLA LEAKED)" if r.get("vulnerable") else "PASS (SECURED)"
        lines.append(f"{idx}. {ep.method} {ep.path} -> Owner: {r.get('baseline_status')} | Attacker: {r.get('attack_status')} | Verdict: {verdict}")
        snippet = (r.get("response_snippet") or "").strip()
        if snippet and r.get("vulnerable"):
            lines.append(f"   Leaked Data Preview: {snippet[:100]}")

    lines.extend([
        "",
        "## INSTRUCTIONS FOR SECURITY INTELLIGENCE REPORT:",
        "Provide a concise, authoritative security report in structured GitHub Markdown with these sections:",
        "### 1. Executive Threat Posture",
        "Summarize the overall authorization security posture of this API.",
        "### 2. Authorization Boundaries & Vulnerability Breakdown",
        "Analyze the findings. If vulnerabilities were found, explain the exact object-level flaw. If all passed, explain the defensive controls verified.",
        "### 3. Threat Scenarios & Impact",
        "Describe how an attacker could exploit these routes for horizontal privilege escalation, or what multi-tenant risks are mitigated.",
        "### 4. Production-Ready Code Remediation",
        "Provide concrete, clean code snippets (TypeScript/JavaScript or Python) showing how to enforce strict object ownership checks before returning data.",
        "### 5. Strategic Hardening Recommendations",
        "2-3 actionable best practices (e.g. database Row-Level Security, policy middleware, opaque UUIDs).",
    ])

    return "\n".join(lines)


def request_ai_overview(
    prompt_text: str,
    progress_callback: Optional[Callable[[int], None]] = None,
    max_tokens: int = 4000,
) -> Tuple[bool, str]:
    """Streams the security prompt to the active LLM provider and returns the complete markdown response."""
    ai_cfg = get_active_ai_config()

    if not ai_cfg["is_configured"]:
        return False, (
            "No AI Provider credentials found in .env.\n"
            "Please configure CUSTOM_LLM_API_KEY, OPENAI_API_KEY, or run `sentinel` setup."
        )

    base_url = ai_cfg["base_url"]
    api_key = ai_cfg["api_key"]
    model = ai_cfg["model"]

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }

    system_prompt = (
        "You are SentinelAPI Core Security Intelligence Engine, a senior zero-trust API security auditor. "
        "Analyze the provided API vulnerability telemetry and provide an authoritative, high-level executive security overview "
        "and production-ready code remediation in clean, structured GitHub Markdown with code blocks. "
        "Ensure your response is completely finished and never truncated."
    )

    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": prompt_text},
        ],
        "stream": True,
        "max_tokens": max_tokens,
        "temperature": 0.2,
    }

    try:
        content_chunks: List[str] = []
        reasoning_chunks: List[str] = []
        token_count = 0

        # Stream connection: connect timeout 15s, read timeout 30s per chunk
        timeout_config = httpx.Timeout(120.0, connect=15.0, read=30.0)

        with httpx.Client(timeout=timeout_config) as client:
            with client.stream("POST", f"{base_url}/chat/completions", headers=headers, json=payload) as response:
                if response.status_code != 200:
                    err_body = response.read().decode("utf-8", errors="ignore")
                    return False, f"AI Provider returned HTTP {response.status_code}: {err_body}"

                for line in response.iter_lines():
                    if not line:
                        continue
                    if line.startswith("data: "):
                        data_str = line[6:].strip()
                        if data_str == "[DONE]":
                            break
                        try:
                            chunk = json.loads(data_str)
                            delta = chunk["choices"][0].get("delta", {})
                            c = delta.get("content") or ""
                            r = delta.get("reasoning_content") or ""

                            if c:
                                content_chunks.append(c)
                                token_count += 1
                                if progress_callback and token_count % 15 == 0:
                                    progress_callback(token_count)
                            elif r:
                                reasoning_chunks.append(r)
                                token_count += 1
                                if progress_callback and token_count % 15 == 0:
                                    progress_callback(token_count)
                        except Exception:
                            continue

        final_text = "".join(content_chunks).strip()
        if not final_text and reasoning_chunks:
            final_text = "".join(reasoning_chunks).strip()

        if not final_text:
            return False, "AI model returned an empty response."

        return True, final_text

    except httpx.ReadTimeout:
        return False, f"Request timed out waiting for AI response from model '{model}'. Try a faster model or retry."
    except Exception as e:
        return False, f"Network or execution error while contacting AI engine: {str(e)}"
