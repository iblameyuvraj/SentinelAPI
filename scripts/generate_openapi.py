#!/usr/bin/env python3
"""
SentinelAPI — Automated OpenAPI Specification Generator & Validator
Consolidates endpoints, applies dynamic base URLs (e.g. Vercel preview deployments),
enriches metadata with git commit/timestamp details, and validates syntax for CI/CD gates.
"""

import argparse
import datetime
import glob
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional


def get_git_info() -> Dict[str, str]:
    """Retrieves current git commit, branch, and author information."""
    info = {
        "branch": os.environ.get("GITHUB_REF_NAME", "unknown"),
        "commit": os.environ.get("GITHUB_SHA", "unknown"),
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    }
    try:
        if info["branch"] == "unknown":
            info["branch"] = subprocess.check_output(
                ["git", "rev-parse", "--abbrev-ref", "HEAD"], text=True
            ).strip()
        if info["commit"] == "unknown":
            info["commit"] = subprocess.check_output(
                ["git", "rev-parse", "--short", "HEAD"], text=True
            ).strip()
    except Exception:
        pass
    return info


def discover_backend_specs(backend_dir: Path) -> List[Path]:
    """Finds all openapi.json or *openapi*.json in the backend directory."""
    specs = []
    if backend_dir.is_dir():
        for p in backend_dir.glob("**/*openapi*.json"):
            if p.is_file():
                specs.append(p)
    return sorted(specs)


def merge_specs(spec_paths: List[Path], base_title: str = "SentinelAPI Unified Assessment Suite") -> Dict[str, Any]:
    """Merges multiple OpenAPI specifications into a unified schema."""
    unified: Dict[str, Any] = {
        "openapi": "3.0.3",
        "info": {
            "title": base_title,
            "description": "Unified and automatically generated OpenAPI specification for SentinelAPI security assessment.",
            "version": "1.0.0",
        },
        "servers": [],
        "components": {
            "securitySchemes": {},
            "schemas": {},
        },
        "paths": {},
    }

    for path in spec_paths:
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)

            # Merge paths
            for p, item in data.get("paths", {}).items():
                if p not in unified["paths"]:
                    unified["paths"][p] = item
                else:
                    unified["paths"][p].update(item)

            # Merge security schemes
            sec_schemes = data.get("components", {}).get("securitySchemes", {})
            unified["components"]["securitySchemes"].update(sec_schemes)

            # Merge schemas
            schemas = data.get("components", {}).get("schemas", {})
            unified["components"]["schemas"].update(schemas)

            # Merge servers
            for s in data.get("servers", []):
                if s not in unified["servers"]:
                    unified["servers"].append(s)

        except Exception as e:
            print(f"⚠️  Warning: Failed to parse spec '{path}': {e}", file=sys.stderr)

    return unified


def generate_openapi_spec(
    source_spec: Optional[str] = None,
    backend_dir: Optional[str] = None,
    base_url: Optional[str] = None,
    output_file: str = "sandbox_openapi.json",
    merge_backend: bool = False,
) -> bool:
    """Generates, updates, and validates OpenAPI specification."""
    repo_root = Path(__file__).resolve().parent.parent
    git_info = get_git_info()

    target_data: Dict[str, Any] = {}

    if merge_backend:
        b_dir = Path(backend_dir) if backend_dir else (repo_root / "backend")
        spec_files = discover_backend_specs(b_dir)
        print(f"📦 Discovered {len(spec_files)} modular specs in {b_dir}")
        target_data = merge_specs(spec_files)
    elif source_spec and os.path.exists(source_spec):
        print(f"📖 Reading base specification from '{source_spec}'")
        with open(source_spec, "r", encoding="utf-8") as f:
            target_data = json.load(f)
    elif (repo_root / "sandbox_openapi.json").exists():
        fallback = repo_root / "sandbox_openapi.json"
        print(f"📖 Using existing '{fallback.name}' as template")
        with open(fallback, "r", encoding="utf-8") as f:
            target_data = json.load(f)
    else:
        print("❌ Error: No valid OpenAPI source specification found.", file=sys.stderr)
        return False

    # Inject metadata
    if "info" not in target_data:
        target_data["info"] = {}

    target_data["info"]["x-generated-at"] = git_info["timestamp"]
    target_data["info"]["x-git-branch"] = git_info["branch"]
    target_data["info"]["x-git-commit"] = git_info["commit"]
    target_data["info"]["x-generator"] = "SentinelAPI CI/CD OpenAPI Generator"

    # Set base URL if provided (e.g. Vercel Preview URL)
    if base_url:
        clean_url = base_url.strip().rstrip("/")
        preview_server = {
            "url": clean_url,
            "description": "Live Preview Deployment (Vercel / Dynamic CI)",
        }
        existing_servers = target_data.get("servers", [])
        target_data["servers"] = [preview_server] + [
            s for s in existing_servers if s.get("url") != clean_url
        ]
        print(f"🌐 Injected primary target base URL: {clean_url}")

    # Write output
    out_path = Path(output_file)
    if not out_path.is_absolute():
        out_path = repo_root / out_path

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(target_data, f, indent=2)

    print(f"💾 OpenAPI specification successfully generated at '{out_path}'")

    # Validate specification using SentinelAPI parser
    try:
        from sentinelapi.api_source.spec_parser import validate_and_parse_spec

        is_valid, parsed, logs = validate_and_parse_spec(str(out_path))
        if is_valid and parsed:
            print("\n========================================================")
            print("✅ OPENAPI SPECIFICATION VALIDATION: PASSED")
            print(f"• Title:       {parsed.title}")
            print(f"• Version:     {parsed.version}")
            print(f"• Endpoints:   {len(parsed.endpoints)} routes discovered")
            print(f"• Auth Scheme: {parsed.auth_scheme}")
            print(f"• Target URL:  {parsed.base_url}")
            print("========================================================")
            return True
        else:
            print("\n❌ OPENAPI SPECIFICATION VALIDATION: FAILED", file=sys.stderr)
            for log in logs:
                print(f"  - {log}", file=sys.stderr)
            return False
    except ImportError:
        print("⚠️  Warning: SentinelAPI not in python path; syntax valid JSON generated.")
        return True


def main():
    parser = argparse.ArgumentParser(
        description="SentinelAPI — Automated OpenAPI Specification Generator & Validator"
    )
    parser.add_argument(
        "--source",
        type=str,
        default="sandbox_openapi.json",
        help="Source OpenAPI specification path to enrich/update",
    )
    parser.add_argument(
        "--backend-dir",
        type=str,
        default="backend",
        help="Path to backend directory containing modular OpenAPI specs",
    )
    parser.add_argument(
        "--base-url",
        type=str,
        help="Live deployment URL (e.g. Vercel preview URL) to inject into servers block",
    )
    parser.add_argument(
        "--output",
        type=str,
        default="sandbox_openapi.json",
        help="Output JSON file destination (default: sandbox_openapi.json)",
    )
    parser.add_argument(
        "--merge-backend",
        action="store_true",
        help="Discover and merge all backend/*/*.json specs into one unified specification",
    )

    args = parser.parse_args()

    success = generate_openapi_spec(
        source_spec=args.source,
        backend_dir=args.backend_dir,
        base_url=args.base_url,
        output_file=args.output,
        merge_backend=args.merge_backend,
    )

    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
