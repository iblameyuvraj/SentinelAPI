"""OpenAPI 3.x and Swagger 2.0 specification parser and validator."""
import json
import os
import re
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple
import yaml
import httpx


class APIEndpointInfo:
    """Represents a discovered endpoint."""

    def __init__(
        self,
        path: str,
        method: str,
        summary: str = "",
        parameters: Optional[List[Dict[str, Any]]] = None,
        auth_required: bool = True,
        tags: Optional[List[str]] = None,
    ):
        self.path = path
        self.method = method.upper()
        self.summary = summary
        self.parameters = parameters or []
        self.auth_required = auth_required
        self.tags = tags or []

    @property
    def identifier(self) -> str:
        return f"{self.method} {self.path}"

    @property
    def has_object_ids(self) -> bool:
        """Checks if the path has template variables like {userId}, {id}, {orderId}."""
        return bool(re.search(r"\{([^}]+)\}", self.path))


class ParsedSpecification:
    """Structured result of an OpenAPI/Swagger parse operation."""

    def __init__(
        self,
        title: str,
        version: str,
        spec_type: str,  # "OpenAPI 3.0", "OpenAPI 3.1", "Swagger 2.0"
        base_url: str,
        auth_scheme: str,
        endpoints: List[APIEndpointInfo],
        raw_spec: Dict[str, Any],
        source: str,
    ):
        self.title = title
        self.version = version
        self.spec_type = spec_type
        self.base_url = base_url
        self.auth_scheme = auth_scheme
        self.endpoints = endpoints
        self.raw_spec = raw_spec
        self.source = source

    @property
    def parameterized_endpoints(self) -> List[APIEndpointInfo]:
        return [ep for ep in self.endpoints if ep.has_object_ids]


def clean_input_path(raw_path: str) -> str:
    """Cleans file paths from drag-and-drop (strips leading/trailing spaces and quotes)."""
    p = raw_path.strip()
    # Strip enclosing quotes added by macOS Terminal drag & drop
    if (p.startswith('"') and p.endswith('"')) or (p.startswith("'") and p.endswith("'")):
        p = p[1:-1]
    # Expand home directory (~)
    return str(Path(p).expanduser().resolve())


def validate_and_parse_spec(file_path_or_url: str) -> Tuple[bool, Optional[ParsedSpecification], List[str]]:
    """Validates and parses an OpenAPI/Swagger specification from file path or URL.
    
    Returns:
        (is_valid, parsed_spec, log_messages)
    """
    logs: List[str] = []
    source = file_path_or_url.strip()

    raw_data: Optional[Dict[str, Any]] = None

    # Case 1: Remote URL
    if source.startswith("http://") or source.startswith("https://"):
        logs.append(f"Connecting to remote URL: {source}")
        try:
            resp = httpx.get(source, timeout=8.0)
            if resp.status_code != 200:
                logs.append(f"HTTP Error {resp.status_code}: Unable to fetch URL")
                return False, None, logs
            logs.append("✓ Connected and fetched content")
            try:
                raw_data = resp.json()
            except Exception:
                raw_data = yaml.safe_load(resp.text)
        except Exception as e:
            logs.append(f"Network error: {str(e)}")
            return False, None, logs

    # Case 2: Local File Path
    else:
        clean_path = clean_input_path(source)
        logs.append(f"Checking path: {clean_path}")

        if not os.path.exists(clean_path):
            logs.append(f"File not found: '{clean_path}'")
            return False, None, logs

        logs.append("✓ File found")

        # Validate extension
        suffix = Path(clean_path).suffix.lower()
        if suffix not in [".json", ".yaml", ".yml"]:
            logs.append(f"Warning: Extension '{suffix}' is not standard (.json, .yaml, .yml)")

        try:
            with open(clean_path, "r", encoding="utf-8") as f:
                content = f.read()

            try:
                raw_data = json.loads(content)
                logs.append("✓ Valid JSON format detected")
            except json.JSONDecodeError:
                try:
                    raw_data = yaml.safe_load(content)
                    logs.append("✓ Valid YAML format detected")
                except Exception as ye:
                    logs.append(f"Invalid file format: Could not parse as JSON or YAML ({ye})")
                    return False, None, logs
        except Exception as e:
            logs.append(f"Read error: {str(e)}")
            return False, None, logs

    if not isinstance(raw_data, dict):
        logs.append("Specification must be a JSON/YAML dictionary/object")
        return False, None, logs

    # Identify Specification Standard
    spec_type = "Unknown"
    if "openapi" in raw_data:
        ver = str(raw_data.get("openapi", "3.0.0"))
        spec_type = f"OpenAPI {ver}"
        logs.append(f"✓ {spec_type} detected")
    elif "swagger" in raw_data:
        ver = str(raw_data.get("swagger", "2.0"))
        spec_type = f"Swagger {ver}"
        logs.append(f"✓ {spec_type} detected")
    else:
        # Fallback if structure looks like API spec
        if "paths" in raw_data:
            spec_type = "OpenAPI / Swagger (Inferred)"
            logs.append("✓ API paths specification detected")
        else:
            logs.append("File is missing 'openapi', 'swagger', or 'paths' root keys")
            return False, None, logs

    info = raw_data.get("info", {})
    title = info.get("title", "Target API")
    version = info.get("version", "1.0.0")

    # Infer base URL
    base_url = "http://localhost:8000"
    if "servers" in raw_data and isinstance(raw_data["servers"], list) and raw_data["servers"]:
        s_url = raw_data["servers"][0].get("url", "")
        if s_url and not s_url.startswith("/"):
            base_url = s_url
    elif "host" in raw_data:
        schemes = raw_data.get("schemes", ["http"])
        base_url = f"{schemes[0]}://{raw_data['host']}{raw_data.get('basePath', '')}".rstrip("/")

    # Detect Auth scheme
    auth_scheme = "None"
    components = raw_data.get("components", {})
    sec_schemes = components.get("securitySchemes", {}) or raw_data.get("securityDefinitions", {})

    for s_name, s_details in sec_schemes.items():
        if isinstance(s_details, dict):
            stype = str(s_details.get("type", "")).lower()
            scheme = str(s_details.get("scheme", "")).lower()
            if scheme == "bearer" or "bearer" in s_name.lower():
                auth_scheme = "Bearer JWT"
                break
            elif stype == "apikey":
                auth_scheme = f"API Key ({s_details.get('name', 'X-API-Key')})"
                break
            elif scheme == "basic" or stype == "basic":
                auth_scheme = "Basic Auth"
                break

    if auth_scheme == "None" and ("security" in raw_data or sec_schemes):
        auth_scheme = "Bearer Token (Default)"

    # Extract endpoints
    endpoints: List[APIEndpointInfo] = []
    paths = raw_data.get("paths", {})

    for path_str, path_item in paths.items():
        if not isinstance(path_item, dict):
            continue

        for method in ["get", "post", "put", "delete", "patch"]:
            if method in path_item:
                op = path_item[method]
                if not isinstance(op, dict):
                    continue

                summary = op.get("summary") or op.get("description", "")
                params = op.get("parameters", [])
                tags = op.get("tags", [])

                endpoints.append(
                    APIEndpointInfo(
                        path=path_str,
                        method=method,
                        summary=summary,
                        parameters=params,
                        tags=tags,
                    )
                )

    logs.append(f"✓ {len(endpoints)} endpoints discovered")
    logs.append("✓ Specification parsed successfully")

    parsed = ParsedSpecification(
        title=title,
        version=version,
        spec_type=spec_type,
        base_url=base_url,
        auth_scheme=auth_scheme,
        endpoints=endpoints,
        raw_spec=raw_data,
        source=source,
    )

    return True, parsed, logs
