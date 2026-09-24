"""Shadow & Zombie API Discovery Engine (OWASP API9:2023 - Improper Inventory Management).

Audits API hosts for:
- Zombie APIs: Deprecated, retired versions (/v1, /v0, /legacy) left active in production.
- Shadow APIs: Undocumented live endpoints (/beta, /export, /internal) omitted from OpenAPI specs.
- Exposed Diagnostics: Debug endpoints, Spring Actuators (/debug, /actuator, /metrics).
- Backup & Configuration Artifacts: Exposed config backups (*.old, *.bak, /.env, /.git).
"""

from typing import Dict, Any, List, Set, Optional
from dataclasses import dataclass
from sentinelapi.api_source.spec_parser import ParsedSpecification


@dataclass
class ShadowZombieVector:
    id: str
    name: str
    category: str
    path: str
    method: str
    description: str
    cwe: str
    severity: str


@dataclass
class ShadowZombieFinding:
    path: str
    method: str
    test_id: str
    test_name: str
    category: str
    status_code: int
    is_vulnerable: bool
    severity: str
    reason: str
    cwe: str
    reproduction_curl: str
    response_snippet: str
    remediation: str


# Common diagnostic and actuator probes
DIAGNOSTIC_PROBES = [
    ("/debug/server-vars", "GET", "INV-03-DIAG-DEBUG", "Exposed Diagnostic Server Variables", "CRITICAL"),
    ("/debug/vars", "GET", "INV-03-DIAG-DEBUG", "Exposed Go/Internal Debug Vars", "CRITICAL"),
    ("/actuator/health", "GET", "INV-04-ACTUATOR", "Exposed Spring Boot Actuator Health", "MEDIUM"),
    ("/actuator/env", "GET", "INV-04-ACTUATOR", "Exposed Spring Boot Actuator Environment", "CRITICAL"),
    ("/actuator/metrics", "GET", "INV-04-ACTUATOR", "Exposed Spring Boot Actuator Metrics", "MEDIUM"),
    ("/metrics", "GET", "INV-04-ACTUATOR", "Prometheus / System Metrics Endpoint", "MEDIUM"),
]

# Sensitive backup / config probes
BACKUP_PROBES = [
    ("/api/config.old", "GET", "INV-05-BACKUP-LEAK", "Exposed Configuration Backup File", "CRITICAL"),
    ("/config.json", "GET", "INV-05-BACKUP-LEAK", "Exposed Public Configuration File", "HIGH"),
    ("/.env", "GET", "INV-05-BACKUP-LEAK", "Exposed Root Environment File", "CRITICAL"),
    ("/.git/HEAD", "GET", "INV-05-BACKUP-LEAK", "Exposed Git Repository Metadata", "CRITICAL"),
]


def generate_shadow_zombie_vectors(spec: ParsedSpecification) -> List[ShadowZombieVector]:
    """Derives candidate Zombie, Shadow, and Diagnostic probe vectors based on the OpenAPI spec."""
    vectors: List[ShadowZombieVector] = []
    seen_paths: Set[str] = set()

    declared_paths = {ep.path.rstrip("/") for ep in spec.endpoints}

    # 1. Generate Zombie API vectors by version downgrading declared routes
    for ep in spec.endpoints:
        path = ep.path
        method = ep.method.upper()

        # If path contains /v2/, /v3/, etc., generate /v1/ and /v0/ candidates
        if "/v2/" in path:
            zombie_v1 = path.replace("/v2/", "/v1/")
            if zombie_v1 not in declared_paths and zombie_v1 not in seen_paths:
                seen_paths.add(zombie_v1)
                vectors.append(
                    ShadowZombieVector(
                        id="INV-01-ZOMBIE-V1",
                        name="Zombie API: Deprecated v1 Version Active",
                        category="Zombie API",
                        path=zombie_v1,
                        method=method,
                        description=f"Tests if deprecated v1 predecessor of '{path}' remains live on production.",
                        cwe="CWE-1050: Designation of Ineffective or Inappropriate Security Control",
                        severity="HIGH",
                    )
                )

        if "/v3/" in path:
            zombie_v2 = path.replace("/v3/", "/v2/")
            if zombie_v2 not in declared_paths and zombie_v2 not in seen_paths:
                seen_paths.add(zombie_v2)
                vectors.append(
                    ShadowZombieVector(
                        id="INV-01-ZOMBIE-V2",
                        name="Zombie API: Deprecated v2 Version Active",
                        category="Zombie API",
                        path=zombie_v2,
                        method=method,
                        description=f"Tests if deprecated v2 predecessor of '{path}' remains live on production.",
                        cwe="CWE-1050: Designation of Ineffective or Inappropriate Security Control",
                        severity="HIGH",
                    )
                )

        # 2. Generate Shadow candidate routes for common resources
        for kw in ("users", "products", "orders", "customers", "auth"):
            if kw in path.lower():
                beta_path = f"/api/v2/beta/export-{kw}" if "/v2/" in path else f"/api/beta/export-{kw}"
                if beta_path not in declared_paths and beta_path not in seen_paths:
                    seen_paths.add(beta_path)
                    vectors.append(
                        ShadowZombieVector(
                            id="INV-02-SHADOW-BETA",
                            name=f"Shadow API: Undocumented Beta Export ({kw})",
                            category="Shadow API",
                            path=beta_path,
                            method="GET",
                            description=f"Probes for undocumented bulk export and beta handler for '{kw}'.",
                            cwe="CWE-1059: Incomplete Documentation",
                            severity="CRITICAL",
                        )
                    )

    # Common legacy authentication zombie vector
    legacy_auth = "/api/v1/auth/legacy-login"
    if legacy_auth not in declared_paths and legacy_auth not in seen_paths:
        seen_paths.add(legacy_auth)
        vectors.append(
            ShadowZombieVector(
                id="INV-01-ZOMBIE-AUTH",
                name="Zombie API: Deprecated Authentication Bypass",
                category="Zombie API",
                path=legacy_auth,
                method="POST",
                description="Checks if retired legacy authentication endpoint bypasses current 2FA/MFA rules.",
                cwe="CWE-287: Improper Authentication",
                severity="HIGH",
            )
        )

    # 3. Add Diagnostic Probes
    for path, method, test_id, name, sev in DIAGNOSTIC_PROBES:
        if path not in declared_paths and path not in seen_paths:
            seen_paths.add(path)
            vectors.append(
                ShadowZombieVector(
                    id=test_id,
                    name=name,
                    category="Exposed Diagnostic",
                    path=path,
                    method=method,
                    description=f"Checks if system diagnostic or metric interface '{path}' is publicly exposed.",
                    cwe="CWE-200: Exposure of Sensitive Information to an Unauthorized Actor",
                    severity=sev,
                )
            )

    # 4. Add Backup / Config Probes
    for path, method, test_id, name, sev in BACKUP_PROBES:
        if path not in declared_paths and path not in seen_paths:
            seen_paths.add(path)
            vectors.append(
                ShadowZombieVector(
                    id=test_id,
                    name=name,
                    category="Backup / Config Leak",
                    path=path,
                    method=method,
                    description=f"Probes for exposed backup, configuration, or environment file at '{path}'.",
                    cwe="CWE-552: Files or Directories Accessible to External Parties",
                    severity=sev,
                )
            )

    return vectors


def evaluate_shadow_zombie_response(
    vector: ShadowZombieVector,
    status_code: int,
    response_body: str,
    headers: Dict[str, str],
    base_url: str,
    declared_paths: Set[str],
) -> ShadowZombieFinding:
    """Classifies whether an undocumented route represents a Zombie, Shadow, or Disclosed asset."""
    target_url = f"{base_url.rstrip('/')}/{vector.path.lstrip('/')}"
    poc_curl = f"curl -s -i -X {vector.method} \"{target_url}\""

    snippet = response_body.strip()
    if len(snippet) > 200:
        snippet = snippet[:197] + "..."

    is_vulnerable = False
    severity = "NONE"
    reason = f"PROTECTED: Endpoint is offline or properly denied with HTTP {status_code}."
    remediation = "Maintain current route inventory controls."

    # 1. Server returned 200, 201, 204: Endpoint is LIVE and completely undocumented!
    if status_code in (200, 201, 204):
        is_vulnerable = True
        severity = vector.severity

        if vector.category == "Zombie API":
            reason = (
                f"CRITICAL ZOMBIE API: Deprecated endpoint '{vector.path}' is actively running on production "
                f"and returned HTTP {status_code}. Deprecated APIs often lack modern authorization and security patches."
            )
            remediation = (
                "Permanently decommission legacy v1 endpoints. Return HTTP 410 Gone with a 'Sunset' header "
                "directing consumers to the active v2 API version."
            )
        elif vector.category == "Shadow API":
            reason = (
                f"CRITICAL SHADOW API: Undocumented live route '{vector.path}' was discovered running in production. "
                "Shadow endpoints operate outside security monitoring and governance."
            )
            remediation = (
                "Audit live codebase. Either document this endpoint formally in the OpenAPI specification "
                "or decommission it if it is an unapproved beta/internal hook."
            )
        elif vector.category == "Exposed Diagnostic":
            reason = (
                f"CRITICAL EXPOSURE: System diagnostic endpoint '{vector.path}' is publicly exposed (HTTP {status_code}), "
                "leaking internal system state, memory variables, or infrastructure metrics."
            )
            remediation = "Restrict access to internal networks/VPN or disable debug/actuator endpoints in production."
        else:
            reason = (
                f"CRITICAL ARTIFACT LEAK: Configuration or backup artifact '{vector.path}' is accessible over HTTP (HTTP {status_code})."
            )
            remediation = "Remove backup files (*.old, *.bak, .env, .git) from the web root and configure web server to deny access."

    # 2. Server returned 410 Gone: Properly decommissioned!
    elif status_code == 410:
        is_vulnerable = False
        severity = "NONE"
        sunset_hdr = headers.get("sunset", "Not specified")
        reason = f"PROTECTED: Deprecated endpoint correctly decommissioned with HTTP 410 Gone (Sunset: {sunset_hdr})."
        remediation = "None required. Decommissioning standard properly enforced."

    # 3. Server returned 401 or 403: Endpoint exists on router but requires credentials
    elif status_code in (401, 403):
        # If it's a diagnostic or beta route, its mere presence on production is an inventory hygiene issue
        if vector.category in ("Shadow API", "Exposed Diagnostic"):
            is_vulnerable = True
            severity = "MEDIUM"
            reason = (
                f"SHADOW ASSET DETECTED: Undocumented endpoint '{vector.path}' exists on the router (HTTP {status_code}), "
                "but is omitted from the official API documentation."
            )
            remediation = "Register endpoint in the official OpenAPI specification or remove route from production router."
        else:
            is_vulnerable = False
            severity = "NONE"
            reason = f"PROTECTED: Unauthorized access denied with HTTP {status_code}."

    # 4. Route not found (404) or connection failed (0)
    elif status_code == 404:
        is_vulnerable = False
        severity = "NONE"
        reason = f"PROTECTED: Route not present on server (HTTP 404)."

    elif status_code == 0:
        is_vulnerable = False
        severity = "NONE"
        reason = "Server unreachable / Connection failed."

    return ShadowZombieFinding(
        path=vector.path,
        method=vector.method,
        test_id=vector.id,
        test_name=vector.name,
        category=vector.category,
        status_code=status_code,
        is_vulnerable=is_vulnerable,
        severity=severity,
        reason=reason,
        cwe=vector.cwe,
        reproduction_curl=poc_curl,
        response_snippet=snippet,
        remediation=remediation,
    )
