"""SentinelAPI Core Data Models & Fail-Closed Status Schema.

Provides clean, structured dataclasses for Findings, Probe Errors, Module Scan Results,
and Master Scan Results.

Strict Fail-Closed Rules:
  - Vulnerability found            → FAIL
  - Zero probes succeeded / error  → ERROR
  - Any probe failed / unreached   → INCOMPLETE
  - All planned probes succeeded
    and zero vulnerabilities found → PASS

Never allows false green results when targets are offline or network probes fail.
"""
from dataclasses import dataclass, field, asdict
from typing import List, Optional, Dict, Any
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class ScanStatus(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    ERROR = "ERROR"
    INCOMPLETE = "INCOMPLETE"


@dataclass
class ProbeError:
    """Represents an HTTP request or connectivity failure during scanning."""
    endpoint: str
    method: str
    error_message: str
    target_url: str
    status_code: int = 0
    phase: str = "network_probe"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Finding:
    """Represents a single vulnerability finding or audit check outcome."""
    id: str
    title: str
    description: str
    severity: str  # "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"
    endpoint: str
    method: str
    owasp_category: str  # e.g. "API1:2023 - BOLA / IDOR"
    cwe: Optional[str] = None
    evidence: Optional[str] = None  # HTTP status, leaked JSON payload snippet, missing header
    status_code: Optional[int] = None
    reproduction_curl: Optional[str] = None
    remediation: Optional[str] = None
    is_vulnerable: bool = True
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ScanResult:
    """Structured result returned by a scanner module with strict fail-closed accounting."""
    scanner_id: str
    scanner_name: str
    owasp_category: str
    planned_probes: int = 0
    successful_probes: int = 0
    failed_probes: int = 0
    findings: List[Finding] = field(default_factory=list)
    probe_errors: List[ProbeError] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    raw_telemetry: Dict[str, Any] = field(default_factory=dict)
    duration_seconds: float = 0.0

    @property
    def scanned_count(self) -> int:
        return self.successful_probes

    @property
    def vulnerable_findings(self) -> List[Finding]:
        """Returns all confirmed vulnerability findings."""
        return [f for f in self.findings if f.is_vulnerable and f.severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW")]

    @property
    def is_vulnerable(self) -> bool:
        """True if one or more vulnerabilities were discovered."""
        return len(self.vulnerable_findings) > 0

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.vulnerable_findings if f.severity == "CRITICAL")

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.vulnerable_findings if f.severity == "HIGH")

    @property
    def medium_count(self) -> int:
        return sum(1 for f in self.vulnerable_findings if f.severity == "MEDIUM")

    @property
    def low_count(self) -> int:
        return sum(1 for f in self.vulnerable_findings if f.severity == "LOW")

    @property
    def status(self) -> str:
        """Computes strict fail-closed status.

        Rules:
          1. Any vulnerability found -> FAIL
          2. Zero successful probes (or fatal error) -> ERROR
          3. Any failed probe / network error -> INCOMPLETE
          4. All planned probes succeeded and 0 vulns -> PASS
        """
        if self.is_vulnerable:
            return ScanStatus.FAIL.value

        if self.planned_probes > 0 and self.successful_probes == 0:
            return ScanStatus.ERROR.value

        if self.errors and self.successful_probes == 0:
            return ScanStatus.ERROR.value

        if self.failed_probes > 0 or len(self.probe_errors) > 0 or self.errors:
            return ScanStatus.INCOMPLETE.value

        if self.planned_probes > 0 and self.successful_probes >= self.planned_probes:
            return ScanStatus.PASS.value

        if self.planned_probes == 0 and not self.errors and not self.probe_errors:
            return ScanStatus.PASS.value

        return ScanStatus.ERROR.value

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scanner_id": self.scanner_id,
            "scanner_name": self.scanner_name,
            "owasp_category": self.owasp_category,
            "status": self.status,
            "planned_probes": self.planned_probes,
            "successful_probes": self.successful_probes,
            "failed_probes": self.failed_probes,
            "is_vulnerable": self.is_vulnerable,
            "vulnerability_counts": {
                "critical": self.critical_count,
                "high": self.high_count,
                "medium": self.medium_count,
                "low": self.low_count,
                "total": len(self.vulnerable_findings),
            },
            "findings": [f.to_dict() for f in self.findings],
            "probe_errors": [pe.to_dict() for pe in self.probe_errors],
            "errors": self.errors,
            "duration_seconds": self.duration_seconds,
        }


@dataclass
class MasterScanResult:
    """Aggregated outcome of the entire full-suite security scan."""
    target_title: str
    base_url: str
    spec_version: str
    auth_scheme: str
    total_endpoints: int
    module_results: Dict[str, ScanResult] = field(default_factory=dict)
    start_time: str = ""
    end_time: str = ""
    ai_report_markdown: Optional[str] = None

    @property
    def all_vulnerable_findings(self) -> List[Finding]:
        res = []
        for r in self.module_results.values():
            res.extend(r.vulnerable_findings)
        return res

    @property
    def all_probe_errors(self) -> List[ProbeError]:
        res = []
        for r in self.module_results.values():
            res.extend(r.probe_errors)
        return res

    @property
    def is_vulnerable(self) -> bool:
        return any(r.is_vulnerable for r in self.module_results.values())

    @property
    def total_planned_probes(self) -> int:
        return sum(r.planned_probes for r in self.module_results.values())

    @property
    def total_successful_probes(self) -> int:
        return sum(r.successful_probes for r in self.module_results.values())

    @property
    def total_failed_probes(self) -> int:
        return sum(r.failed_probes for r in self.module_results.values())

    @property
    def total_critical(self) -> int:
        return sum(r.critical_count for r in self.module_results.values())

    @property
    def total_high(self) -> int:
        return sum(r.high_count for r in self.module_results.values())

    @property
    def total_medium(self) -> int:
        return sum(r.medium_count for r in self.module_results.values())

    @property
    def total_low(self) -> int:
        return sum(r.low_count for r in self.module_results.values())

    @property
    def status(self) -> str:
        """Overall Master Assessment Status.

        Rules:
          - If any module found vulnerabilities -> FAIL
          - If any module is ERROR (unreachable target / 0 probes succeeded) -> ERROR
          - If any module is INCOMPLETE (probes failed / partial coverage) -> INCOMPLETE
          - If all modules PASS -> PASS
        """
        if self.is_vulnerable:
            return ScanStatus.FAIL.value

        statuses = [r.status for r in self.module_results.values()]
        if not statuses:
            return ScanStatus.ERROR.value

        if any(s == ScanStatus.ERROR.value for s in statuses):
            return ScanStatus.ERROR.value

        if any(s == ScanStatus.INCOMPLETE.value for s in statuses):
            return ScanStatus.INCOMPLETE.value

        if all(s == ScanStatus.PASS.value for s in statuses):
            return ScanStatus.PASS.value

        return ScanStatus.ERROR.value

    @property
    def exit_code(self) -> int:
        """Standard CI/CD exit code mapping (0, 1, 2).

        0 = PASS (Clean, all probes verified, zero vulnerabilities)
        1 = FAIL (Security vulnerabilities confirmed)
        2 = ERROR (Target offline, incomplete/failed probes, or fatal error)
        """
        st = self.status
        if st == ScanStatus.PASS.value:
            return 0
        elif st == ScanStatus.FAIL.value:
            return 1
        elif st == ScanStatus.ERROR.value or st == ScanStatus.INCOMPLETE.value:
            return 2
        return 2

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target_title": self.target_title,
            "base_url": self.base_url,
            "spec_version": self.spec_version,
            "auth_scheme": self.auth_scheme,
            "total_endpoints": self.total_endpoints,
            "status": self.status,
            "exit_code": self.exit_code,
            "coverage": {
                "planned_probes": self.total_planned_probes,
                "successful_probes": self.total_successful_probes,
                "failed_probes": self.total_failed_probes,
            },
            "is_vulnerable": self.is_vulnerable,
            "summary": {
                "total_vulnerabilities": len(self.all_vulnerable_findings),
                "critical": self.total_critical,
                "high": self.total_high,
                "medium": self.total_medium,
                "low": self.total_low,
            },
            "modules": {k: v.to_dict() for k, v in self.module_results.items()},
        }
