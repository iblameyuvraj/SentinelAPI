# SentinelAPI System Architecture

## Overview
**SentinelAPI** is an AI-powered, Zero-Trust API Vulnerability Scanner built for developers, AppSec teams, and automated CI/CD pipelines. It ingests OpenAPI/Swagger specifications, identifies attack surfaces, dynamically generates cross-tenant test scenarios across 7 OWASP API categories, leverages LLM reasoning for deep exploit analysis and remediation, and delivers executive PDFs and automated CI gates.

---

## High-Level Architecture Diagram

![SentinelAPI System Architecture](sentinel_architecture.jpg)

### Component Topology (Mermaid)

```mermaid
flowchart TD
    %% ─────────────────────────────────────────────────────────────
    %% STYLES & CONFIG
    %% ─────────────────────────────────────────────────────────────
    classDef inputLayer fill:#1e293b,stroke:#38bdf8,stroke-width:2px,color:#f8fafc;
    classDef coreLayer fill:#0f172a,stroke:#818cf8,stroke-width:2px,color:#f8fafc;
    classDef moduleLayer fill:#1e1e38,stroke:#ec4899,stroke-width:2px,color:#f8fafc;
    classDef aiLayer fill:#1f2937,stroke:#a855f7,stroke-width:2px,color:#f8fafc;
    classDef reportLayer fill:#064e3b,stroke:#10b981,stroke-width:2px,color:#f8fafc;
    classDef cicdLayer fill:#451a03,stroke:#f59e0b,stroke-width:2px,color:#f8fafc;

    %% ─────────────────────────────────────────────────────────────
    %% LAYER 1: INGESTION
    %% ─────────────────────────────────────────────────────────────
    subgraph Ingestion ["1. INGESTION & ATTACK SURFACE DISCOVERY"]
        SPEC_FILE["OpenAPI / Swagger Spec\n(.json, .yaml, .yml)"]:::inputLayer
        LIVE_URL["Target Base URL\n(Live Service / Preview Deployment)"]:::inputLayer
        SPEC_PARSER["Specification Parser\n(spec_parser.py)\n• Route Cataloging\n• Parameter Extraction\n• Auth Scheme Derivation"]:::inputLayer
    end

    SPEC_FILE --> SPEC_PARSER
    LIVE_URL --> SPEC_PARSER

    %% ─────────────────────────────────────────────────────────────
    %% LAYER 2: ORCHESTRATION CORE
    %% ─────────────────────────────────────────────────────────────
    subgraph Core ["2. TEST ORCHESTRATION ENGINE"]
        CLI_HEADLESS["CI/Headless Runner\n(CLI Flags: --spec, --base-url, --ci)"]:::coreLayer
        CLI_INTERACTIVE["Interactive Cyber Terminal\n(Rich / Questionary / Custom Theme)"]:::coreLayer
        MASTER_SCAN["Master Scan Pipeline\n(master_scan.py)"]:::coreLayer
        IDENTITY_ENGINE["Dual-Tenant Identity Generator\n• Victim (User A Session)\n• Attacker (User B Session)\n• Smart Parameter Fuzzer"]:::coreLayer
    end

    SPEC_PARSER --> CLI_HEADLESS
    SPEC_PARSER --> CLI_INTERACTIVE
    CLI_HEADLESS --> MASTER_SCAN
    CLI_INTERACTIVE --> MASTER_SCAN
    MASTER_SCAN --> IDENTITY_ENGINE

    %% ─────────────────────────────────────────────────────────────
    %% LAYER 3: 7x OWASP MODULES
    %% ─────────────────────────────────────────────────────────────
    subgraph Modules ["3. 7x OWASP API VULNERABILITY DETECTORS"]
        direction TB
        M1["OWASP API1:2023\nBOLA / IDOR\nCross-tenant object leak test"]:::moduleLayer
        M2["OWASP API2:2023\nAuth Misconfiguration\n'none' alg & unauth bypass"]:::moduleLayer
        M3["OWASP API3:2023\nExcessive Data Exposure\nSchema diff & PII leak detector"]:::moduleLayer
        M4["OWASP API4:2023\nRate Limiting\nBurst probe & 429 validation"]:::moduleLayer
        M5["OWASP API5:2023\nBFLA\nRole elevation & admin probe"]:::moduleLayer
        M6["OWASP API8:2023\nSecurity Misconfiguration\nCORS, HSTS, CSP, Cookies"]:::moduleLayer
        M7["OWASP API9:2023\nShadow & Zombie APIs\nUnmapped routes & legacy /v1 fuzzing"]:::moduleLayer
    end

    IDENTITY_ENGINE --> M1
    IDENTITY_ENGINE --> M2
    IDENTITY_ENGINE --> M3
    IDENTITY_ENGINE --> M4
    IDENTITY_ENGINE --> M5
    IDENTITY_ENGINE --> M6
    IDENTITY_ENGINE --> M7

    %% ─────────────────────────────────────────────────────────────
    %% LAYER 4: TARGET EXECUTION & TELEMETRY
    %% ─────────────────────────────────────────────────────────────
    TARGET_API[("Target API Under Test\n(Live Endpoints / Sandboxed Mock Servers)")]
    M1 <-->|HTTP Probes & Responses| TARGET_API
    M2 <-->|HTTP Probes & Responses| TARGET_API
    M3 <-->|HTTP Probes & Responses| TARGET_API
    M4 <-->|HTTP Probes & Responses| TARGET_API
    M5 <-->|HTTP Probes & Responses| TARGET_API
    M6 <-->|HTTP Probes & Responses| TARGET_API
    M7 <-->|HTTP Probes & Responses| TARGET_API

    %% ─────────────────────────────────────────────────────────────
    %% LAYER 5: AI REASONING
    %% ─────────────────────────────────────────────────────────────
    subgraph AI ["4. AI SYNTHESIS & THREAT REASONING"]
        AI_GATEWAY["Multi-Provider LLM Gateway\n(Google Gemini / Claude / OpenAI / Local)"]:::aiLayer
        PROMPT_BUILDER["Telemetry Prompt Synthesizer\n(Token Estimation & Metric Aggregation)"]:::aiLayer
        AI_OUTPUT["AI Security Dossier\n• Vulnerability Explanations\n• CVSS 3.1 Scoring\n• Remediation Code Blueprints"]:::aiLayer
    end

    M1 & M2 & M3 & M4 & M5 & M6 & M7 --> PROMPT_BUILDER
    PROMPT_BUILDER --> AI_GATEWAY
    AI_GATEWAY --> AI_OUTPUT

    %% ─────────────────────────────────────────────────────────────
    %% LAYER 6: OUTPUTS & REPORTING
    %% ─────────────────────────────────────────────────────────────
    subgraph Reporting ["5. REPORTING & ARTIFACT DELIVERY"]
        TERM_DASH["Interactive Terminal Dashboard\n(Colored Status Matrix & Risk Gauges)"]:::reportLayer
        PDF_ENGINE["Dual-View Executive PDF Engine\n(pdf_generator.py)\n• Executive Summary (Leadership)\n• Technical Dossier + PoC cURLs (Devs)"]:::reportLayer
        EMAIL_ALERT["Brevo Automated Dispatch\n(email_service.py)\nPDFs attached to Security Alert"]:::reportLayer
        ARTIFACTS["Audit Files (.md, .json)\nin /markdown & /reports"]:::reportLayer
    end

    AI_OUTPUT --> TERM_DASH
    AI_OUTPUT --> PDF_ENGINE
    AI_OUTPUT --> ARTIFACTS
    PDF_ENGINE --> EMAIL_ALERT

    %% ─────────────────────────────────────────────────────────────
    %% LAYER 7: DEVSECOPS & CI/CD
    %% ─────────────────────────────────────────────────────────────
    subgraph CICD ["6. DEVSECOPS & CI/CD GATE"]
        DOCKER["Production Docker Container\n(python:3.11-slim, entrypoint: sentinel)"]:::cicdLayer
        GITHUB_ACTIONS["GitHub Actions Security Gate\n(fluffwalks-web-ci-workflow.yml)"]:::cicdLayer
        PR_GATE["Fail-Closed Deployment Blocker\nExit 0: PASS | Exit 1: FAIL | Exit 2: ERROR"]:::cicdLayer
    end

    DOCKER --> GITHUB_ACTIONS
    GITHUB_ACTIONS --> MASTER_SCAN
    REPORTING --> PR_GATE
```

---

## End-to-End Execution Sequence Flow

```mermaid
sequenceDiagram
    autonumber
    actor Dev as Developer / CI Runner
    participant CLI as SentinelAPI Core
    participant Parser as Spec Parser
    participant Engine as Scanner Modules (7x)
    participant Target as Target API
    participant AI as Gemini / LLM Engine
    participant Reporter as PDF & Email Service

    Dev->>CLI: Launch scan (Interactive or Headless --spec)
    CLI->>Parser: Load OpenAPI / Swagger Spec
    Parser-->>CLI: Return Endpoints, Params, Auth Scheme
    CLI->>Engine: Initialize Test Identities (Victim vs Attacker)

    loop Execute 7 OWASP Modules
        Engine->>Target: 1. Baseline Request (Legitimate Owner)
        Target-->>Engine: HTTP Response (e.g. 200 OK)
        Engine->>Target: 2. Cross-Tenant / Attack Probe (Attacker Token)
        Target-->>Engine: HTTP Response (e.g. 200 OK leaked or 403 Protected)
        Engine->>Engine: Record status, latency, response body diff & PoC cURL
    end

    Engine-->>CLI: Consolidated Security Telemetry Matrix
    CLI->>AI: Send Scan Telemetry & Spec Context
    AI-->>CLI: Executive Analysis, CVSS Scores & Code Remediation
    CLI->>Reporter: Generate vulnerabilities.pdf & all_logs.pdf
    Reporter->>Dev: Render Terminal Matrix & Save Artifacts
    Reporter-->>Dev: Dispatch Executive Email Alert via Brevo
    CLI->>Dev: Exit with Status Code (0: Pass, 1: Fail, 2: Error)
```

---

## Core Architectural Components

### 1. Ingestion & Attack Surface Modeling
* **OpenAPI / Swagger Ingestion:** Parses OpenAPI 3.0 and Swagger 2.0 specifications in JSON or YAML format. Extracts route paths, methods, request bodies, query/path parameters, and authentication schemes.
* **Dynamic Parameter Mapping:** Identifies parameterized routes (e.g. `/users/{userId}/orders/{orderId}`) and infers parameter data types (UUID, integer, slug) to generate realistic test values.

### 2. Dual-Tenant Authorization Testing Engine
* **Cross-Tenant Probing:** Implements Zero-Trust validation by executing baseline queries with a legitimate resource owner's token (User A), followed by identical requests using an unprivileged or cross-tenant identity (User B).
* **Verdict Evaluation:** Differentiates between secured endpoints (401/403/404) and leaked boundaries (200 OK returning victim object data).

### 3. The 7 OWASP API Security Modules
1. **BOLA / IDOR (`bola_idor`):** Tests unauthorized access to object-level records across users.
2. **Authentication Misconfiguration (`Authentication_Misconfiguration`):** Tests missing auth, spoofed tokens, expired tokens, and `alg: none` JWTs.
3. **Excessive Data Exposure (`Excessive_Data_Exposure`):** Compares returned JSON payload keys against documented OpenAPI schema; flags leaked PII (passwords, tokens, SSNs, salary, internal keys).
4. **Rate Limiting (`Rate_Limiting`):** Sends high-concurrency bursts (10/20/30 reqs) and validates HTTP 429 throttling and retry headers.
5. **BFLA / Privilege Escalation (`BFLA`):** Probes administrative and privileged endpoints using low-privilege member/viewer credentials.
6. **Security Misconfiguration (`Security_Misconfiguration`):** Audits missing security headers (HSTS, CSP, CORS, X-Frame-Options) and insecure cookie attributes (`HttpOnly`, `SameSite`, `Secure`).
7. **Shadow & Zombie APIs (`Shadow_Zombie_APIs`):** Fuzzes undocumented legacy version prefixes (`/v1`, `/v2`, `/beta`, `/internal`) to uncover unmaintained endpoints.

### 4. AI Reasoning & Threat Synthesis
* Integrates with Google Gemini, Claude, OpenAI, and custom OpenAI-compatible local models.
* Generates technical dossiers explaining the business impact, calculated CVSS 3.1 vector, root-cause vulnerability analysis, and code-level remediation blueprints for engineers.

### 5. Multi-Stakeholder Reporting & Artifact Generation
* **Executive Summary:** High-level risk score, OWASP compliance radar, and total vulnerability count designed for CTOs and security managers.
* **Engineering Dossier:** Technical deep-dive with copy-pasteable, reproducible `curl` commands, request/response headers, and response payload diffs.
* **Automated Dispatch:** Built-in Brevo transactional email engine attaches PDF reports and delivers instant notifications to engineering teams.

### 6. DevSecOps CI/CD Integration
* **Fail-Closed Gate:** Emits standard non-zero exit codes to block GitHub PR merges when critical vulnerabilities are found (`Exit 0`: Clean Pass, `Exit 1`: Vulnerabilities Detected, `Exit 2`: Unreachable Host / Target Error).
* **Vercel Preview Auto-Discovery:** Seamlessly discovers and polls dynamic preview deployment URLs before running the audit suite.
