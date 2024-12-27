# API Documentation

## Core Modules

### O1 Analyzer

The O1 Analyzer module provides advanced security analysis using OpenAI's O1 model.

```python
from tools.analysis.o1_analyzer import O1Analyzer

analyzer = O1Analyzer()
results = await analyzer.analyze_code(code_snippet, context)
```

#### Methods

- `analyze_code(code: str, context: Dict[str, Any]) -> AnalysisResult`
- `analyze_endpoint(endpoint: WebEndpoint, context: Dict[str, Any]) -> List[VulnerabilityReport]`
- `analyze_chain(chain: List[ChainableVulnerability]) -> ChainAnalysisResult`

### Scope Manager

Manages bug bounty scope and validates findings against program rules.

```python
from tools.analysis.scope_manager import ScopeManager

scope_manager = ScopeManager("config/scope.yaml")
status = scope_manager.check_scope(finding)
```

#### Methods

- `check_scope(finding: Dict[str, Any]) -> ScopeStatus`
- `validate_target(target: str) -> bool`
- `is_vulnerability_allowed(vuln_type: str) -> bool`

### Bug Bounty Analyzer

Comprehensive analysis tool combining multiple analysis techniques.

```python
from tools.analysis.bug_bounty_analyzer import BugBountyAnalyzer

analyzer = BugBountyAnalyzer()
findings = await analyzer.analyze_target(target)
```

#### Methods

- `analyze_target(target: BugBountyTarget) -> Dict[str, List[Finding]]`
- `identify_vulnerability_chains() -> List[VulnerabilityChain]`
- `generate_report(findings: List[Finding]) -> Report`

## Configuration

### Environment Variables

Required environment variables in `.env`:

```bash
# API Configuration
LLM_API_ENDPOINT="https://api.openai.com/v1/..."
LLM_API_KEY="your-api-key"

# Rate Limiting
RATE_LIMIT_REQUESTS=100
RATE_LIMIT_PERIOD=60
RATE_LIMIT_BURST=10

# Caching
CACHE_TTL_HOURS=24
CACHE_MAX_ENTRIES=1000

# Logging
LOG_LEVEL=INFO
LOG_FILE=logs/recon.log

# Security Settings
ALLOWED_DOMAINS=example.com,*.example.com
MAX_PAYLOAD_SIZE=10485760
TIMEOUT_SECONDS=30
```

### Scope Configuration

Example `config/scope.yaml`:

```yaml
domains:
  primary:
    - example.com
  secondary:
    - api.example.com
    - dev.example.com

assets:
  web:
    endpoints:
      - /api/v1/*
      - /api/v2/*
  mobile:
    endpoints:
      - /mobile-api/*

vulnerability_types:
  qualifying:
    - rce
    - sqli
    - ssrf
    - auth_bypass
  excluded:
    - self_xss
    - rate_limit

special_conditions:
  ssrf:
    requires:
      - internal_impact
      - data_exposure
```

## Usage Examples

### Basic Vulnerability Scan

```python
from tools.analysis.bug_bounty_analyzer import BugBountyAnalyzer, BugBountyTarget

# Configure target
target = BugBountyTarget(
    domain="example.com",
    endpoints=["/api/v1/users", "/api/v1/admin"],
    technology_stack={
        "framework": "django",
        "database": "postgresql"
    },
    scope_rules={
        "allowed_paths": ["/api/*"],
        "excluded_paths": ["/api/health"]
    }
)

# Initialize analyzer
analyzer = BugBountyAnalyzer()

# Run analysis
findings = await analyzer.analyze_target(target)

# Process results
for severity, vulns in findings.items():
    print(f"{severity.upper()} Severity Findings:")
    for vuln in vulns:
        print(f"- {vuln['vulnerability_type']}: {vuln['description']}")
```

### Chain Analysis

```python
from tools.analysis.o1_chain_analyzer import O1ChainAnalyzer, ChainContext

# Initialize chain analyzer
chain_analyzer = O1ChainAnalyzer()

# Create analysis context
context = ChainContext(
    entry_points={"/api/v1/upload"},
    affected_components={"file_storage", "image_processor"},
    technology_stack={"python": "3.9", "framework": "fastapi"},
    security_controls={"waf": True, "input_validation": True}
)

# Analyze potential chains
chains = await chain_analyzer.analyze_chain(vulnerabilities, context)

# Process results
for chain in chains:
    print(f"Chain Impact: {chain.impact_score}")
    for step in chain.attack_steps:
        print(f"- {step}")
```
