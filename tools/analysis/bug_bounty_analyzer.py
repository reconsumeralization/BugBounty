from __future__ import annotations

from typing import List, Dict, Any, Optional, Set, cast
from dataclasses import dataclass
from enum import Enum
import logging
from pathlib import Path

from .o1_analyzer import O1Analyzer
from .scope_manager import ScopeManager, ScopeStatus
from .web_analyzer import WebVulnerabilityAnalyzer, WebEndpoint, WebVulnerabilityContext

# Constants for bug bounty specific settings
MAX_CONCURRENT_ANALYSIS: int = 5
CRITICAL_CONFIDENCE_THRESHOLD: float = 0.85
HIGH_CONFIDENCE_THRESHOLD: float = 0.80
DEFAULT_CONFIDENCE_THRESHOLD: float = 0.75

class BugBountyImpact(Enum):
    CRITICAL = "critical"  # RCE, Auth Bypass, Critical Data Leak
    HIGH = "high"         # SQLi, SSRF, Privilege Escalation
    MEDIUM = "medium"     # XSS, CSRF with impact
    LOW = "low"          # Info Disclosure, Config Issues

@dataclass
class ChainableVulnerability:
    """Represents a vulnerability that could be chained with others"""
    id: str
    vulnerability_type: str
    entry_points: Set[str]
    prerequisites: Set[str]
    impact: BugBountyImpact
    affected_components: Set[str]
    chain_probability: float = 0.0

@dataclass
class BugBountyTarget:
    """Represents a bug bounty target with relevant metadata"""
    domain: str
    endpoints: List[WebEndpoint]
    technology_stack: Dict[str, str]
    scope_rules: Dict[str, Any]
    known_vulnerabilities: List[str]
    reward_range: Dict[str, float]
    excluded_paths: Set[str]
    special_conditions: Dict[str, Any]

class BugBountyAnalyzer:
    """Advanced analyzer specifically for bug bounty hunting"""

    def __init__(
        self,
        scope_path: Path,
        config_path: Path,
        o1_analyzer: Optional[O1Analyzer] = None,
        web_analyzer: Optional[WebVulnerabilityAnalyzer] = None
    ):
        self.scope_manager = ScopeManager(scope_path)
        self.o1_analyzer = o1_analyzer or O1Analyzer()
        self.web_analyzer = web_analyzer or WebVulnerabilityAnalyzer()
        self.logger = logging.getLogger(__name__)
        self.vulnerability_chains: List[List[ChainableVulnerability]] = []
        self.high_value_targets: List[BugBountyTarget] = []

        # Load configurations
        self._load_config(config_path)
        self._setup_logging()

    def _load_config(self, config_path: Path) -> None:
        """Load bug bounty specific configurations"""
        # Implementation will load from config file
        pass

    def _setup_logging(self) -> None:
        """Configure specialized logging for bug bounty hunting"""
        self.logger.setLevel(logging.INFO)
        handler = logging.FileHandler('bug_bounty_analysis.log')
        handler.setFormatter(
            logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        )
        self.logger.addHandler(handler)

    async def analyze_target(self, target: BugBountyTarget) -> Dict[str, List[Dict[str, Any]]]:
        """Perform comprehensive analysis of a bug bounty target"""
        findings: Dict[str, List[Dict[str, Any]]] = {
            "critical": [],
            "high": [],
            "medium": [],
            "low": [],
            "potential_chains": []
        }

        # Analyze each endpoint
        for endpoint in target.endpoints:
            if self._is_endpoint_excluded(endpoint, target.excluded_paths):
                continue

            context = self._create_endpoint_context(endpoint, target)
            result = await self.web_analyzer.analyze_endpoint(
                self._generate_endpoint_code(endpoint),
                context
            )

            # Process and categorize findings
            self._process_findings(cast(Dict[str, Any], result), findings, target)

        # Look for vulnerability chains
        chains = self._identify_vulnerability_chains(findings)
        if chains:
            findings["potential_chains"].extend(chains)

        return findings

    def _is_endpoint_excluded(self, endpoint: WebEndpoint, excluded_paths: Set[str]) -> bool:
        """Check if endpoint is excluded from scope"""
        return any(
            endpoint.url.startswith(excluded)
            for excluded in excluded_paths
        )

    def _create_endpoint_context(
        self,
        endpoint: WebEndpoint,
        target: BugBountyTarget
    ) -> WebVulnerabilityContext:
        """Create context for endpoint analysis"""
        auth_type = "none"
        if endpoint.authentication and isinstance(endpoint.authentication, dict):
            auth_type = str(endpoint.authentication.get("type", "none"))

        return WebVulnerabilityContext(
            framework=target.technology_stack.get("framework", "unknown"),
            endpoint=endpoint,
            dependencies=[{"name": k, "version": v} for k, v in target.technology_stack.items()],
            security_headers={},  # Will be populated during analysis
            authentication_type=auth_type,
            input_validation={}  # Will be populated during analysis
        )

    def _generate_endpoint_code(self, endpoint: WebEndpoint) -> str:
        """Generate code representation of endpoint for analysis"""
        # Implementation will generate code representation
        return ""

    def _process_findings(
        self,
        result: Dict[str, Any],
        findings: Dict[str, List[Dict[str, Any]]],
        target: BugBountyTarget
    ) -> None:
        """Process and categorize findings based on bug bounty criteria"""
        for finding in result.get("findings", []):
            if not isinstance(finding, dict):
                continue

            # Skip if confidence doesn't meet threshold
            if not self._meets_confidence_threshold(finding):
                continue

            # Validate finding is in scope
            scope_status = self.scope_manager.check_scope(finding)
            if scope_status != ScopeStatus.IN_SCOPE:
                continue

            # Check for special conditions
            if self._requires_special_conditions(finding, target):
                finding["requires_special_conditions"] = True

            # Add to appropriate category
            severity = str(finding.get("severity", "low")).lower()
            if severity in findings:
                findings[severity].append(finding)

            # Check if finding can be part of a chain
            if self._is_chainable(finding):
                self._add_to_chainable(finding)

    def _meets_confidence_threshold(self, finding: Dict[str, Any]) -> bool:
        """Check if finding meets confidence threshold for its severity"""
        confidence = float(finding.get("confidence", 0))
        severity = str(finding.get("severity", "low")).lower()

        thresholds = {
            "critical": CRITICAL_CONFIDENCE_THRESHOLD,
            "high": HIGH_CONFIDENCE_THRESHOLD
        }

        return confidence >= thresholds.get(severity, DEFAULT_CONFIDENCE_THRESHOLD)

    def _requires_special_conditions(
        self,
        finding: Dict[str, Any],
        target: BugBountyTarget
    ) -> bool:
        """Check if finding requires special conditions to be valid"""
        vuln_type = str(finding.get("vulnerability_type", ""))
        if vuln_type in target.special_conditions:
            conditions = target.special_conditions[vuln_type]
            # Check if finding meets special conditions
            return self._validate_special_conditions(finding, conditions)
        return False

    def _validate_special_conditions(
        self,
        finding: Dict[str, Any],
        conditions: Dict[str, Any]
    ) -> bool:
        """Validate if finding meets special conditions"""
        required_conditions = conditions.get("requires", [])
        for condition in required_conditions:
            if not self._check_condition(finding, condition):
                return False
        return True

    def _check_condition(self, finding: Dict[str, Any], condition: str) -> bool:
        """Check if finding meets a specific condition"""
        # Implementation will check specific conditions
        return True

    def _is_chainable(self, finding: Dict[str, Any]) -> bool:
        """Determine if finding can be part of a vulnerability chain"""
        chainable_types = {
            "ssrf",
            "xss",
            "sql_injection",
            "file_upload",
            "path_traversal",
            "deserialization"
        }
        return str(finding.get("vulnerability_type", "")).lower() in chainable_types

    def _add_to_chainable(self, finding: Dict[str, Any]) -> None:
        """Add finding to chainable vulnerabilities"""
        chainable = ChainableVulnerability(
            id=str(finding.get("id", "")),
            vulnerability_type=str(finding.get("vulnerability_type", "")),
            entry_points=set(str(ep) for ep in finding.get("entry_points", [])),
            prerequisites=set(str(p) for p in finding.get("prerequisites", [])),
            impact=BugBountyImpact(str(finding.get("severity", "low")).lower()),
            affected_components=set(str(ac) for ac in finding.get("affected_components", [])),
            chain_probability=float(finding.get("confidence", 0.0))
        )

        # Find potential chains
        self._update_vulnerability_chains(chainable)

    def _update_vulnerability_chains(self, new_vuln: ChainableVulnerability) -> None:
        """Update vulnerability chains with new finding"""
        # Check existing chains for potential connections
        for chain in self.vulnerability_chains:
            last_vuln = chain[-1]
            if self._can_chain_vulnerabilities(last_vuln, new_vuln):
                chain.append(new_vuln)

        # Start new chain
        self.vulnerability_chains.append([new_vuln])

    def _can_chain_vulnerabilities(
        self,
        vuln1: ChainableVulnerability,
        vuln2: ChainableVulnerability
    ) -> bool:
        """Check if two vulnerabilities can be chained"""
        # Check if vuln2's prerequisites match vuln1's capabilities
        return bool(vuln1.affected_components & vuln2.prerequisites)

    def _identify_vulnerability_chains(
        self,
        findings: Dict[str, List[Dict[str, Any]]]
    ) -> List[Dict[str, Any]]:
        """Identify potential vulnerability chains from findings"""
        chains: List[Dict[str, Any]] = []
        for chain in self.vulnerability_chains:
            if len(chain) > 1:  # Only include chains of 2 or more vulnerabilities
                chain_impact = self._calculate_chain_impact(chain)
                if chain_impact >= HIGH_CONFIDENCE_THRESHOLD:
                    chains.append({
                        "vulnerabilities": [
                            {
                                "id": v.id,
                                "type": v.vulnerability_type,
                                "impact": v.impact.value,
                                "probability": v.chain_probability
                            } for v in chain
                        ],
                        "impact": chain_impact,
                        "description": self._generate_chain_description(chain)
                    })
        return chains

    def _calculate_chain_impact(self, chain: List[ChainableVulnerability]) -> float:
        """Calculate the potential impact of a vulnerability chain"""
        impact_weights = {
            BugBountyImpact.CRITICAL: 1.0,
            BugBountyImpact.HIGH: 0.8,
            BugBountyImpact.MEDIUM: 0.5,
            BugBountyImpact.LOW: 0.2
        }

        # Calculate combined impact
        chain_impact = 1.0
        for vuln in chain:
            chain_impact *= impact_weights[vuln.impact] * vuln.chain_probability

        return chain_impact

    def _generate_chain_description(self, chain: List[ChainableVulnerability]) -> str:
        """Generate detailed description of vulnerability chain"""
        steps = []
        for i, vuln in enumerate(chain, 1):
            steps.append(f"Step {i}: {vuln.vulnerability_type} - {vuln.impact.value}")

        return " -> ".join(steps)
