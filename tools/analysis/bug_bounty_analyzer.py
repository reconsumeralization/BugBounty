from __future__ import annotations

from typing import List, Dict, Any, Optional, Set, TypedDict
from dataclasses import dataclass
from enum import Enum
import logging
from pathlib import Path

from .o1_analyzer import O1Analyzer
from .scope_manager import ScopeManager, ScopeStatus
from .web_analyzer import WebVulnerabilityAnalyzer, WebEndpoint

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

class Finding(TypedDict):
    id: str
    vulnerability_type: str
    severity: str
    confidence: float
    entry_points: List[str]
    prerequisites: List[str]
    affected_components: List[str]
    requires_special_conditions: bool

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
        """Configure logging with appropriate handlers"""
        # Implementation will set up logging
        pass

    def check_scope(self, finding: Finding) -> ScopeStatus:
        """Check if finding is within scope"""
        # Implementation will check scope rules
        return ScopeStatus.IN_SCOPE

    def _meets_confidence_threshold(self, finding: Finding) -> bool:
        """Check if finding meets confidence threshold"""
        severity = finding.get("severity", "").lower()
        confidence = finding.get("confidence", 0.0)

        if severity == "critical" and confidence >= CRITICAL_CONFIDENCE_THRESHOLD:
            return True
        if severity == "high" and confidence >= HIGH_CONFIDENCE_THRESHOLD:
            return True
        return confidence >= DEFAULT_CONFIDENCE_THRESHOLD

    def _process_findings(
        self,
        findings: List[Finding],
        target: BugBountyTarget
    ) -> None:
        """Process and categorize findings based on bug bounty criteria"""
        for finding in findings:
            # Skip if confidence doesn't meet threshold
            if not self._meets_confidence_threshold(finding):
                continue

            # Validate finding is in scope
            scope_status = self.check_scope(finding)
            if scope_status != ScopeStatus.IN_SCOPE:
                continue

            # Check for special conditions
            if finding["requires_special_conditions"] and not self._check_special_conditions(finding, target):
                continue

            # Add to appropriate category
            self._categorize_finding(finding, target)

    def _check_special_conditions(self, finding: Finding, target: BugBountyTarget) -> bool:
        """Check if finding meets special conditions"""
        # Implementation will check special conditions
        return True

    def _categorize_finding(self, finding: Finding, target: BugBountyTarget) -> None:
        """Categorize finding based on type and impact"""
        # Implementation will categorize findings
        pass
