from __future__ import annotations

from typing import Dict, Any, List, Set
from pathlib import Path
import pytest
from unittest.mock import AsyncMock, Mock, patch

from tools.analysis.bug_bounty_analyzer import (
    BugBountyAnalyzer,
    BugBountyTarget,
    BugBountyImpact,
    ChainableVulnerability,
    WebEndpoint
)

@pytest.fixture
def mock_config() -> Dict[str, Any]:
    return {
        "analysis": {
            "max_concurrent_analysis": 5,
            "confidence_thresholds": {
                "critical": 0.85,
                "high": 0.80,
                "default": 0.75
            }
        },
        "vulnerability_chains": {
            "chainable_types": [
                {"ssrf": {
                    "chain_weight": 0.9,
                    "potential_impacts": ["rce", "data_leak"]
                }},
                {"sql_injection": {
                    "chain_weight": 0.9,
                    "potential_impacts": ["data_leak", "auth_bypass"]
                }}
            ]
        }
    }

@pytest.fixture
def mock_scope() -> Dict[str, Any]:
    return {
        "domains": {
            "primary": ["test.com"],
            "secondary": ["api.test.com"]
        },
        "assets": {
            "web_applications": [{
                "name": "Test App",
                "url": "https://test.com",
                "paths": ["/api/v1/*"],
                "excluded": ["/api/v1/health"]
            }]
        },
        "vulnerability_types": {
            "qualifying": ["sql_injection", "rce", "ssrf"]
        }
    }

@pytest.fixture
def sample_target() -> BugBountyTarget:
    return BugBountyTarget(
        domain="test.com",
        endpoints=[
            WebEndpoint(
                url="/api/v1/users",
                method="POST",
                parameters={"username": "string", "email": "string"},
                authentication={"type": "bearer"},
                rate_limits={"max_requests": 100, "window": 60}
            )
        ],
        technology_stack={
            "framework": "django",
            "database": "postgresql",
            "cache": "redis"
        },
        scope_rules={
            "included_paths": ["/api/v1/*"],
            "excluded_paths": ["/api/v1/health"]
        },
        known_vulnerabilities=[],
        reward_range={"critical": 5000.0, "high": 2000.0},
        excluded_paths={"/api/v1/health"},
        special_conditions={}
    )

@pytest.fixture
def sample_findings() -> List[Dict[str, Any]]:
    return [
        {
            "title": "SQL Injection",
            "severity": "high",
            "vulnerability_type": "sql_injection",
            "location": "api/v1/users",
            "description": "User input directly used in query",
            "impact": "Data leak possible",
            "confidence": 0.9,
            "entry_points": ["/api/v1/users"],
            "prerequisites": ["user_input"],
            "affected_components": ["database"]
        },
        {
            "title": "SSRF Vulnerability",
            "severity": "high",
            "vulnerability_type": "ssrf",
            "location": "api/v1/proxy",
            "description": "Unvalidated URL in proxy endpoint",
            "impact": "Internal service access",
            "confidence": 0.85,
            "entry_points": ["/api/v1/proxy"],
            "prerequisites": ["url_input"],
            "affected_components": ["internal_network"]
        }
    ]

@pytest.mark.asyncio
async def test_analyze_target(
    mock_config: Dict[str, Any],
    mock_scope: Dict[str, Any],
    sample_target: BugBountyTarget,
    sample_findings: List[Dict[str, Any]]
) -> None:
    # Arrange
    with patch("pathlib.Path.open"), \
         patch("yaml.safe_load") as mock_load:

        mock_load.side_effect = [mock_config, mock_scope]

        analyzer = BugBountyAnalyzer(
            scope_path=Path("test_scope.yaml"),
            config_path=Path("test_config.yaml")
        )

        # Mock web analyzer
        mock_web_analyzer = AsyncMock()
        mock_web_analyzer.analyze_endpoint.return_value = {
            "findings": sample_findings
        }
        analyzer.web_analyzer = mock_web_analyzer

        # Act
        results = await analyzer.analyze_target(sample_target)

        # Assert
        assert "high" in results
        assert len(results["high"]) == 2
        assert results["high"][0]["vulnerability_type"] == "sql_injection"
        assert results["high"][1]["vulnerability_type"] == "ssrf"
        assert "potential_chains" in results
        assert len(results["potential_chains"]) > 0

@pytest.mark.asyncio
async def test_vulnerability_chaining(
    mock_config: Dict[str, Any],
    mock_scope: Dict[str, Any]
) -> None:
    # Arrange
    with patch("pathlib.Path.open"), \
         patch("yaml.safe_load") as mock_load:

        mock_load.side_effect = [mock_config, mock_scope]

        analyzer = BugBountyAnalyzer(
            scope_path=Path("test_scope.yaml"),
            config_path=Path("test_config.yaml")
        )

        vuln1 = ChainableVulnerability(
            id="SQL-001",
            vulnerability_type="sql_injection",
            entry_points={"/api/v1/users"},
            prerequisites={"user_input"},
            impact=BugBountyImpact.HIGH,
            affected_components={"database"},
            chain_probability=0.9
        )

        vuln2 = ChainableVulnerability(
            id="SSRF-001",
            vulnerability_type="ssrf",
            entry_points={"/api/v1/proxy"},
            prerequisites={"database"},
            impact=BugBountyImpact.HIGH,
            affected_components={"internal_network"},
            chain_probability=0.85
        )

        # Act
        analyzer._add_to_chainable(vuln1)
        analyzer._add_to_chainable(vuln2)

        # Assert
        assert len(analyzer.vulnerability_chains) > 0
        chain = analyzer.vulnerability_chains[0]
        assert len(chain) == 2
        assert chain[0].vulnerability_type == "sql_injection"
        assert chain[1].vulnerability_type == "ssrf"

def test_confidence_thresholds(
    mock_config: Dict[str, Any],
    mock_scope: Dict[str, Any]
) -> None:
    # Arrange
    with patch("pathlib.Path.open"), \
         patch("yaml.safe_load") as mock_load:

        mock_load.side_effect = [mock_config, mock_scope]

        analyzer = BugBountyAnalyzer(
            scope_path=Path("test_scope.yaml"),
            config_path=Path("test_config.yaml")
        )

        findings = [
            {"severity": "critical", "confidence": 0.8},  # Below threshold
            {"severity": "critical", "confidence": 0.9},  # Above threshold
            {"severity": "high", "confidence": 0.75},     # Below threshold
            {"severity": "high", "confidence": 0.85}      # Above threshold
        ]

        # Act & Assert
        for finding in findings:
            meets_threshold = analyzer._meets_confidence_threshold(finding)
            if finding["confidence"] >= mock_config["analysis"]["confidence_thresholds"][
                finding["severity"]
            ]:
                assert meets_threshold
            else:
                assert not meets_threshold

def test_special_conditions(
    mock_config: Dict[str, Any],
    mock_scope: Dict[str, Any],
    sample_target: BugBountyTarget
) -> None:
    # Arrange
    with patch("pathlib.Path.open"), \
         patch("yaml.safe_load") as mock_load:

        mock_load.side_effect = [mock_config, mock_scope]

        analyzer = BugBountyAnalyzer(
            scope_path=Path("test_scope.yaml"),
            config_path=Path("test_config.yaml")
        )

        # Add special conditions to target
        sample_target.special_conditions = {
            "rate_limiting": {
                "requires": ["business_impact"]
            }
        }

        findings = [
            {
                "vulnerability_type": "rate_limiting",
                "impact": "No business impact"
            },
            {
                "vulnerability_type": "rate_limiting",
                "impact": "Significant business impact",
                "business_impact": True
            }
        ]

        # Act & Assert
        for finding in findings:
            requires_special = analyzer._requires_special_conditions(finding, sample_target)
            has_business_impact = "business_impact" in finding
            assert requires_special == has_business_impact
