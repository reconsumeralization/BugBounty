from __future__ import annotations

from typing import Dict, Any, List, Set, AsyncGenerator
import json
from pathlib import Path
from unittest.mock import AsyncMock, Mock, patch

import pytest
from pytest_mock import MockerFixture

from tools.analysis.o1_chain_analyzer import (
    O1ChainAnalyzer,
    ChainAnalysisMode,
    ChainContext,
    ChainAnalysisResult
)
from tools.analysis.bug_bounty_analyzer import (
    ChainableVulnerability,
    BugBountyImpact
)

@pytest.fixture
def mock_prompts() -> Dict[str, str]:
    return {
        "deep_analysis": "Deep analysis template {chain_description}",
        "quick_analysis": "Quick analysis template {chain_description}"
    }

@pytest.fixture
def sample_chain() -> List[ChainableVulnerability]:
    return [
        ChainableVulnerability(
            id="SQL-001",
            vulnerability_type="sql_injection",
            entry_points={"/api/v1/users"},
            prerequisites={"user_input"},
            impact=BugBountyImpact.HIGH,
            affected_components={"database"},
            chain_probability=0.9
        ),
        ChainableVulnerability(
            id="SSRF-001",
            vulnerability_type="ssrf",
            entry_points={"/api/v1/proxy"},
            prerequisites={"database"},
            impact=BugBountyImpact.HIGH,
            affected_components={"internal_network"},
            chain_probability=0.85
        )
    ]

@pytest.fixture
def sample_context() -> ChainContext:
    return ChainContext(
        entry_points={"/api/v1/users", "/api/v1/proxy"},
        affected_components={"database", "internal_network"},
        technology_stack={
            "framework": "django",
            "database": "postgresql",
            "cache": "redis"
        },
        security_controls={
            "waf": "enabled",
            "input_validation": "strict",
            "network_segmentation": "enabled"
        },
        known_bypasses=[
            "WAF bypass using JSON encoding",
            "Input validation bypass using nested objects"
        ],
        chain_history=[
            "Previous SQL injection attempt detected",
            "SSRF attempts blocked by WAF"
        ]
    )

@pytest.fixture
def sample_analysis_result() -> Dict[str, Any]:
    return {
        "findings": [{
            "feasibility": 0.75,
            "complexity": 0.8,
            "impact_score": 0.9,
            "detection_likelihood": 0.6,
            "reasoning": "Chain analysis reasoning...",
            "prerequisites": [
                "Database access",
                "Network visibility"
            ],
            "mitigations": [
                "Implement prepared statements",
                "Strict URL validation"
            ],
            "attack_steps": [
                "Exploit SQL injection",
                "Pivot to internal network"
            ]
        }]
    }

@pytest.fixture
async def analyzer(
    mocker: MockerFixture,
    mock_prompts: Dict[str, str]
) -> AsyncGenerator[O1ChainAnalyzer, None]:
    """Create analyzer with mocked dependencies"""
    # Mock prompt loading
    mocker.patch(
        "json.load",
        return_value=mock_prompts
    )

    # Mock file operations
    mocker.patch("pathlib.Path.open")

    # Create analyzer
    analyzer = O1ChainAnalyzer(mode=ChainAnalysisMode.DEEP)

    # Mock O1Analyzer
    mock_o1 = AsyncMock()
    analyzer.analyzer = mock_o1

    yield analyzer

@pytest.mark.asyncio
async def test_analyze_chain(
    analyzer: O1ChainAnalyzer,
    sample_chain: List[ChainableVulnerability],
    sample_context: ChainContext,
    sample_analysis_result: Dict[str, Any]
) -> None:
    """Test single chain analysis"""
    # Arrange
    analyzer.analyzer.analyze.return_value = sample_analysis_result

    # Act
    result = await analyzer.analyze_chain(sample_chain, sample_context)

    # Assert
    assert isinstance(result, dict)
    assert result["feasibility"] == 0.75
    assert result["complexity"] == 0.8
    assert result["impact_score"] == 0.9
    assert result["detection_likelihood"] == 0.6
    assert len(result["prerequisites"]) == 2
    assert len(result["mitigations"]) == 2
    assert len(result["attack_steps"]) == 2

@pytest.mark.asyncio
async def test_analyze_chain_batch(
    analyzer: O1ChainAnalyzer,
    sample_chain: List[ChainableVulnerability],
    sample_context: ChainContext,
    sample_analysis_result: Dict[str, Any]
) -> None:
    """Test batch chain analysis"""
    # Arrange
    analyzer.analyzer.analyze.return_value = sample_analysis_result
    chains = [sample_chain, sample_chain]  # Two identical chains for testing

    # Act
    results = await analyzer.analyze_chain_batch(chains, sample_context, batch_size=2)

    # Assert
    assert len(results) == 2
    for result in results:
        assert isinstance(result, dict)
        assert result["feasibility"] == 0.75
        assert result["complexity"] == 0.8
        assert len(result["prerequisites"]) == 2

@pytest.mark.asyncio
async def test_analyze_chain_with_errors(
    analyzer: O1ChainAnalyzer,
    sample_chain: List[ChainableVulnerability],
    sample_context: ChainContext
) -> None:
    """Test chain analysis with error handling"""
    # Arrange
    analyzer.analyzer.analyze.side_effect = Exception("Analysis failed")

    # Act & Assert
    with pytest.raises(Exception, match="Analysis failed"):
        await analyzer.analyze_chain(sample_chain, sample_context)

def test_estimate_chain_complexity(
    analyzer: O1ChainAnalyzer,
    sample_chain: List[ChainableVulnerability]
) -> None:
    """Test chain complexity estimation"""
    # Act
    complexity = analyzer.estimate_chain_complexity(sample_chain)

    # Assert
    assert 0 <= complexity <= 1.0
    assert complexity > 0.5  # Should be relatively complex chain

def test_chain_analysis_modes(
    analyzer: O1ChainAnalyzer,
    sample_chain: List[ChainableVulnerability],
    sample_context: ChainContext,
    sample_analysis_result: Dict[str, Any]
) -> None:
    """Test different chain analysis modes"""
    # Test DEEP mode
    analyzer.mode = ChainAnalysisMode.DEEP
    prompt = analyzer._prepare_chain_prompt(sample_chain, sample_context)
    assert "Deep analysis template" in prompt

    # Test QUICK mode
    analyzer.mode = ChainAnalysisMode.QUICK
    prompt = analyzer._prepare_chain_prompt(sample_chain, sample_context)
    assert "Quick analysis template" in prompt

def test_invalid_chain_data(analyzer: O1ChainAnalyzer) -> None:
    """Test handling of invalid chain data"""
    # Empty chain
    complexity = analyzer.estimate_chain_complexity([])
    assert complexity == 0.0

    # Invalid context
    with pytest.raises(ValueError):
        analyzer._parse_chain_analysis({"findings": []})

def test_context_building(
    analyzer: O1ChainAnalyzer,
    sample_context: ChainContext
) -> None:
    """Test context description building"""
    # Act
    context_desc = analyzer._build_context_description(sample_context)

    # Assert
    assert "Technology Stack" in context_desc
    assert "Security Controls" in context_desc
    assert "Known Bypasses" in context_desc
    assert "Chain History" in context_desc
    assert "django" in context_desc
    assert "waf" in context_desc
