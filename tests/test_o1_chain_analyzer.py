from __future__ import annotations

from typing import Dict, List, AsyncGenerator, cast, Any
from unittest.mock import AsyncMock, MagicMock
import pytest
from pytest_mock import MockerFixture
from pytest import fixture

from tools.analysis.o1_chain_analyzer import (
    O1ChainAnalyzer,
    ChainAnalysisMode,
    ChainContext
)
from tools.analysis.bug_bounty_analyzer import (
    ChainableVulnerability,
    BugBountyImpact
)
from tools.analysis.o1_analyzer import O1Analyzer, AnalysisStatus, Findings

@fixture
def mock_prompts() -> Dict[str, str]:
    return {
        "deep_analysis": "Deep analysis template {chain_description}",
        "quick_analysis": "Quick analysis template {chain_description}"
    }

@fixture
def sample_chain() -> List[ChainableVulnerability]:
    return [
        ChainableVulnerability(
            id="TEST-001",
            vulnerability_type="sql_injection",
            entry_points={"api/v1/users"},
            prerequisites={"authenticated"},
            impact=BugBountyImpact.HIGH,
            affected_components={"database"},
            chain_probability=0.8
        )
    ]

@fixture
def sample_context() -> ChainContext:
    return ChainContext(
        entry_points={"api/v1/users"},
        affected_components={"database"},
        technology_stack={"python": "3.9", "django": "4.2"},
        security_controls={},
        known_bypasses=[],
        chain_history=[]
    )

@fixture
def sample_analysis_result() -> Dict[str, Any]:
    return {
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
    }

@fixture
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

    # Mock analyzer's internal analyzer
    mock_analyzer = AsyncMock(spec=O1Analyzer)
    mock_analyzer.analyze = AsyncMock()
    analyzer.analyzer = mock_analyzer

    yield analyzer

@pytest.fixture
def mock_analyzer(mocker: MockerFixture) -> MagicMock:
    analyzer_mock = mocker.MagicMock(spec=O1Analyzer)
    analyzer_mock.analyze = AsyncMock()
    return analyzer_mock

@pytest.mark.asyncio
async def test_analyze_chain(
    analyzer: O1ChainAnalyzer,
    sample_chain: List[ChainableVulnerability],
    sample_context: ChainContext,
    sample_analysis_result: Dict[str, Any]
) -> None:
    """Test single chain analysis"""
    # Arrange
    mock_analyzer = cast(AsyncMock, analyzer.analyzer)
    findings: Findings = [{
        "type": "sql_injection",
        "severity": "high",
        "confidence": 0.9,
        "description": "Test finding",
        "feasibility": 0.75,
        "complexity": 0.8,
        "impact_score": 0.9,
        "detection_likelihood": 0.6,
        "reasoning": "Chain analysis reasoning...",
        "prerequisites": ["Database access", "Network visibility"],
        "mitigations": ["Implement prepared statements", "Strict URL validation"],
        "attack_steps": ["Exploit SQL injection", "Pivot to internal network"]
    }]
    mock_analyzer.analyze.return_value = {
        "findings": findings,
        "reasoning_tokens": 100,
        "completion_tokens": 50,
        "total_tokens": 150,
        "status": AnalysisStatus.SUCCESS
    }

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
    mock_analyzer = cast(AsyncMock, analyzer.analyzer)
    findings: Findings = [{
        "type": "sql_injection",
        "severity": "high",
        "confidence": 0.9,
        "description": "Test finding",
        "feasibility": 0.75,
        "complexity": 0.8,
        "impact_score": 0.9,
        "detection_likelihood": 0.6,
        "reasoning": "Chain analysis reasoning...",
        "prerequisites": ["Database access", "Network visibility"],
        "mitigations": ["Implement prepared statements", "Strict URL validation"],
        "attack_steps": ["Exploit SQL injection", "Pivot to internal network"]
    }]
    mock_analyzer.analyze.return_value = {
        "findings": findings,
        "reasoning_tokens": 100,
        "completion_tokens": 50,
        "total_tokens": 150,
        "status": AnalysisStatus.SUCCESS
    }
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
    mock_analyzer = cast(AsyncMock, analyzer.analyzer)
    mock_analyzer.analyze.side_effect = Exception("Analysis failed")

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
    assert analyzer.mode == ChainAnalysisMode.DEEP

    # Test QUICK mode
    analyzer.mode = ChainAnalysisMode.QUICK
    assert analyzer.mode == ChainAnalysisMode.QUICK

@pytest.mark.asyncio
async def test_invalid_chain_data(
    analyzer: O1ChainAnalyzer,
    sample_context: ChainContext
) -> None:
    """Test handling of invalid chain data"""
    # Empty chain
    complexity = analyzer.estimate_chain_complexity([])
    assert complexity == 0.0

    # Invalid chain
    with pytest.raises(ValueError, match="Empty vulnerability chain"):
        await analyzer.analyze_chain([], sample_context)

@pytest.mark.asyncio
async def test_invalid_context(
    analyzer: O1ChainAnalyzer,
    sample_chain: List[ChainableVulnerability]
) -> None:
    """Test handling of invalid context"""
    # Create invalid context
    invalid_context = ChainContext(
        entry_points=set(),  # Empty entry points
        affected_components={"database"},
        technology_stack={},  # Empty tech stack
        security_controls={},
        known_bypasses=[],
        chain_history=[]
    )

    # Test with invalid context
    with pytest.raises(ValueError, match="Invalid chain context"):
        await analyzer.analyze_chain(sample_chain, invalid_context)

@pytest.mark.asyncio
async def test_analyze_chain_success(
    mock_analyzer: MagicMock,
    sample_chain: List[ChainableVulnerability],
    sample_context: ChainContext
) -> None:
    # Arrange
    findings: Findings = [{
        "type": "sql_injection",
        "severity": "high",
        "confidence": 0.9,
        "description": "Test finding",
        "feasibility": 0.75,
        "complexity": 0.8,
        "impact_score": 0.9,
        "detection_likelihood": 0.6,
        "reasoning": "Chain analysis reasoning...",
        "prerequisites": ["Database access", "Network visibility"],
        "mitigations": ["Implement prepared statements", "Strict URL validation"],
        "attack_steps": ["Exploit SQL injection", "Pivot to internal network"]
    }]
    mock_analyzer.analyze.return_value = {
        "findings": findings,
        "reasoning_tokens": 100,
        "completion_tokens": 50,
        "total_tokens": 150,
        "status": AnalysisStatus.SUCCESS
    }

    # Act
    analyzer = O1ChainAnalyzer(analyzer=mock_analyzer)
    result = await analyzer.analyze_chain(sample_chain, sample_context)

    # Assert
    assert result is not None
    assert isinstance(result, dict)
    assert "feasibility" in result
    assert mock_analyzer.analyze.return_value["status"] == AnalysisStatus.SUCCESS

@pytest.mark.asyncio
async def test_analyze_chain_failure(
    mock_analyzer: MagicMock,
    sample_chain: List[ChainableVulnerability],
    sample_context: ChainContext
) -> None:
    # Arrange
    mock_analyzer.analyze.side_effect = RuntimeError("Analysis failed")

    # Act & Assert
    analyzer = O1ChainAnalyzer(analyzer=mock_analyzer)
    with pytest.raises(RuntimeError, match="Analysis failed"):
        await analyzer.analyze_chain(sample_chain, sample_context)
