"""Tests for e-voting analysis tools."""

from typing import AsyncGenerator, Dict, Any
import json
from unittest.mock import AsyncMock, MagicMock, create_autospec, patch

from tools.llm.evoting_tools import (
    EVotingAnalyzer,
    EVotingTarget
)
from openai import AsyncOpenAI
from openai.types.chat import ChatCompletion as OpenAIChatCompletion
from openai.types.chat.chat_completion_message import ChatCompletionMessage
import pytest

@pytest.fixture
def mock_config() -> Dict[str, Any]:
    """Create mock configuration."""
    return {
        "analysis": {
            "confidence_thresholds": {
                "critical": 0.85,
                "high": 0.80,
                "default": 0.75
            }
        }
    }

@pytest.fixture
def mock_scope() -> Dict[str, Any]:
    """Create mock scope."""
    return {
        "domains": ["evoting.test"],
        "endpoints": ["/api/v1/vote"],
        "excluded_paths": ["/health"]
    }

@pytest.fixture
def sample_target() -> EVotingTarget:
    """Create sample e-voting target."""
    return {
        "domain": "evoting.test",
        "endpoints": [{
            "url": "/api/v1/vote",
            "method": "POST",
            "parameters": {"voter_id": "string", "ballot": "string"},
            "authentication": {"type": "jwt"},
            "rate_limits": {"max_requests": 1, "window": 300}
        }],
        "technology_stack": {"framework": "flask", "database": "postgresql"},
        "scope_rules": {"included_paths": ["/api/v1/*"]},
        "known_vulnerabilities": [],
        "reward_range": {"critical": 10000.0, "high": 5000.0},
        "excluded_paths": {"/health"},
        "special_conditions": {}
    }

@pytest.fixture
async def mock_openai_client() -> AsyncGenerator[AsyncOpenAI, None]:
    """Create mock OpenAI client."""
    mock_client = create_autospec(AsyncOpenAI, instance=True)
    mock_completion = MagicMock(spec=OpenAIChatCompletion)
    mock_completion.choices = [MagicMock()]
    mock_completion.choices[0].message = MagicMock(spec=ChatCompletionMessage)
    mock_completion.choices[0].message.content = json.dumps({
        "findings": [{
            "id": "VOTE-001",
            "vulnerability_type": "vote_manipulation",
            "severity": "critical",
            "confidence": 0.95,
            "entry_points": ["/api/v1/vote"],
            "prerequisites": ["jwt_manipulation"],
            "affected_components": ["vote_processor"],
            "requires_special_conditions": False
        }]
    })
    mock_client.chat.completions.create = AsyncMock(return_value=mock_completion)
    yield mock_client

@pytest.fixture
async def evoting_analyzer(mock_openai_client: AsyncOpenAI) -> EVotingAnalyzer:
    """Create e-voting analyzer instance."""
    return EVotingAnalyzer(client=mock_openai_client)

@pytest.mark.asyncio
async def test_evoting_analysis(
    evoting_analyzer: EVotingAnalyzer,
    sample_target: EVotingTarget
) -> None:
    """Test e-voting analysis with implementation."""
    result = await evoting_analyzer.analyze_target(sample_target)

    assert isinstance(result, dict)
    assert "critical" in result
    assert len(result.get("critical", [])) > 0

    finding = result["critical"][0]
    assert finding["vulnerability_type"] == "vote_manipulation"
    assert finding["severity"] == "critical"
    assert finding["confidence"] >= 0.85
    assert not finding["requires_special_conditions"]

@pytest.mark.asyncio
async def test_evoting_analysis_excluded_path(
    evoting_analyzer: EVotingAnalyzer,
    sample_target: EVotingTarget
) -> None:
    """Test e-voting analysis with excluded path."""
    # Add excluded path
    sample_target["endpoints"][0]["url"] = "/health"

    result = await evoting_analyzer.analyze_target(sample_target)
    assert isinstance(result, dict)
    assert len(result.get("critical", [])) == 0

@pytest.mark.asyncio
async def test_evoting_analysis_error(
    evoting_analyzer: EVotingAnalyzer,
    sample_target: EVotingTarget
) -> None:
    """Test e-voting analysis with error."""
    with patch.object(
        evoting_analyzer,
        "analyze_target",
        side_effect=Exception("Analysis error")
    ):
        result = await evoting_analyzer.analyze_target(sample_target)
        assert isinstance(result, dict)
        assert len(result.get("critical", [])) == 0
