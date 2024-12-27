"""Tests for bug bounty analyzer."""

from typing import AsyncGenerator, Dict, Any
from pathlib import Path
import json
from unittest.mock import AsyncMock, MagicMock, create_autospec, patch

from tools.analysis.bug_bounty_analyzer import (
    BugBountyAnalyzer,
    BugBountyTarget,
    Finding,
    WebEndpoint
)
from tools.analysis.scope_manager import ScopeStatus
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
        "domains": ["test.com"],
        "endpoints": ["/api/v1/auth"],
        "excluded_paths": ["/health"]
    }

@pytest.fixture
def sample_target() -> BugBountyTarget:
    """Create sample bug bounty target."""
    return BugBountyTarget(
        domain="test.com",
        endpoints=[
            WebEndpoint(
                url="/api/v1/auth",
                method="POST",
                parameters={"username": "string", "password": "string"},
                authentication={"type": "none"},
                rate_limits={"max_requests": 100, "window": 60}
            )
        ],
        technology_stack={"framework": "django", "database": "postgresql"},
        scope_rules={"included_paths": ["/api/v1/*"]},
        known_vulnerabilities=[],
        reward_range={"critical": 5000.0, "high": 2000.0},
        excluded_paths={"/health"},
        special_conditions={}
    )

@pytest.fixture
async def mock_openai_client() -> AsyncGenerator[AsyncOpenAI, None]:
    """Create mock OpenAI client."""
    mock_client = create_autospec(AsyncOpenAI, instance=True)
    mock_completion = MagicMock(spec=OpenAIChatCompletion)
    mock_completion.choices = [MagicMock()]
    mock_completion.choices[0].message = MagicMock(spec=ChatCompletionMessage)
    mock_completion.choices[0].message.content = json.dumps({
        "findings": [{
            "id": "AUTH-001",
            "vulnerability_type": "auth_bypass",
            "severity": "critical",
            "confidence": 0.95,
            "entry_points": ["/api/v1/auth"],
            "prerequisites": ["token_manipulation"],
            "affected_components": ["auth_service"],
            "requires_special_conditions": False
        }]
    })
    mock_client.chat.completions.create = AsyncMock(return_value=mock_completion)
    yield mock_client

@pytest.fixture
async def bug_bounty_analyzer(
    mock_config: Dict[str, Any],
    mock_scope: Dict[str, Any]
) -> AsyncGenerator[BugBountyAnalyzer, None]:
    """Create bug bounty analyzer instance."""
    with patch("pathlib.Path.open"), \
         patch("yaml.safe_load") as mock_load:

        mock_load.side_effect = [mock_config, mock_scope]

        analyzer = BugBountyAnalyzer(
            scope_path=Path("test_scope.yaml"),
            config_path=Path("test_config.yaml")
        )
        yield analyzer

@pytest.mark.asyncio
async def test_check_scope_in_scope(
    bug_bounty_analyzer: BugBountyAnalyzer
) -> None:
    """Test check_scope with in-scope finding."""
    finding: Finding = {
        "id": "AUTH-001",
        "vulnerability_type": "auth_bypass",
        "severity": "critical",
        "confidence": 0.95,
        "entry_points": ["/api/v1/auth"],
        "prerequisites": ["token_manipulation"],
        "affected_components": ["auth_service"],
        "requires_special_conditions": False
    }

    scope_status = bug_bounty_analyzer.check_scope(finding)
    assert scope_status == ScopeStatus.IN_SCOPE

@pytest.mark.asyncio
async def test_check_scope_excluded_path(
    bug_bounty_analyzer: BugBountyAnalyzer
) -> None:
    """Test check_scope with excluded path."""
    finding: Finding = {
        "id": "AUTH-001",
        "vulnerability_type": "auth_bypass",
        "severity": "critical",
        "confidence": 0.95,
        "entry_points": ["/health"],
        "prerequisites": ["token_manipulation"],
        "affected_components": ["auth_service"],
        "requires_special_conditions": False
    }

    scope_status = bug_bounty_analyzer.check_scope(finding)
    assert scope_status == ScopeStatus.OUT_OF_SCOPE
