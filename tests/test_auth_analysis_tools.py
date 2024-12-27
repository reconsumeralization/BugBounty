"""Tests for authentication analysis tools."""

import pytest
from typing import AsyncGenerator, Dict, Any, List, TypedDict
from types import ModuleType
import json
from unittest.mock import AsyncMock, MagicMock, create_autospec

from tools.llm.auth_analysis_tools import AuthAnalysisTool
from tools.llm.session_analysis_tools import SessionAnalyzer
from tools.llm.tool_manager import ToolResult
from tools.llm.types import ChatChoice
from openai import AsyncOpenAI
from openai.types.chat import ChatCompletion as OpenAIChatCompletion
from openai.types.chat.chat_completion_message import ChatCompletionMessage

class Vulnerability(TypedDict):
    """Type definition for vulnerability data."""
    title: str
    description: str
    severity: str
    bounty_range: str

# Import pytest_asyncio for proper type hints
pytest_asyncio: ModuleType = pytest.importorskip("pytest_asyncio")

@pytest.fixture
async def mock_openai_client() -> AsyncGenerator[AsyncOpenAI, None]:
    """Create mock OpenAI client."""
    mock_client = create_autospec(AsyncOpenAI, instance=True)
    mock_completion = MagicMock(spec=OpenAIChatCompletion)
    mock_completion.choices = [MagicMock(spec=ChatChoice)]
    mock_completion.choices[0].message = MagicMock(spec=ChatCompletionMessage)
    mock_completion.choices[0].message.content = json.dumps({
        "vulnerabilities": [{
            "title": "Weak Password Policy",
            "description": "The password policy is not enforced properly.",
            "severity": "High",
            "bounty_range": "2,000 - 5,000 USD"
        }]
    })
    mock_client.chat.completions.create = AsyncMock(return_value=mock_completion)
    yield mock_client

@pytest.fixture
async def auth_analyzer(mock_openai_client: AsyncOpenAI) -> AsyncGenerator[AuthAnalysisTool, None]:
    """Create authentication analyzer instance."""
    analyzer = AuthAnalysisTool()
    yield analyzer

@pytest.fixture
async def session_analyzer(mock_openai_client: AsyncOpenAI) -> AsyncGenerator[SessionAnalyzer, None]:
    """Create session analyzer instance."""
    analyzer = SessionAnalyzer(client=mock_openai_client)
    yield analyzer

@pytest_asyncio.mark.asyncio
async def test_authentication_analysis(auth_analyzer: AuthAnalysisTool) -> None:
    """Test authentication analysis with implementation."""
    implementation: Dict[str, Any] = {
        "type": "password",
        "hash_algorithm": "bcrypt",
        "iterations": 10
    }

    result = await auth_analyzer.execute(target=json.dumps(implementation))
    assert isinstance(result, ToolResult)
    assert result.success
    assert result.data is not None
    assert isinstance(result.data, dict)
    assert "vulnerabilities" in result.data
    vulnerabilities: List[Vulnerability] = result.data.get("vulnerabilities", [])
    assert isinstance(vulnerabilities, list)
    assert len(vulnerabilities) > 0
    vuln: Vulnerability = vulnerabilities[0]
    assert isinstance(vuln, dict)
    assert "bounty_range" in vuln
    assert isinstance(vuln["bounty_range"], str)
    assert "2,000 - 5,000 USD" in vuln["bounty_range"]

@pytest_asyncio.mark.asyncio
async def test_authentication_analysis_no_implementation(auth_analyzer: AuthAnalysisTool) -> None:
    """Test authentication analysis with no implementation provided."""
    result = await auth_analyzer.execute(target=None)
    assert isinstance(result, ToolResult)
    assert not result.success
    assert result.error == "No target provided for analysis"

@pytest_asyncio.mark.asyncio
async def test_authentication_analysis_error(auth_analyzer: AuthAnalysisTool) -> None:
    """Test authentication analysis with API error."""
    result = await auth_analyzer.execute(target={"type": "password"})
    assert isinstance(result, ToolResult)
    assert not result.success
    assert "Auth analysis failed" in str(result.error)
