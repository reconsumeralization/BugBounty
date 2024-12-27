"""Tests for API security analysis tools."""

import pytest
from typing import AsyncGenerator, Dict, Any, List, TypedDict
from types import ModuleType
import json
from unittest.mock import AsyncMock, MagicMock, create_autospec

from tools.llm.api_security_tools import APISecurityAnalyzer
from tools.llm.tool_manager import ToolResult
from openai import AsyncOpenAI
from openai.types.chat import ChatCompletion as OpenAIChatCompletion
from openai.types.chat.chat_completion_message import ChatCompletionMessage

class APIVulnerability(TypedDict):
    """Type definition for API vulnerability data."""
    title: str
    description: str
    severity: str
    bounty_range: str
    affected_endpoints: List[str]
    impact: str

# Import pytest_asyncio for proper type hints
pytest_asyncio: ModuleType = pytest.importorskip("pytest_asyncio")

@pytest.fixture
async def mock_openai_client() -> AsyncGenerator[AsyncOpenAI, None]:
    """Create mock OpenAI client."""
    mock_client = create_autospec(AsyncOpenAI, instance=True)
    mock_completion = MagicMock(spec=OpenAIChatCompletion)
    mock_completion.choices = [MagicMock()]
    mock_completion.choices[0].message = MagicMock(spec=ChatCompletionMessage)
    mock_completion.choices[0].message.content = json.dumps({
        "vulnerabilities": [{
            "title": "Insecure Direct Object Reference",
            "description": "API endpoints allow unauthorized access to resources.",
            "severity": "High",
            "bounty_range": "2,000 - 5,000 USD",
            "affected_endpoints": ["/api/v1/users/{id}"],
            "impact": "Unauthorized data access and manipulation"
        }]
    })
    mock_client.chat.completions.create = AsyncMock(return_value=mock_completion)
    yield mock_client

@pytest.fixture
async def api_security_analyzer(mock_openai_client: AsyncOpenAI) -> AsyncGenerator[APISecurityAnalyzer, None]:
    """Create API security analyzer instance."""
    analyzer = APISecurityAnalyzer(client=mock_openai_client)
    yield analyzer

@pytest.mark.asyncio
async def test_api_security_analysis(api_security_analyzer: APISecurityAnalyzer) -> None:
    """Test API security analysis with implementation."""
    implementation: Dict[str, Any] = {
        "openapi": "3.0.0",
        "paths": {
            "/api/v1/users/{id}": {
                "get": {
                    "parameters": [
                        {
                            "name": "id",
                            "in": "path",
                            "required": True,
                            "schema": {"type": "string"}
                        }
                    ],
                    "responses": {
                        "200": {
                            "description": "User details",
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": "#/components/schemas/User"}
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    result = await api_security_analyzer.execute(source_code=implementation)
    assert isinstance(result, ToolResult)
    assert result.success
    assert result.data is not None
    assert isinstance(result.data, dict)
    assert "vulnerabilities" in result.data
    vulnerabilities: List[APIVulnerability] = result.data.get("vulnerabilities", [])
    assert isinstance(vulnerabilities, list)
    assert len(vulnerabilities) > 0
    vuln: APIVulnerability = vulnerabilities[0]
    assert isinstance(vuln, dict)
    assert "bounty_range" in vuln
    assert isinstance(vuln["bounty_range"], str)
    assert "2,000 - 5,000 USD" in vuln["bounty_range"]

@pytest.mark.asyncio
async def test_api_security_analysis_no_implementation(api_security_analyzer: APISecurityAnalyzer) -> None:
    """Test API security analysis with no implementation provided."""
    result = await api_security_analyzer.execute(source_code=None)
    assert isinstance(result, ToolResult)
    assert not result.success
    assert result.error == "No application components provided for analysis"

@pytest.mark.asyncio
async def test_api_security_analysis_error(api_security_analyzer: APISecurityAnalyzer) -> None:
    """Test API security analysis with API error."""
    mock_client = create_autospec(AsyncOpenAI, instance=True)
    mock_client.chat.completions.create = AsyncMock(side_effect=Exception("API error"))
    api_security_analyzer.client = mock_client

    result = await api_security_analyzer.execute(source_code={"type": "openapi"})
    assert isinstance(result, ToolResult)
    assert not result.success
    assert result.error == "API error"
