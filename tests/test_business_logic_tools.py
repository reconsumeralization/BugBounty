"""Tests for business logic analysis tools."""

import pytest
from typing import AsyncGenerator, Dict, Any, List, TypedDict
from types import ModuleType
import json
from unittest.mock import AsyncMock, MagicMock, create_autospec

from tools.llm.business_logic_tools import BusinessLogicAnalyzer
from tools.llm.tool_manager import ToolResult
from openai import AsyncOpenAI
from openai.types.chat import ChatCompletion as OpenAIChatCompletion
from openai.types.chat.chat_completion_message import ChatCompletionMessage

class BusinessLogicVulnerability(TypedDict):
    """Type definition for business logic vulnerability data."""
    title: str
    description: str
    severity: str
    bounty_range: str
    affected_components: List[str]
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
            "title": "Race Condition in Order Processing",
            "description": "Concurrent order processing can lead to inventory inconsistencies.",
            "severity": "High",
            "bounty_range": "3,000 - 7,000 USD",
            "affected_components": ["order_processor.py"],
            "impact": "Financial loss and inventory discrepancies"
        }]
    })
    mock_client.chat.completions.create = AsyncMock(return_value=mock_completion)
    yield mock_client

@pytest.fixture
async def business_logic_analyzer(mock_openai_client: AsyncOpenAI) -> AsyncGenerator[BusinessLogicAnalyzer, None]:
    """Create business logic analyzer instance."""
    analyzer = BusinessLogicAnalyzer(client=mock_openai_client)
    yield analyzer

@pytest_asyncio.mark.asyncio
async def test_business_logic_analysis(business_logic_analyzer: BusinessLogicAnalyzer) -> None:
    """Test business logic analysis with implementation."""
    implementation: Dict[str, Any] = {
        "order_processor.py": """
        async def process_order(order_id: str) -> None:
            inventory = await get_inventory()
            if inventory.available > 0:
                await update_inventory(inventory.count - 1)
                await create_order(order_id)
        """
    }

    result = await business_logic_analyzer.execute(source_code=implementation)
    assert isinstance(result, ToolResult)
    assert result.success
    assert result.data is not None
    assert isinstance(result.data, dict)
    assert "vulnerabilities" in result.data
    vulnerabilities: List[BusinessLogicVulnerability] = result.data.get("vulnerabilities", [])
    assert isinstance(vulnerabilities, list)
    assert len(vulnerabilities) > 0
    vuln: BusinessLogicVulnerability = vulnerabilities[0]
    assert isinstance(vuln, dict)
    assert "bounty_range" in vuln
    assert isinstance(vuln["bounty_range"], str)
    assert "3,000 - 7,000 USD" in vuln["bounty_range"]

@pytest_asyncio.mark.asyncio
async def test_business_logic_analysis_no_implementation(business_logic_analyzer: BusinessLogicAnalyzer) -> None:
    """Test business logic analysis with no implementation provided."""
    result = await business_logic_analyzer.execute(source_code=None)
    assert isinstance(result, ToolResult)
    assert not result.success
    assert result.error == "No application components provided for analysis"

@pytest_asyncio.mark.asyncio
async def test_business_logic_analysis_error(business_logic_analyzer: BusinessLogicAnalyzer) -> None:
    """Test business logic analysis with API error."""
    mock_client = create_autospec(AsyncOpenAI, instance=True)
    mock_client.chat.completions.create = AsyncMock(side_effect=Exception("API error"))
    business_logic_analyzer.client = mock_client

    result = await business_logic_analyzer.execute(source_code={"type": "order_processing"})
    assert isinstance(result, ToolResult)
    assert not result.success
    assert result.error == "API error"
