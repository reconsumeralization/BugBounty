"""Tests for LLM tools and O1 integration."""

import pytest
from typing import Dict, Any, List, cast, AsyncGenerator
from unittest.mock import AsyncMock

from tools.llm.manager import DefaultLLMToolManager
from tools.llm.tool_manager import (
    ToolMetadata,
    ToolCategory,
    ToolResult
)
from tools.llm.o1_tools import VulnerabilityAnalysisTool
from openai import AsyncOpenAI

@pytest.fixture
async def mock_openai_client() -> AsyncGenerator[AsyncOpenAI, None]:
    """Create mock OpenAI client."""
    client = AsyncMock(spec=AsyncOpenAI)
    yield client

@pytest.fixture
def tool_manager() -> DefaultLLMToolManager:
    """Create a tool manager instance."""
    return DefaultLLMToolManager()

@pytest.fixture
def sample_code() -> str:
    """Sample code for testing."""
    return """
    def process_user_input(user_input: str) -> str:
        return f"SELECT * FROM users WHERE id = {user_input}"
    """

@pytest.fixture
def sample_vulnerabilities() -> List[Dict[str, Any]]:
    """Sample vulnerabilities for testing."""
    return [
        {
            "type": "sql_injection",
            "severity": "high",
            "location": "process_user_input",
            "description": "Unsanitized user input in SQL query"
        }
    ]

@pytest.mark.asyncio
async def test_vulnerability_analysis(
    tool_manager: DefaultLLMToolManager,
    mock_openai_client: AsyncOpenAI,
    sample_code: str
) -> None:
    """Test vulnerability analysis tool."""
    # Register tools with client
    tool = VulnerabilityAnalysisTool(client=mock_openai_client)
    metadata = ToolMetadata(
        name="o1_vulnerability_analysis",
        description="Analyze code for security vulnerabilities using O1",
        category=ToolCategory.ANALYSIS,
        version="1.0.0",
        author="Security Team",
        timeout=300
    )
    tool_manager.register_tool(metadata, tool)

    # Execute analysis
    result = await tool_manager.execute_tool(
        "o1_vulnerability_analysis",
        code=sample_code
    )

    # Verify result
    assert result.success
    data = cast(Dict[str, Any], result.data)
    assert isinstance(data, dict)
    assert data.get("vulnerabilities") is not None
    assert data.get("risk_score") is not None
    assert data.get("recommendations") is not None

@pytest.mark.asyncio
async def test_chain_analysis(
    tool_manager: DefaultLLMToolManager,
    mock_openai_client: AsyncOpenAI,
    sample_vulnerabilities: List[Dict[str, Any]]
) -> None:
    """Test chain analysis tool."""
    # Register tools with client
    tool = VulnerabilityAnalysisTool(client=mock_openai_client)
    metadata = ToolMetadata(
        name="o1_chain_analysis",
        description="Analyze vulnerability chains using O1",
        category=ToolCategory.ANALYSIS,
        version="1.0.0",
        author="Security Team",
        timeout=300
    )
    tool_manager.register_tool(metadata, tool)

    # Execute analysis
    result = await tool_manager.execute_tool(
        "o1_chain_analysis",
        vulnerabilities=sample_vulnerabilities
    )

    # Verify result
    assert result.success
    data = cast(Dict[str, Any], result.data)
    assert isinstance(data, dict)
    assert data.get("chains") is not None
    assert data.get("impact_scores") is not None
    assert data.get("attack_paths") is not None

@pytest.mark.asyncio
async def test_security_recommendations(
    tool_manager: DefaultLLMToolManager,
    mock_openai_client: AsyncOpenAI,
    sample_vulnerabilities: List[Dict[str, Any]]
) -> None:
    """Test security recommendations tool."""
    # Register tools with client
    tool = VulnerabilityAnalysisTool(client=mock_openai_client)
    metadata = ToolMetadata(
        name="o1_security_recommendations",
        description="Generate security recommendations using O1",
        category=ToolCategory.ANALYSIS,
        version="1.0.0",
        author="Security Team",
        timeout=300
    )
    tool_manager.register_tool(metadata, tool)

    # Execute analysis
    result = await tool_manager.execute_tool(
        "o1_security_recommendations",
        findings=sample_vulnerabilities
    )

    # Verify result
    assert result.success
    data = cast(Dict[str, Any], result.data)
    assert isinstance(data, dict)
    assert data.get("high_priority") is not None
    assert data.get("medium_priority") is not None
    assert data.get("low_priority") is not None
    assert data.get("best_practices") is not None

@pytest.mark.asyncio
async def test_tool_chain_execution(
    tool_manager: DefaultLLMToolManager,
    mock_openai_client: AsyncOpenAI,
    sample_code: str,
    sample_vulnerabilities: List[Dict[str, Any]]
) -> None:
    """Test executing a chain of tools."""
    # Register tools with client
    for name, desc in [
        ("o1_vulnerability_analysis", "Analyze code for security vulnerabilities"),
        ("o1_chain_analysis", "Analyze vulnerability chains"),
        ("o1_security_recommendations", "Generate security recommendations")
    ]:
        tool = VulnerabilityAnalysisTool(client=mock_openai_client)
        metadata = ToolMetadata(
            name=name,
            description=desc,
            category=ToolCategory.ANALYSIS,
            version="1.0.0",
            author="Security Team",
            timeout=300
        )
        tool_manager.register_tool(metadata, tool)

    # Define tool chain
    tool_chain = [
        ("o1_vulnerability_analysis", {"code": sample_code}),
        ("o1_chain_analysis", {"vulnerabilities": sample_vulnerabilities}),
        ("o1_security_recommendations", {"findings": sample_vulnerabilities})
    ]

    # Execute chain
    results = await tool_manager.execute_chain(tool_chain)

    # Verify results
    assert len(results) == 3
    assert all(isinstance(r, ToolResult) and r.success for r in results)

    # Verify each step
    vuln_result, chain_result, rec_result = results

    vuln_data = cast(Dict[str, Any], vuln_result.data)
    chain_data = cast(Dict[str, Any], chain_result.data)
    rec_data = cast(Dict[str, Any], rec_result.data)

    assert vuln_data.get("vulnerabilities") is not None
    assert chain_data.get("chains") is not None
    assert rec_data.get("high_priority") is not None

@pytest.mark.asyncio
async def test_tool_timeout(
    tool_manager: DefaultLLMToolManager,
    mock_openai_client: AsyncOpenAI
) -> None:
    """Test tool execution timeout."""
    # Register tool with short timeout
    tool = VulnerabilityAnalysisTool(client=mock_openai_client)
    metadata = ToolMetadata(
        name="timeout_test",
        description="Test timeout",
        category=ToolCategory.ANALYSIS,
        version="1.0.0",
        author="Test",
        timeout=1
    )
    tool_manager.register_tool(metadata, tool)

    # Execute with delay
    result = await tool_manager.execute_tool(
        "timeout_test",
        code="# Large code block that would take time to analyze"
    )

    # Verify timeout
    assert not result.success
    error = result.error if result.error else ""
    assert "timeout" in error.lower()
