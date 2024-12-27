from __future__ import annotations

from typing import AsyncGenerator, Dict
from datetime import datetime, UTC
import json
from unittest.mock import AsyncMock, MagicMock, Mock

import pytest
from pytest_mock import MockerFixture

from tools.analysis.o1_analyzer import (
    O1Analyzer,
    SecurityAnalysisRequest,
    SecurityContext,
    AnalysisStatus
)

@pytest.fixture
async def analyzer(mocker: MockerFixture) -> AsyncGenerator[O1Analyzer, None]:
    """Create analyzer with mocked OpenAI client"""
    # Mock OpenAI client
    mock_message = Mock()
    mock_message.content = json.dumps({
        "findings": [{
            "title": "SQL Injection",
            "severity": "high",
            "vulnerability_type": "sql_injection",
            "location": "line 3",
            "description": "Direct user input in SQL query",
            "impact": "Database compromise",
            "fix": "Use parameterized queries",
            "cwe_id": "CWE-89",
            "confidence": 0.95,
            "reasoning": "The code directly interpolates user input into SQL query string. " * 10,
            "prerequisites": ["User input reaches database query"],
            "affected_components": ["Database layer"]
        }]
    })

    mock_choice = Mock()
    mock_choice.message = mock_message

    mock_usage = Mock()
    mock_usage.completion_tokens = 1000
    mock_usage.prompt_tokens = 500
    mock_usage.total_tokens = 1500

    mock_completion = Mock()
    mock_completion.choices = [mock_choice]
    mock_completion.usage = mock_usage

    mock_client = AsyncMock()
    mock_client.chat.completions.create.return_value = mock_completion
    mocker.patch("openai.AsyncOpenAI", return_value=mock_client)

    async with O1Analyzer() as analyzer:
        yield analyzer

@pytest.fixture
def sample_code() -> str:
    return """
def process_user_input(user_input: str) -> str:
    # Vulnerable code for testing
    query = f"SELECT * FROM users WHERE id = {user_input}"
    return query
"""

@pytest.fixture
def sample_context() -> SecurityContext:
    return SecurityContext(
        service="test_service",
        endpoint="/api/users",
        method="GET",
        parameters={
            "id": "integer",
            "fields": "string[]"
        },
        timestamp=datetime.now(UTC)
    )

@pytest.fixture
def sample_request(sample_code: str, sample_context: SecurityContext) -> SecurityAnalysisRequest:
    return SecurityAnalysisRequest(
        code=sample_code,
        context=sample_context,
        focus_areas=["input validation", "query construction"],
        vulnerability_types=["sql_injection", "input_validation"]
    )

@pytest.mark.asyncio
async def test_analyze_single_request(
    analyzer: O1Analyzer,
    sample_request: SecurityAnalysisRequest,
    mocker: MockerFixture
) -> None:
    # Arrange
    mock_span = MagicMock()
    mock_tracer = mocker.patch("opentelemetry.trace.get_tracer")
    mock_tracer.return_value.start_as_current_span.return_value.__enter__.return_value = mock_span

    # Act
    result: Dict = await analyzer.analyze(sample_request)

    # Assert
    assert isinstance(result, dict)
    assert "findings" in result
    assert isinstance(result["findings"], list)
    assert result["reasoning_tokens"] > 0
    assert result["completion_tokens"] > 0
    assert result["total_tokens"] > 0
    assert result["status"] == AnalysisStatus.SUCCESS

    # Validate finding structure
    finding = result["findings"][0]
    assert finding["title"] == "SQL Injection"
    assert finding["severity"] == "high"
    assert finding["vulnerability_type"] == "sql_injection"
    assert 0 <= finding["confidence"] <= 1

    # Verify tracing
    mock_span.set_attribute.assert_any_call("model", analyzer.model)
    mock_span.set_attribute.assert_any_call("code_length", len(sample_request.code))

@pytest.mark.asyncio
async def test_analyze_batch_requests(analyzer: O1Analyzer) -> None:
    # Arrange
    requests = [
        SecurityAnalysisRequest(
            code="print(input('Enter command: '))",
            context=SecurityContext(
                service="test_service",
                endpoint="/api/execute",
                method="POST"
            ),
            focus_areas=["input validation"],
            vulnerability_types=["command_injection"]
        ),
        SecurityAnalysisRequest(
            code="exec(user_input)",
            context=SecurityContext(
                service="test_service",
                endpoint="/api/eval",
                method="POST"
            ),
            focus_areas=["input validation"],
            vulnerability_types=["code_injection"]
        )
    ]

    # Act
    results = await analyzer.analyze_batch(requests)

    # Assert
    assert len(results) == len(requests)
    for result in results:
        assert isinstance(result, dict)
        assert "findings" in result
        assert result["reasoning_tokens"] > 0
        assert result["status"] == AnalysisStatus.SUCCESS

@pytest.mark.asyncio
async def test_error_handling(
    analyzer: O1Analyzer,
    mocker: MockerFixture
) -> None:
    # Arrange
    mock_client = AsyncMock()
    mock_client.chat.completions.create.side_effect = Exception("API Error")
    mocker.patch("openai.AsyncOpenAI", return_value=mock_client)

    invalid_request = SecurityAnalysisRequest(
        code="",  # Empty code should raise an error
        context=SecurityContext(
            service="test_service",
            endpoint="/api/test",
            method="GET"
        ),
        focus_areas=[],
        vulnerability_types=[]
    )

    # Act & Assert
    with pytest.raises(ValueError, match="Empty code provided"):
        await analyzer.analyze(invalid_request)

@pytest.mark.asyncio
async def test_caching(
    analyzer: O1Analyzer,
    sample_request: SecurityAnalysisRequest,
    mocker: MockerFixture
) -> None:
    # Arrange
    mock_client = AsyncMock()
    mocker.patch("openai.AsyncOpenAI", return_value=mock_client)

    # Act
    result1 = await analyzer.analyze(sample_request)
    result2 = await analyzer.analyze(sample_request)

    # Assert
    assert result1 == result2
    assert mock_client.chat.completions.create.call_count == 1
