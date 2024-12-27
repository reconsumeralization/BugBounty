"""Tests for Azure-specific security analyzer."""

import pytest
from typing import AsyncGenerator, Dict, Any
from pathlib import Path
import json
from unittest.mock import AsyncMock, MagicMock, create_autospec, patch

from programs.microsoft.analyzers.azure_analyzer import (
    AzureAnalyzer,
    AzureContext,
    AzureServiceType
)
from tools.analysis.web_analyzer import WebEndpoint
from tools.analysis.o1_analyzer import O1Analyzer
from tools.llm.tool_manager import ToolResult
from openai import AsyncOpenAI
from openai.types.chat import ChatCompletion as OpenAIChatCompletion
from openai.types.chat.chat_completion_message import ChatCompletionMessage

class TestAzureAnalyzer(AzureAnalyzer):
    """Test implementation of AzureAnalyzer."""

    async def execute(self, **kwargs: Any) -> ToolResult:
        """Implement required abstract method."""
        endpoint = kwargs.get("endpoint")
        context = kwargs.get("context")
        if not endpoint or not context:
            return ToolResult(success=False, error="Missing required parameters")
        return await self.analyze_app_service(endpoint, context)

@pytest.fixture
def mock_config() -> Dict[str, Any]:
    """Create mock configuration."""
    return {
        "analysis": {
            "confidence_thresholds": {
                "critical": 0.90,
                "high": 0.85,
                "medium": 0.80,
                "low": 0.75
            }
        }
    }

@pytest.fixture
def sample_context() -> AzureContext:
    """Create sample Azure context."""
    return AzureContext(
        service_type=AzureServiceType.APP_SERVICE,
        region="eastus",
        subscription_id="12345678-1234-5678-1234-567812345678",
        resource_group="production-rg",
        instance_name="webapp1",
        access_tier="standard",
        network_rules={
            "ip_rules": ["10.0.0.0/24"],
            "virtual_network_rules": ["subnet1"]
        },
        security_controls={
            "authentication": "aad",
            "ssl_enabled": True,
            "minimum_tls_version": "1.2"
        },
        compliance_requirements={"PCI-DSS", "HIPAA"}
    )

@pytest.fixture
def sample_endpoint() -> WebEndpoint:
    """Create sample web endpoint."""
    return WebEndpoint(
        url="https://webapp1.azurewebsites.net/api/data",
        method="POST",
        parameters={"id": "string", "data": "object"},
        authentication={"type": "bearer"},
        rate_limits={"max_requests": 100, "window": 60}
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
            "id": "AZURE-001",
            "vulnerability_type": "authentication_bypass",
            "severity": "critical",
            "confidence": 0.95,
            "description": "Potential authentication bypass in App Service",
            "prerequisites": ["token_manipulation"],
            "affected_components": ["auth_service"],
            "requires_special_conditions": False
        }]
    })
    mock_client.chat.completions.create = AsyncMock(return_value=mock_completion)
    yield mock_client

@pytest.fixture
async def azure_analyzer(
    mock_config: Dict[str, Any],
    mock_openai_client: AsyncOpenAI
) -> AsyncGenerator[TestAzureAnalyzer, None]:
    """Create Azure analyzer instance."""
    with patch("pathlib.Path.open"), \
         patch("json.load") as mock_load:

        mock_load.return_value = mock_config
        o1_analyzer = O1Analyzer(openai_client=mock_openai_client)
        analyzer = TestAzureAnalyzer(
            config_path=Path("test_config.json"),
            o1_analyzer=o1_analyzer
        )
        yield analyzer

@pytest.mark.asyncio
async def test_analyze_app_service(
    azure_analyzer: TestAzureAnalyzer,
    sample_endpoint: WebEndpoint,
    sample_context: AzureContext
) -> None:
    """Test App Service analysis."""
    result = await azure_analyzer.analyze_app_service(sample_endpoint, sample_context)

    assert result.success
    assert result.data is not None
    assert isinstance(result.data, dict)
    assert "findings" in result.data
    findings = result.data["findings"]
    assert isinstance(findings, list)
    assert len(findings) > 0

    finding = findings[0]
    assert isinstance(finding, dict)
    assert finding["vulnerability_type"] == "authentication_bypass"
    assert finding["severity"] == "critical"
    assert finding["confidence"] >= 0.90
    assert finding["azure_context"]["service_type"] == AzureServiceType.APP_SERVICE.value
    assert finding["azure_context"]["region"] == sample_context.region
    assert finding["azure_severity"] == "critical"  # Due to production resource group
    assert "PCI-DSS" in finding.get("compliance_impact", {})

@pytest.mark.asyncio
async def test_analyze_storage(
    azure_analyzer: TestAzureAnalyzer,
    sample_endpoint: WebEndpoint,
    sample_context: AzureContext
) -> None:
    """Test Storage analysis."""
    # Modify context for storage
    sample_context.service_type = AzureServiceType.STORAGE

    result = await azure_analyzer.analyze_storage(sample_endpoint, sample_context)

    assert result.success
    assert result.data is not None
    assert isinstance(result.data, dict)
    assert "findings" in result.data
    findings = result.data["findings"]
    assert isinstance(findings, list)
    assert len(findings) > 0

    finding = findings[0]
    assert isinstance(finding, dict)
    assert finding["azure_context"]["service_type"] == AzureServiceType.STORAGE.value
    assert finding["azure_context"]["region"] == sample_context.region
    assert "Enable Azure Storage encryption" in finding.get("remediation", [])

@pytest.mark.asyncio
async def test_analyze_app_service_error(
    azure_analyzer: TestAzureAnalyzer,
    sample_endpoint: WebEndpoint,
    sample_context: AzureContext
) -> None:
    """Test App Service analysis with error."""
    with patch.object(
        azure_analyzer.o1_analyzer,
        "analyze",
        side_effect=Exception("Analysis error")
    ):
        result = await azure_analyzer.analyze_app_service(sample_endpoint, sample_context)
        assert not result.success
        assert result.error is not None
        assert "Analysis failed" in result.error
