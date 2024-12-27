"""API security analysis tools using O1."""

from typing import Any, List, TypedDict, Dict, Optional
from dataclasses import dataclass
import json
from openai import AsyncOpenAI
from openai.types.chat import ChatCompletion, ChatCompletionMessage
from .tool_manager import ToolExecutor, ToolResult, ToolCategory, ToolMetadata
from .o1_tools import O1BaseAnalyzer
from .manager import DefaultLLMToolManager

class APIVulnerability(TypedDict):
    """Type definition for API vulnerability."""
    name: str
    endpoint: str
    method: str
    description: str
    impact: str
    prerequisites: List[str]
    exploitation_steps: List[str]
    severity: str
    cvss_score: float
    proof_of_concept: str
    remediation: str

@dataclass
class APISecurityAnalyzer(ToolExecutor, O1BaseAnalyzer):
    """Tool for analyzing API security using O1."""

    async def execute(self, **kwargs: Any) -> ToolResult:
        """Execute API security analysis."""
        try:
            endpoints = kwargs.get('endpoints', [])
            api_spec = kwargs.get('api_spec', {})
            context = kwargs.get('context', {})

            if not endpoints and not api_spec:
                return ToolResult(
                    success=False,
                    data=None,
                    error="No API endpoints or specification provided for analysis"
                )

            system_prompt = """You are an expert in API security. Analyze the provided
            API endpoints and specification for vulnerabilities, focusing on:
            1. Authentication/Authorization
            2. Input validation
            3. Rate limiting
            4. Data exposure
            5. Business logic flaws
            Return detailed findings in JSON format with practical exploitation steps."""

            prompt = f"""Analyze these API endpoints for vulnerabilities:

            Endpoints:
            {json.dumps(endpoints, indent=2)}

            API Specification:
            {json.dumps(api_spec, indent=2)}

            Context:
            {json.dumps(context, indent=2)}

            For each endpoint, analyze:
            1. Authentication mechanisms
            2. Authorization controls
            3. Input validation
            4. Rate limiting
            5. Data exposure
            6. Business logic
            7. Error handling
            8. CVSS scoring
            9. Proof of concept
            10. Remediation steps"""

            # Use full o1 model for complex API analysis
            response: ChatCompletion = await self._analyze(prompt, system_prompt, use_mini=False)
            message: Optional[ChatCompletionMessage] = response.choices[0].message
            content = str(message.content if message else '')
            if not content:
                raise ValueError("Empty response from OpenAI API")

            # Parse the response and create the analysis dict
            raw_analysis = json.loads(content)
            usage = response.usage

            analysis: Dict[str, Any] = {
                "findings": raw_analysis.get("findings", []),
                "confidence": raw_analysis.get("confidence", 0.0),
                "reasoning": raw_analysis.get("reasoning", ""),
                "completion_tokens_details": {
                    "tokens": usage.total_tokens if usage else 0,
                    "completion_tokens": usage.completion_tokens if usage else 0
                }
            }

            return ToolResult(
                success=True,
                data=analysis,
                error=None
            )

        except Exception as e:
            self.logger.error(f"API security analysis failed: {e}")
            return ToolResult(
                success=False,
                data=None,
                error=str(e)
            )

@dataclass
class GraphQLSecurityAnalyzer(ToolExecutor, O1BaseAnalyzer):
    """Tool for analyzing GraphQL security using O1."""

    async def execute(self, **kwargs: Any) -> ToolResult:
        """Execute GraphQL security analysis."""
        try:
            schema = kwargs.get('schema', '')
            queries = kwargs.get('queries', [])
            context = kwargs.get('context', {})

            if not schema:
                return ToolResult(
                    success=False,
                    data=None,
                    error="No GraphQL schema provided for analysis"
                )

            system_prompt = """You are an expert in GraphQL security. Analyze the provided
            schema and queries for vulnerabilities, focusing on:
            1. Query complexity
            2. Field suggestions
            3. Batching attacks
            4. Information disclosure
            5. Authorization flaws
            Return detailed findings in JSON format with practical exploitation steps."""

            prompt = f"""Analyze this GraphQL API for vulnerabilities:

            Schema:
            {schema}

            Sample Queries:
            {json.dumps(queries, indent=2)}

            Context:
            {json.dumps(context, indent=2)}

            For each component, analyze:
            1. Query complexity
            2. Field suggestions
            3. Batching attacks
            4. Information disclosure
            5. Authorization flaws
            6. Introspection risks
            7. Depth/breadth limits
            8. CVSS scoring
            9. Proof of concept
            10. Remediation steps"""

            # Use full o1 model for complex GraphQL analysis
            response: ChatCompletion = await self._analyze(prompt, system_prompt, use_mini=False)
            message: Optional[ChatCompletionMessage] = response.choices[0].message
            content = str(message.content if message else '')
            if not content:
                raise ValueError("Empty response from OpenAI API")

            # Parse the response and create the analysis dict
            raw_analysis = json.loads(content)
            usage = response.usage

            analysis: Dict[str, Any] = {
                "findings": raw_analysis.get("findings", []),
                "confidence": raw_analysis.get("confidence", 0.0),
                "reasoning": raw_analysis.get("reasoning", ""),
                "completion_tokens_details": {
                    "tokens": usage.total_tokens if usage else 0,
                    "completion_tokens": usage.completion_tokens if usage else 0
                }
            }

            return ToolResult(
                success=True,
                data=analysis,
                error=None
            )

        except Exception as e:
            self.logger.error(f"GraphQL security analysis failed: {e}")
            return ToolResult(
                success=False,
                data=None,
                error=str(e)
            )

def register_api_security_tools(manager: DefaultLLMToolManager) -> None:
    """Register API security analysis tools with the manager."""
    # Create shared OpenAI client
    client = AsyncOpenAI()

    # Register API security analyzer
    api_tool = APISecurityAnalyzer(client=client)
    api_metadata = ToolMetadata(
        name="o1_api_security_analysis",
        description="Analyze API security using O1",
        category=ToolCategory.ANALYSIS,
        version="1.0.0",
        author="Security Team",
        timeout=300  # Longer timeout for complex analysis
    )
    manager.register_tool(api_metadata, api_tool)

    # Register GraphQL security analyzer
    graphql_tool = GraphQLSecurityAnalyzer(client=client)
    graphql_metadata = ToolMetadata(
        name="o1_graphql_security_analysis",
        description="Analyze GraphQL security using O1",
        category=ToolCategory.ANALYSIS,
        version="1.0.0",
        author="Security Team",
        timeout=300  # Longer timeout for complex analysis
    )
    manager.register_tool(graphql_metadata, graphql_tool)
