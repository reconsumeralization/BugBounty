"""O1-specific tools for security analysis."""

from typing import Dict, Any, List, TypedDict, Final, TYPE_CHECKING
from dataclasses import dataclass
import logging
import json

# Type checking imports
if TYPE_CHECKING:
    from openai import AsyncOpenAI

# Runtime imports
has_openai = False
try:
    from openai import AsyncOpenAI
    has_openai = True
except ImportError:
    logging.warning("OpenAI package not installed. O1 tools will not be available.")
    AsyncOpenAI = object  # type: ignore

from .tool_manager import ToolExecutor, ToolResult, ToolCategory, ToolMetadata
from .manager import DefaultLLMToolManager

# Constants
MAX_COMPLETION_TOKENS: Final[int] = 25000  # Reserve space for reasoning
MODEL_NAME: Final[str] = "o1"  # Use o1 for complex reasoning
MODEL_NAME_MINI: Final[str] = "o1-mini"  # Use for coding and specific tasks

class AnalysisResponse(TypedDict):
    """Type definition for analysis response."""
    findings: List[Dict[str, Any]]
    confidence: float
    reasoning: str
    completion_tokens_details: Dict[str, Any]

@dataclass
class O1BaseAnalyzer:
    """Base class for O1 analysis tools."""
    client: Any  # Type hint as Any to avoid forward reference issues

    def __init__(self, client: Any) -> None:
        if not has_openai:
            raise ImportError("OpenAI package not installed. Please install it to use O1 tools.")
        self.client = client
        self.logger = logging.getLogger(__name__)

    async def _analyze(
        self,
        prompt: str,
        system_prompt: str,
        use_mini: bool = False
    ) -> Any:  # Type hint as Any since ChatCompletion is not available at runtime
        """Execute analysis using OpenAI API."""
        try:
            messages: List[Dict[str, str]] = [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt}
            ]

            response = await self.client.chat.completions.create(
                model=MODEL_NAME_MINI if use_mini else MODEL_NAME,
                messages=messages,
                max_tokens=MAX_COMPLETION_TOKENS,
                response_format={"type": "json_object"}
            )
            return response
        except Exception as e:
            self.logger.error(f"OpenAI API call failed: {e}")
            raise

@dataclass
class VulnerabilityAnalysisTool(ToolExecutor, O1BaseAnalyzer):
    """Tool for analyzing vulnerabilities using O1."""

    async def execute(self, **kwargs: Any) -> ToolResult:
        """Execute vulnerability analysis."""
        try:
            code = str(kwargs.get('code', ''))
            context = kwargs.get('context', {})

            if not code:
                return ToolResult(
                    success=False,
                    data=None,
                    error="No code provided for analysis"
                )

            system_prompt = """You are an expert security analyst. Analyze the provided code for security vulnerabilities.
            Focus on identifying potential security issues, their severity, and provide detailed remediation steps.
            Return your analysis in JSON format with findings, confidence scores, and reasoning."""

            prompt = f"""Analyze this code for security vulnerabilities:

            ```
            {code}
            ```

            Context:
            {json.dumps(context, indent=2)}

            Provide a detailed security analysis including:
            1. Identified vulnerabilities
            2. Severity levels
            3. Potential impact
            4. Remediation steps
            5. Code examples for fixes"""

            # Use o1-mini since this is a focused code analysis task
            response = await self._analyze(prompt, system_prompt, use_mini=True)
            choices = response.choices
            content = str(choices[0].message.content or '')
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
            self.logger.error(f"Vulnerability analysis failed: {e}")
            return ToolResult(
                success=False,
                data=None,
                error=str(e)
            )

@dataclass
class ChainAnalysisTool(ToolExecutor, O1BaseAnalyzer):
    """Tool for analyzing vulnerability chains using O1."""

    async def execute(self, **kwargs: Any) -> ToolResult:
        """Execute chain analysis."""
        try:
            vulnerabilities = kwargs.get('vulnerabilities', [])
            context = kwargs.get('context', {})

            if not vulnerabilities:
                return ToolResult(
                    success=False,
                    data=None,
                    error="No vulnerabilities provided for chain analysis"
                )

            system_prompt = """You are an expert in attack chain analysis. Analyze the provided vulnerabilities
            to identify potential attack chains and their impact. Consider how vulnerabilities could be combined
            for maximum impact. Return your analysis in JSON format."""

            prompt = f"""Analyze these vulnerabilities for potential attack chains:

            Vulnerabilities:
            {json.dumps(vulnerabilities, indent=2)}

            Context:
            {json.dumps(context, indent=2)}

            Identify:
            1. Possible attack chains
            2. Prerequisites for each chain
            3. Overall impact
            4. Success likelihood
            5. Detection/prevention strategies"""

            # Use full o1 model for complex reasoning about attack chains
            response = await self._analyze(prompt, system_prompt, use_mini=False)
            choices = response.choices
            content = str(choices[0].message.content or '')
            if not content:
                raise ValueError("Empty response from OpenAI API")

            # Parse the response and create the analysis dict
            raw_analysis = json.loads(content)
            usage = response.usage

            analysis: Dict[str, Any] = {
                "chains": raw_analysis.get("chains", []),
                "impact": raw_analysis.get("impact", ""),
                "likelihood": raw_analysis.get("likelihood", 0.0),
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
            self.logger.error(f"Chain analysis failed: {e}")
            return ToolResult(
                success=False,
                data=None,
                error=str(e)
            )

@dataclass
class SecurityRecommendationTool(ToolExecutor, O1BaseAnalyzer):
    """Tool for generating security recommendations using O1."""

    async def execute(self, **kwargs: Any) -> ToolResult:
        """Execute recommendation generation."""
        try:
            findings = kwargs.get('findings', [])
            context = kwargs.get('context', {})

            if not findings:
                return ToolResult(
                    success=False,
                    data=None,
                    error="No findings provided for recommendation generation"
                )

            system_prompt = """You are an expert security consultant. Generate prioritized recommendations
            based on the security findings. Focus on practical, actionable steps for remediation.
            Return your recommendations in JSON format."""

            prompt = f"""Generate security recommendations for these findings:

            Findings:
            {json.dumps(findings, indent=2)}

            Context:
            {json.dumps(context, indent=2)}

            Provide:
            1. Prioritized recommendations
            2. Implementation steps
            3. Required resources
            4. Expected impact
            5. Validation steps"""

            # Use o1-mini since this is a focused recommendation task
            response = await self._analyze(prompt, system_prompt, use_mini=True)
            choices = response.choices
            content = str(choices[0].message.content or '')
            if not content:
                raise ValueError("Empty response from OpenAI API")

            # Parse the response and create the recommendations dict
            raw_recommendations = json.loads(content)
            usage = response.usage

            recommendations: Dict[str, Any] = {
                "recommendations": raw_recommendations.get("recommendations", []),
                "priority": raw_recommendations.get("priority", "medium"),
                "impact": raw_recommendations.get("impact", ""),
                "completion_tokens_details": {
                    "tokens": usage.total_tokens if usage else 0,
                    "completion_tokens": usage.completion_tokens if usage else 0
                }
            }

            return ToolResult(
                success=True,
                data=recommendations,
                error=None
            )

        except Exception as e:
            self.logger.error(f"Recommendation generation failed: {e}")
            return ToolResult(
                success=False,
                data=None,
                error=str(e)
            )

def register_o1_tools(manager: DefaultLLMToolManager) -> None:
    """Register O1 tools with the manager."""

    # Create shared OpenAI client
    client = AsyncOpenAI()

    # Register vulnerability analysis tool
    vuln_tool = VulnerabilityAnalysisTool(client=client)
    vuln_metadata = ToolMetadata(
        name="o1_vulnerability_analysis",
        description="Analyze code for security vulnerabilities using O1",
        category=ToolCategory.ANALYSIS,
        version="1.0.0",
        author="Security Team",
        timeout=300  # Longer timeout for complex analysis
    )
    manager.register_tool(vuln_metadata, vuln_tool)

    # Register chain analysis tool
    chain_tool = ChainAnalysisTool(client=client)
    chain_metadata = ToolMetadata(
        name="o1_chain_analysis",
        description="Analyze vulnerability chains using O1",
        category=ToolCategory.ANALYSIS,
        version="1.0.0",
        author="Security Team",
        timeout=300  # Longer timeout for complex analysis
    )
    manager.register_tool(chain_metadata, chain_tool)

    # Register recommendation tool
    rec_tool = SecurityRecommendationTool(client=client)
    rec_metadata = ToolMetadata(
        name="o1_security_recommendations",
        description="Generate security recommendations using O1",
        category=ToolCategory.REPORT,
        version="1.0.0",
        author="Security Team",
        timeout=300  # Longer timeout for complex analysis
    )
    manager.register_tool(rec_metadata, rec_tool)
