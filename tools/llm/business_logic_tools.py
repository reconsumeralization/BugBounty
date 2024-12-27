"""Business logic security analysis tools using O1 models."""

from dataclasses import dataclass
from typing import Dict, List, Optional, Any
import json
import logging
from openai import AsyncOpenAI
from openai.types.chat import ChatCompletion, ChatCompletionMessage

from tools.llm.tool_manager import ToolExecutor, ToolResult

logger = logging.getLogger(__name__)

@dataclass
class BusinessLogicVulnerability:
    """Represents a business logic vulnerability."""
    name: str
    category: str
    description: str
    impact: str
    affected_components: List[str]
    prerequisites: List[str]
    exploitation_steps: List[str]
    severity: str
    cvss_score: float
    bounty_range: str
    proof_of_concept: str
    remediation: str
    business_rules_violated: List[str]

class BusinessLogicAnalyzer(ToolExecutor):
    """Analyzes business logic for security vulnerabilities."""

    def __init__(self, client: AsyncOpenAI) -> None:
        """Initialize the analyzer.

        Args:
            client: OpenAI client for API calls
        """
        self.client = client
        self.max_tokens = 4096
        self.temperature = 0.1
        self.model = "gpt-4-1106-preview"

    async def execute(
        self,
        source_code: Optional[Dict[str, Any]] = None,
        business_rules: Optional[Dict[str, Any]] = None,
        context: Optional[Dict[str, Any]] = None,
        **kwargs: Any
    ) -> ToolResult:
        """Execute business logic analysis.

        Args:
            source_code: Application source code components
            business_rules: Business rules and constraints
            context: Additional context for analysis
            kwargs: Additional keyword arguments

        Returns:
            ToolResult containing vulnerabilities found
        """
        try:
            if not source_code:
                return ToolResult(
                    success=False,
                    data=None,
                    error="No application components provided for analysis"
                )

            prompt = self._build_prompt(source_code, business_rules, context)
            response = await self._analyze(prompt)
            message: Optional[ChatCompletionMessage] = response.choices[0].message
            content = str(message.content if message else '')
            if not content:
                raise ValueError("Empty response from OpenAI API")

            # Parse the response and create the analysis dict
            raw_analysis = json.loads(content)

            return ToolResult(
                success=True,
                data=raw_analysis,
                error=None
            )

        except Exception as e:
            logger.error(f"Error in business logic analysis: {str(e)}")
            return ToolResult(
                success=False,
                data=None,
                error=str(e)
            )

    def _build_prompt(
        self,
        source_code: Dict[str, Any],
        business_rules: Optional[Dict[str, Any]],
        context: Optional[Dict[str, Any]]
    ) -> str:
        """Build analysis prompt.

        Args:
            source_code: Application source code
            business_rules: Business rules and constraints
            context: Additional context

        Returns:
            Formatted prompt string
        """
        prompt = [
            "Analyze the following application for business logic vulnerabilities.",
            "Consider authentication, authorization, workflow, and data validation.",
            "\nSource code:",
            json.dumps(source_code, indent=2)
        ]

        if business_rules:
            prompt.extend([
                "\nBusiness rules:",
                json.dumps(business_rules, indent=2)
            ])

        if context:
            prompt.extend([
                "\nAdditional context:",
                json.dumps(context, indent=2)
            ])

        prompt.extend([
            "\nProvide a detailed analysis including:",
            "- Vulnerabilities found (name, category, description)",
            "- Impact and prerequisites",
            "- Exploitation steps",
            "- Severity and CVSS score",
            "- Bug bounty range estimate",
            "- Proof of concept",
            "- Remediation steps",
            "- Business rules violated",
            "\nFormat the response as a JSON object."
        ])

        return "\n".join(prompt)

    async def _analyze(self, prompt: str) -> ChatCompletion:
        """Execute analysis using O1 model.

        Args:
            prompt: Analysis prompt

        Returns:
            Model response
        """
        return await self.client.chat.completions.create(
            model=self.model,
            messages=[{
                "role": "system",
                "content": "You are an expert in business logic security analysis."
            }, {
                "role": "user",
                "content": prompt
            }],
            temperature=self.temperature,
            max_tokens=self.max_tokens
        )
