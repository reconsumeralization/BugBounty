"""E-voting security analysis tools using O1."""

from typing import Any, List, TypedDict, Dict, Optional
from dataclasses import dataclass
import json
from openai import AsyncOpenAI
from openai.types.chat import ChatCompletion, ChatCompletionMessage
from .tool_manager import (
    ToolExecutor,
    ToolResult,
    ToolCategory,
    ToolMetadata,
)
from .manager import DefaultLLMToolManager
from .o1_tools import O1BaseAnalyzer

class EVotingVulnerability(TypedDict):
    """Type definition for e-voting vulnerability."""
    name: str
    category: str  # "vote_manipulation", "privacy_breach", "protocol_violation", etc.
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
    trust_assumptions_violated: List[str]

@dataclass
class EVotingAnalyzer(ToolExecutor, O1BaseAnalyzer):
    """Tool for analyzing e-voting system security using O1."""

    async def execute(self, **kwargs: Any) -> ToolResult:
        """Execute e-voting security analysis."""
        try:
            source_code = kwargs.get('source_code', {})
            protocol_spec = kwargs.get('protocol_spec', {})
            system_spec = kwargs.get('system_spec', {})
            context = kwargs.get('context', {})

            if not source_code and not protocol_spec and not system_spec:
                return ToolResult(
                    success=False,
                    data=None,
                    error="No e-voting system components provided for analysis"
                )

            system_prompt = """You are an expert in e-voting security analysis. Analyze the provided
            system components for critical vulnerabilities, focusing on:
            1. Vote manipulation (undetected by voter and system) - Critical severity (€70,000-€230,000)
               - Individual vote manipulation without detection
               - Tallying process manipulation
            2. Vote manipulation (detected by system) - High severity (€50,000-€70,000)
               - Individual vote manipulation with system detection
               - Result manipulation detected by auditors
            3. Vote privacy breaches - High severity (€40,000-€50,000)
               - Server-side privacy violations
               - Protocol-level privacy issues
            4. Vote corruption - High severity (€30,000-€40,000)
               - Vote decryption prevention
               - Unfair advantage scenarios
            5. Trust assumption violations
               - Federal Chancellery Ordinance compliance
               - Control component assumptions
            Return detailed findings in JSON format with practical exploitation steps."""

            prompt = f"""Analyze these e-voting system components for vulnerabilities:

            Source Code:
            {json.dumps(source_code, indent=2)}

            Protocol Specification:
            {json.dumps(protocol_spec, indent=2)}

            System Specification:
            {json.dumps(system_spec, indent=2)}

            Context:
            {json.dumps(context, indent=2)}

            For each component, analyze:
            1. Vote manipulation possibilities:
               - Individual vote manipulation without detection (€70,000-€230,000)
               - Tallying process manipulation (€70,000-€230,000)
               - Manipulation detected by auditor but not voter (€50,000-€70,000)
            2. Vote privacy:
               - Server-side vote privacy breaches (€40,000-€50,000)
               - Protocol-level privacy issues (€40,000-€50,000)
            3. Vote corruption:
               - Vote decryption prevention (€30,000-€40,000)
               - Unfair advantage scenarios (€30,000-€40,000)
            4. Trust assumptions:
               - Federal Chancellery Ordinance compliance
               - Control component assumptions
            5. Implementation issues:
               - Cryptographic implementation flaws
               - Protocol deviations
               - Security function misuse
            6. CVSS scoring and bounty range
            7. Proof of concept
            8. Remediation steps"""

            # Use full o1 model for complex e-voting analysis
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
            self.logger.error(f"E-voting analysis failed: {e}")
            return ToolResult(
                success=False,
                data=None,
                error=str(e)
            )

@dataclass
class CryptographicAnalyzer(ToolExecutor, O1BaseAnalyzer):
    """Tool for analyzing e-voting cryptographic protocols using O1."""

    async def execute(self, **kwargs: Any) -> ToolResult:
        """Execute cryptographic protocol analysis."""
        try:
            protocol = kwargs.get('protocol', {})
            crypto_impl = kwargs.get('crypto_impl', {})
            context = kwargs.get('context', {})

            if not protocol and not crypto_impl:
                return ToolResult(
                    success=False,
                    data=None,
                    error="No cryptographic protocol or implementation provided for analysis"
                )

            system_prompt = """You are an expert in cryptographic protocol analysis. Analyze the provided
            e-voting cryptographic components for vulnerabilities, focusing on:
            1. Protocol design flaws (€70,000-€230,000 for undetectable manipulation)
            2. Implementation weaknesses (€50,000-€70,000 for detectable manipulation)
            3. Trust assumption violations (€40,000-€50,000 for privacy breaches)
            4. Universal verifiability issues (€30,000-€40,000 for vote corruption)
            5. Privacy guarantees
            Return detailed findings in JSON format with practical exploitation steps."""

            prompt = f"""Analyze these cryptographic components for vulnerabilities:

            Protocol:
            {json.dumps(protocol, indent=2)}

            Implementation:
            {json.dumps(crypto_impl, indent=2)}

            Context:
            {json.dumps(context, indent=2)}

            For each component, analyze:
            1. Protocol design:
               - Cryptographic primitives
               - Protocol flow
               - Trust assumptions
            2. Implementation:
               - Cryptographic operations
               - Key management
               - Random number generation
            3. Verifiability:
               - Individual verifiability
               - Universal verifiability
               - Proof generation and verification
            4. Privacy:
               - Vote secrecy (€40,000-€50,000 for breaches)
               - Ballot anonymity
               - Receipt-freeness
            5. Attack scenarios:
               - Protocol-level attacks (��70,000-€230,000 for undetectable manipulation)
               - Implementation attacks (€50,000-€70,000 for detectable manipulation)
               - Trust model violations
            6. CVSS scoring and bounty range
            7. Proof of concept
            8. Remediation steps"""

            # Use full o1 model for complex cryptographic analysis
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
            self.logger.error(f"Cryptographic analysis failed: {e}")
            return ToolResult(
                success=False,
                data=None,
                error=str(e)
            )

def register_evoting_tools(manager: DefaultLLMToolManager) -> None:
    """Register e-voting analysis tools with the manager."""

    # Create shared OpenAI client
    client = AsyncOpenAI()

    # Register e-voting analyzer
    evoting_tool = EVotingAnalyzer(client=client)
    evoting_metadata = ToolMetadata(
        name="o1_evoting_analysis",
        description="Analyze e-voting system security using O1",
        category=ToolCategory.ANALYSIS,
        version="1.0.0",
        author="Security Team",
        timeout=600  # Longer timeout for complex analysis
    )
    manager.register_tool(evoting_metadata, evoting_tool)

    # Register cryptographic analyzer
    crypto_tool = CryptographicAnalyzer(client=client)
    crypto_metadata = ToolMetadata(
        name="o1_crypto_analysis",
        description="Analyze e-voting cryptographic protocols using O1",
        category=ToolCategory.ANALYSIS,
        version="1.0.0",
        author="Security Team",
        timeout=600  # Longer timeout for complex analysis
    )
    manager.register_tool(crypto_metadata, crypto_tool)
