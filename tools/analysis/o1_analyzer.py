from __future__ import annotations

from typing import List, Dict, Any, TypedDict, Final, Sequence
from typing_extensions import TypeAlias
from dataclasses import dataclass, field
from enum import Enum, auto
import os
import logging
from datetime import datetime, UTC
import asyncio

try:
    import aiohttp
    from aiohttp_retry import RetryClient, ExponentialRetry
except ImportError:
    raise ImportError("aiohttp and aiohttp_retry are required. Install with: pip install aiohttp aiohttp_retry")

try:
    from pydantic import BaseModel, Field, field_validator
except ImportError:
    raise ImportError("pydantic is required. Install with: pip install pydantic")

from cachetools import TTLCache
try:
    from opentelemetry import trace
except ImportError:
    raise ImportError("opentelemetry is required. Install with: pip install opentelemetry-api")

try:
    from openai import AsyncOpenAI
    from openai.types.chat.chat_completion import ChatCompletion, Choice
    from openai.types.chat.chat_completion_message import ChatCompletionMessage
    from openai.types.completion_usage import CompletionUsage
except ImportError:
    raise ImportError("openai is required. Install with: pip install openai")

try:
    from dotenv import load_dotenv
except ImportError:
    raise ImportError("python-dotenv is required. Install with: pip install python-dotenv")

# Type aliases
JsonDict: TypeAlias = Dict[str, Any]
Finding: TypeAlias = Dict[str, Any]
Findings: TypeAlias = List[Finding]

# Constants
MAX_RETRIES: Final[int] = 3
DEFAULT_TIMEOUT: Final[int] = 180
MIN_REASONING_LENGTH: Final[int] = 50
DEFAULT_BATCH_SIZE: Final[int] = 5

class AnalysisStatus(Enum):
    SUCCESS = auto()
    FAILURE = auto()
    PARTIAL = auto()

class AnalysisResult(TypedDict):
    findings: Findings
    reasoning_tokens: int
    completion_tokens: int
    total_tokens: int
    status: AnalysisStatus

class SecurityContext(BaseModel):
    service: str
    endpoint: str
    method: str
    parameters: Dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @field_validator("method")
    def validate_method(cls, v: str) -> str:
        valid_methods = {"GET", "POST", "PUT", "DELETE", "PATCH"}
        if v.upper() not in valid_methods:
            raise ValueError(f"Invalid HTTP method: {v}")
        return v.upper()

@dataclass
class SecurityAnalysisRequest:
    code: str
    context: SecurityContext
    focus_areas: List[str]
    vulnerability_types: List[str]
    confidence_threshold: float = 0.8
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.code.strip():
            raise ValueError("Empty code provided")
        if not self.vulnerability_types:
            raise ValueError("No vulnerability types specified")

class O1Analyzer:
    """Security analyzer using OpenAI's O1 model for advanced reasoning"""

    def __init__(self) -> None:
        load_dotenv()

        self.client = AsyncOpenAI(
            api_key=os.getenv("OPENAI_API_KEY"),
            timeout=float(os.getenv("TIMEOUT_SECONDS", DEFAULT_TIMEOUT))
        )
        self.model = os.getenv("O1_MODEL", "o1-mini")
        self.max_completion_tokens = int(os.getenv("O1_REASONING_BUFFER", 25000))
        self.logger = logging.getLogger(__name__)
        self.tracer = trace.get_tracer(__name__)

        # Initialize caching
        cache_ttl = int(os.getenv("CACHE_TTL_HOURS", 24)) * 3600
        self.cache: TTLCache[bytes, AnalysisResult] = TTLCache(
            maxsize=int(os.getenv("CACHE_MAX_ENTRIES", 1000)),
            ttl=cache_ttl
        )

        # Initialize retry client
        retry_options = ExponentialRetry(
            attempts=MAX_RETRIES,
            start_timeout=1,
            max_timeout=10,
            factor=2
        )
        self.http_client = RetryClient(
            client_session=aiohttp.ClientSession(),
            retry_options=retry_options
        )

    async def analyze_batch(
        self,
        requests: Sequence[SecurityAnalysisRequest],
        batch_size: int = DEFAULT_BATCH_SIZE
    ) -> List[AnalysisResult]:
        """Analyze multiple requests in batches.

        Args:
            requests: Sequence of security analysis requests
            batch_size: Number of requests to process concurrently

        Returns:
            List of AnalysisResult for each request

        Raises:
            RuntimeError: If batch analysis fails
        """
        results: List[AnalysisResult] = []
        semaphore = asyncio.Semaphore(batch_size)

        async def analyze_with_semaphore(request: SecurityAnalysisRequest) -> AnalysisResult:
            async with semaphore:
                return await self.analyze(request)

        # Process requests in batches
        for i in range(0, len(requests), batch_size):
            batch = requests[i:i + batch_size]
            try:
                batch_results = await asyncio.gather(
                    *[analyze_with_semaphore(request) for request in batch],
                    return_exceptions=True
                )

                # Filter out failed analyses
                for result in batch_results:
                    if isinstance(result, Exception):
                        self.logger.error(f"Batch analysis failed: {str(result)}")
                        failure_result: AnalysisResult = {
                            "findings": [],
                            "reasoning_tokens": 0,
                            "completion_tokens": 0,
                            "total_tokens": 0,
                            "status": AnalysisStatus.FAILURE
                        }
                        results.append(failure_result)
                    else:
                        # Type check to ensure result is AnalysisResult
                        if isinstance(result, dict) and all(k in result for k in AnalysisResult.__annotations__):
                            results.append(result)
                        else:
                            self.logger.error(f"Invalid result type: {type(result)}")
                            failure_result: AnalysisResult = {
                                "findings": [],
                                "reasoning_tokens": 0,
                                "completion_tokens": 0,
                                "total_tokens": 0,
                                "status": AnalysisStatus.FAILURE
                            }
                            results.append(failure_result)

            except Exception as e:
                self.logger.error(f"Batch processing failed: {str(e)}")
                # Add failure results for the entire batch
                failure_result: AnalysisResult = {
                    "findings": [],
                    "reasoning_tokens": 0,
                    "completion_tokens": 0,
                    "total_tokens": 0,
                    "status": AnalysisStatus.FAILURE
                }
                results.extend([failure_result for _ in batch])

        return results

    async def analyze(self, request: SecurityAnalysisRequest) -> AnalysisResult:
        """Analyze code for security vulnerabilities using O1 model.

        Args:
            request: The security analysis request containing code and context

        Returns:
            AnalysisResult containing findings and analysis metrics

        Raises:
            ValueError: If the request is invalid
            RuntimeError: If analysis fails
        """
        # Check cache
        cache_key = self._compute_cache_key(request)
        if cache_key in self.cache:
            return self.cache[cache_key]

        # Create analysis span
        with self.tracer.start_as_current_span("o1_analysis") as span:
            try:
                # Prepare prompt
                prompt = self._prepare_analysis_prompt(request)

                # Call O1 model
                response: ChatCompletion = await self.client.chat.completions.create(
                    model=self.model,
                    messages=[{
                        "role": "system",
                        "content": "You are a security analysis assistant focused on identifying vulnerabilities."
                    }, {
                        "role": "user",
                        "content": prompt
                    }],
                    max_tokens=self.max_completion_tokens,
                    temperature=0.1
                )

                if not response.usage:
                    raise RuntimeError("No usage information in response")

                usage: CompletionUsage = response.usage

                # Process response
                findings = self._process_response(response)

                # Create result
                result = AnalysisResult(
                    findings=findings,
                    reasoning_tokens=usage.prompt_tokens,
                    completion_tokens=usage.completion_tokens,
                    total_tokens=usage.total_tokens,
                    status=AnalysisStatus.SUCCESS if findings else AnalysisStatus.PARTIAL
                )

                # Cache result
                self.cache[cache_key] = result
                return result

            except Exception as e:
                self.logger.error(f"Analysis failed: {str(e)}")
                span.set_status(trace.Status(trace.StatusCode.ERROR, str(e)))
                raise RuntimeError(f"Analysis failed: {str(e)}")

    def _compute_cache_key(self, request: SecurityAnalysisRequest) -> bytes:
        """Compute cache key for request"""
        key_parts = [
            request.code,
            request.context.service,
            request.context.endpoint,
            request.context.method,
            str(sorted(request.focus_areas)),
            str(sorted(request.vulnerability_types))
        ]
        return "|".join(key_parts).encode()

    def _prepare_analysis_prompt(self, request: SecurityAnalysisRequest) -> str:
        """Prepare analysis prompt from request"""
        return f"""
        Analyze the following code for security vulnerabilities:

        Code:
        {request.code}

        Context:
        - Service: {request.context.service}
        - Endpoint: {request.context.endpoint}
        - Method: {request.context.method}
        - Parameters: {request.context.parameters}

        Focus on these areas:
        {", ".join(request.focus_areas)}

        Look for these vulnerability types:
        {", ".join(request.vulnerability_types)}

        For each finding, provide:
        1. Vulnerability type and severity
        2. Description and impact
        3. Reproduction steps
        4. Remediation guidance
        """

    def _process_response(self, response: ChatCompletion) -> Findings:
        """Process model response into findings"""
        try:
            choices: List[Choice] = response.choices
            if not choices:
                return []

            message: ChatCompletionMessage = choices[0].message
            if not message.content:
                return []

            content: str = message.content
            if len(content) < MIN_REASONING_LENGTH:
                return []

            # Parse findings from response
            findings = self._parse_findings(content)
            return findings

        except Exception as e:
            self.logger.error(f"Failed to process response: {str(e)}")
            return []

    def _parse_findings(self, content: str) -> Findings:
        """Parse findings from response content"""
        # TODO: Implement finding parsing based on response format
        findings: Findings = []
        return findings
