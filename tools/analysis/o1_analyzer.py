from __future__ import annotations

from typing import List, Dict, Any, TypedDict, Sequence, Final
from typing_extensions import TypeAlias
from dataclasses import dataclass, field
from enum import Enum, auto
import os
import logging
import orjson
from openai import AsyncOpenAI
import asyncio
from dotenv import load_dotenv
import aiohttp
from aiohttp_retry import RetryClient, ExponentialRetry
from pydantic import BaseModel, Field, validator
from datetime import datetime
from cachetools import TTLCache
from opentelemetry import trace
from opentelemetry.trace import Status, StatusCode

# Type aliases
JsonDict: TypeAlias = Dict[str, Any]
Findings: TypeAlias = List[Dict[str, Any]]

# Constants
MAX_RETRIES: Final[int] = 3
DEFAULT_TIMEOUT: Final[int] = 180
MIN_REASONING_LENGTH: Final[int] = 50

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
    timestamp: datetime = Field(default_factory=datetime.utcnow)

    @validator("method")
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
        self.cache: TTLCache = TTLCache(
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

    async def __aenter__(self) -> O1Analyzer:
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        await self.cleanup()

    async def cleanup(self) -> None:
        """Cleanup resources"""
        if self.http_client:
            await self.http_client.close()

    def _prepare_analysis_prompt(self, request: SecurityAnalysisRequest) -> str:
        """Prepare sanitized prompt for O1 analysis"""
        return f"""Analyze this code for security vulnerabilities. Focus on identifying complex, non-obvious security issues that require deep understanding of the code's context and potential interactions.

CODE:
{request.code}

CONTEXT:
{orjson.dumps(request.context.dict(), option=orjson.OPT_INDENT_2).decode()}

Consider these vulnerability types:
{', '.join(request.vulnerability_types)}

Additional focus areas:
{', '.join(request.focus_areas)}

Return a detailed analysis in this JSON format:
{{
    "findings": [
        {{
            "title": "string",
            "severity": "critical|high|medium|low",
            "vulnerability_type": "string",
            "location": "string",
            "description": "string",
            "impact": "string",
            "fix": "string",
            "cwe_id": "string",
            "confidence": float,
            "reasoning": "string",
            "prerequisites": ["string"],
            "affected_components": ["string"]
        }}
    ]
}}"""

    async def analyze(self, request: SecurityAnalysisRequest) -> AnalysisResult:
        """Perform security analysis using O1 model with advanced reasoning"""
        with self.tracer.start_as_current_span("o1_analysis") as span:
            try:
                # Check cache
                cache_key = orjson.dumps([request.code, request.context.dict()])
                if cached_result := self.cache.get(cache_key):
                    span.set_attribute("cache.hit", True)
                    return cached_result

                span.set_attribute("model", self.model)
                span.set_attribute("code_length", len(request.code))

                response = await self.client.chat.completions.create(
                    model=self.model,
                    messages=[
                        {
                            "role": "user",
                            "content": self._prepare_analysis_prompt(request)
                        }
                    ],
                    max_completion_tokens=self.max_completion_tokens,
                    temperature=0.1  # Lower temperature for more focused analysis
                )

                # Parse response
                content = response.choices[0].message.content
                findings = orjson.loads(content)

                # Extract token usage
                usage = response.usage
                completion_details = usage.completion_tokens_details

                result = AnalysisResult(
                    findings=findings["findings"],
                    reasoning_tokens=completion_details.reasoning_tokens,
                    completion_tokens=completion_details.accepted_prediction_tokens,
                    total_tokens=usage.total_tokens,
                    status=AnalysisStatus.SUCCESS
                )

                # Cache result
                self.cache[cache_key] = result
                span.set_status(Status(StatusCode.OK))

                return result

            except Exception as e:
                self.logger.error(f"Analysis failed: {str(e)}")
                span.set_status(Status(StatusCode.ERROR), str(e))
                span.record_exception(e)
                raise

    async def analyze_batch(
        self,
        requests: List[SecurityAnalysisRequest],
        concurrency: int = 3
    ) -> Sequence[AnalysisResult]:
        """Analyze multiple code snippets with rate limiting"""
        semaphore = asyncio.Semaphore(concurrency)

        async def _analyze_with_semaphore(request: SecurityAnalysisRequest) -> AnalysisResult:
            async with semaphore:
                return await self.analyze(request)

        results = await asyncio.gather(
            *[_analyze_with_semaphore(req) for req in requests],
            return_exceptions=True
        )

        return [r for r in results if isinstance(r, dict)]

    def validate_response(self, result: AnalysisResult) -> bool:
        """Validate analysis result format and content"""
        try:
            findings = result.get("findings", [])
            if not findings:
                return False

            required_fields = {
                "title", "severity", "vulnerability_type",
                "location", "description", "impact", "fix",
                "reasoning", "prerequisites", "affected_components"
            }

            for finding in findings:
                if not all(field in finding for field in required_fields):
                    return False

                if finding["severity"] not in {"critical", "high", "medium", "low"}:
                    return False

                if not (0 <= finding.get("confidence", 0) <= 1):
                    return False

                # Validate reasoning quality
                if len(finding.get("reasoning", "").split()) < MIN_REASONING_LENGTH:
                    return False

            return True

        except Exception as e:
            self.logger.error(f"Validation failed: {str(e)}")
            return False
