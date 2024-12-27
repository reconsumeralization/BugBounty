from dataclasses import dataclass
from typing import List, Dict, Any, Tuple, Optional, Protocol, TypedDict, TypeVar, Mapping, cast
from pathlib import Path
import json
import logging
from .scope_manager import ScopeManager, ScopeStatus
import asyncio
from enum import Enum
import hashlib
from datetime import datetime, timedelta
import aiohttp

# Custom exceptions
class LLMAnalysisError(Exception):
    """Base exception for LLM analysis errors"""
    pass

class APIError(LLMAnalysisError):
    """Raised when API calls fail"""
    pass

class ValidationError(LLMAnalysisError):
    """Raised when validation fails"""
    pass

class RateLimitError(APIError):
    """Raised when API rate limit is exceeded"""
    pass

class AuthenticationError(APIError):
    """Raised when API authentication fails"""
    pass

class InvalidResponseError(APIError):
    """Raised when API response is invalid"""
    pass

# Type definitions
class AnalysisContext(TypedDict):
    service: str
    endpoint: str
    method: str
    parameters: Dict[str, Any]

class LLMResponse(TypedDict):
    findings: List[Dict[str, Any]]
    status: str
    confidence: float
    metadata: Dict[str, Any]

ResponseT = TypeVar('ResponseT', covariant=True)

class AsyncResponse(Protocol[ResponseT]):
    async def json(self) -> ResponseT: ...
    status: int
    headers: Mapping[str, str]

class AsyncSession(Protocol):
    async def post(self, url: str, json: Dict[str, Any], headers: Dict[str, str]) -> AsyncResponse[Dict[str, Any]]: ...
    async def __aenter__(self) -> 'AsyncSession': ...
    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None: ...

class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

@dataclass
class CodeAnalysisRequest:
    code_snippet: str
    context: AnalysisContext
    focus_areas: List[str]
    vulnerability_types: List[str]
    confidence_threshold: float = 0.8

@dataclass
class VulnerabilityReport:
    title: str
    severity: Severity
    confidence: float
    description: str
    code_location: str
    potential_impact: str
    reproduction_steps: str
    recommendations: List[str]
    references: List[str]
    vulnerability_type: str
    impact_areas: List[str]
    timestamp: str

@dataclass
class CacheEntry:
    response: List[VulnerabilityReport]
    timestamp: datetime
    hash: str

class LLMAnalyzer:
    """Helper class for LLM-based code analysis with proper error handling and validation"""

    def __init__(self, config_path: Path, scope_path: Path):
        self.config = self._load_config(config_path)
        self.scope_manager = ScopeManager(scope_path)
        self.findings: Dict[ScopeStatus, List[VulnerabilityReport]] = {
            ScopeStatus.IN_SCOPE: [],
            ScopeStatus.OUT_OF_SCOPE: [],
            ScopeStatus.REQUIRES_CLARIFICATION: []
        }
        self.logger = logging.getLogger(__name__)
        self._setup_logging()
        self._validate_config()
        self._response_cache: Dict[str, CacheEntry] = {}
        self._cache_ttl = timedelta(hours=self.config.get('cache_ttl_hours', 24))
        self._session: Optional[aiohttp.ClientSession] = None

    def _setup_logging(self) -> None:
        """Configure logging with appropriate handlers and formatters"""
        self.logger.setLevel(logging.INFO)
        handler = logging.FileHandler('llm_analysis.log')
        handler.setFormatter(
            logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        )
        self.logger.addHandler(handler)

    def _validate_config(self) -> None:
        """Validate configuration parameters"""
        required_fields = ['llm_api_endpoint', 'api_key', 'max_tokens', 'temperature']
        missing_fields = [field for field in required_fields if field not in self.config]
        if missing_fields:
            raise ValidationError(f"Missing required config fields: {missing_fields}")

        # Validate value ranges
        if not (0 <= self.config.get('temperature', 0) <= 1):
            raise ValidationError("Temperature must be between 0 and 1")
        if self.config.get('max_tokens', 0) <= 0:
            raise ValidationError("max_tokens must be positive")
        if not self.config['llm_api_endpoint'].startswith(('http://', 'https://')):
            raise ValidationError("Invalid API endpoint URL")

    def _load_config(self, config_path: Path) -> Dict[str, Any]:
        """Load configuration from file"""
        try:
            with open(config_path) as f:
                return json.load(f)
        except Exception as e:
            raise ValidationError(f"Failed to load config: {str(e)}")

    def _sanitize_input(self, text: str) -> str:
        """Sanitize input text to prevent prompt injection"""
        # Remove potential control characters and normalize whitespace
        sanitized = ' '.join(text.split())
        # Additional sanitization for potential prompt injection characters
        sanitized = sanitized.replace('{', '{{').replace('}', '}}')
        return sanitized

    def _sanitize_context(self, context: Dict[str, Any]) -> str:
        """Sanitize analysis context"""
        # Cast the context to AnalysisContext to ensure type safety
        analysis_context = cast(AnalysisContext, context)
        return json.dumps({
            k: self._sanitize_input(str(v)) if isinstance(v, str) else v
            for k, v in analysis_context.items()
        })

    def _get_cache_key(self, endpoint_config: Dict[str, Any]) -> str:
        """Generate cache key for endpoint configuration"""
        config_str = json.dumps(endpoint_config, sort_keys=True)
        return hashlib.sha256(config_str.encode()).hexdigest()

    def _check_cache(self, cache_key: str) -> Optional[List[VulnerabilityReport]]:
        """Check if valid cached response exists"""
        if cache_key in self._response_cache:
            entry = self._response_cache[cache_key]
            if datetime.now() - entry.timestamp < self._cache_ttl:
                self.logger.info(f"Cache hit for key {cache_key}")
                return entry.response
            else:
                del self._response_cache[cache_key]
        return None

    async def _make_api_request(self, url: str, data: Dict[str, Any], headers: Dict[str, str]) -> AsyncResponse[Dict[str, Any]]:
        """Make API request using aiohttp session"""
        if self._session is None:
            self._session = aiohttp.ClientSession()

        response = await self._session.post(url, json=data, headers=headers)
        # Cast the response to AsyncResponse since ClientResponse implements the protocol
        return cast(AsyncResponse[Dict[str, Any]], response)

    def _parse_llm_response(self, response: Dict[str, Any]) -> List[VulnerabilityReport]:
        """Parse and validate LLM API response"""
        # Cast the response to LLMResponse to ensure type safety
        llm_response = cast(LLMResponse, response)
        findings: List[VulnerabilityReport] = []

        try:
            if not llm_response.get('findings', []):
                raise ValidationError("Response findings must be a list")

            for finding in llm_response['findings']:
                # Validate required fields
                required_fields = ['title', 'severity', 'confidence', 'description']
                if not all(field in finding for field in required_fields):
                    self.logger.warning(f"Missing required fields in finding: {finding}")
                    continue

                try:
                    # Validate numeric fields
                    confidence = float(finding.get('confidence', 0.0))
                    if not 0 <= confidence <= 1:
                        raise ValueError("Confidence must be between 0 and 1")

                    # Validate severity enum
                    severity_str = finding.get('severity', 'info').lower()
                    if severity_str not in [s.value for s in Severity]:
                        raise ValueError(f"Invalid severity value: {severity_str}")

                    findings.append(VulnerabilityReport(
                        title=str(finding.get('title', '')),
                        severity=Severity(severity_str),
                        confidence=confidence,
                        description=str(finding.get('description', '')),
                        code_location=str(finding.get('location', '')),
                        potential_impact=str(finding.get('impact', '')),
                        reproduction_steps=str(finding.get('steps', '')),
                        recommendations=list(finding.get('recommendations', [])),
                        references=list(finding.get('references', [])),
                        vulnerability_type=str(finding.get('type', '')),
                        impact_areas=list(finding.get('impact_areas', [])),
                        timestamp=str(finding.get('timestamp', datetime.now().isoformat()))
                    ))
                except (ValueError, TypeError) as e:
                    self.logger.error(f"Failed to parse finding: {e}")
                    continue

        except Exception as e:
            self.logger.error(f"Failed to parse LLM response: {e}")
            raise ValidationError(f"Invalid response format: {e}")

        return findings

    async def analyze_endpoint(self, endpoint_config: Dict[str, Any]) -> Tuple[List[VulnerabilityReport], List[VulnerabilityReport]]:
        """Analyze endpoint and categorize findings by scope"""
        self.logger.info(f"Starting analysis for endpoint: {endpoint_config.get('url', 'unknown')}")

        # Validate endpoint configuration
        required_fields = ['url', 'path']
        if not all(field in endpoint_config for field in required_fields):
            raise ValidationError(f"Missing required endpoint configuration fields: {required_fields}")

        try:
            all_findings = await self._perform_analysis(endpoint_config)
        except LLMAnalysisError as e:
            self.logger.error(f"Analysis failed: {e}")
            return [], []

        in_scope_findings: List[VulnerabilityReport] = []
        out_of_scope_findings: List[VulnerabilityReport] = []

        for finding in all_findings:
            try:
                # Validate finding before scope check
                if not finding.title or not finding.description:
                    self.logger.warning("Skipping finding with missing required fields")
                    continue

                status = self.scope_manager.check_scope({
                    'target': str(endpoint_config['url']),
                    'path': str(endpoint_config['path']),
                    'type': finding.vulnerability_type,
                    'impact': finding.impact_areas
                })

                if status == ScopeStatus.IN_SCOPE:
                    in_scope_findings.append(finding)
                else:
                    out_of_scope_findings.append(finding)

            except Exception as e:
                self.logger.error(f"Failed to process finding: {e}")
                continue

        self.logger.info(
            f"Analysis complete. Found {len(in_scope_findings)} in-scope and "
            f"{len(out_of_scope_findings)} out-of-scope findings"
        )

        return in_scope_findings, out_of_scope_findings

    async def _perform_analysis(self, endpoint_config: Dict[str, Any]) -> List[VulnerabilityReport]:
        """Perform the actual analysis using LLM API with retries and error handling"""
        max_retries = self.config.get('max_retries', 3)
        retry_delay = self.config.get('retry_delay', 1)

        # Check cache first
        cache_key = self._get_cache_key(endpoint_config)
        cached_response = self._check_cache(cache_key)
        if cached_response is not None:
            return cached_response

        for attempt in range(max_retries):
            try:
                prompt = self.prepare_analysis_prompt(
                    endpoint_config.get('code', ''),
                    endpoint_config.get('context', {})
                )

                headers = {
                    'Authorization': f"Bearer {self.config['api_key']}",
                    'Content-Type': 'application/json',
                    'X-Request-ID': f"analysis-{datetime.now().isoformat()}"
                }

                async with asyncio.timeout(self.config.get('timeout', 30)):
                    response = await self._make_api_request(
                        self.config['llm_api_endpoint'],
                        {
                            'prompt': prompt,
                            'max_tokens': self.config.get('max_tokens', 1000),
                            'temperature': self.config.get('temperature', 0.7)
                        },
                        headers
                    )

                    result = await response.json()
                    if 'findings' not in result:
                        raise InvalidResponseError("Invalid response format from API")

                    findings = self._parse_llm_response(result)

                    # Cache successful response
                    self._response_cache[cache_key] = CacheEntry(
                        response=findings,
                        timestamp=datetime.now(),
                        hash=cache_key
                    )

                    return findings

            except asyncio.TimeoutError:
                self.logger.warning(f"Request timeout, attempt {attempt + 1}/{max_retries}")
            except RateLimitError:
                self.logger.error("Rate limit exceeded, backing off...")
                await asyncio.sleep(retry_delay * (2 ** attempt) * 2)  # Double the normal backoff
            except AuthenticationError as e:
                self.logger.critical(f"Authentication failed: {e}")
                raise  # Don't retry auth failures
            except Exception as e:
                self.logger.error(f"Analysis failed: {str(e)}")
                if attempt == max_retries - 1:
                    raise LLMAnalysisError(f"Analysis failed after {max_retries} attempts: {str(e)}")

            await asyncio.sleep(retry_delay * (2 ** attempt))  # Exponential backoff

        return []

    def prepare_analysis_prompt(self, code: str, context: Dict[str, Any]) -> str:
        """Prepare sanitized prompt for LLM analysis"""
        # Validate inputs
        if not code.strip():
            raise ValidationError("Empty code provided")
        if not context:
            raise ValidationError("Empty context provided")

        # Sanitize inputs
        sanitized_code = self._sanitize_input(code)
        sanitized_context = self._sanitize_context(context)

        return f"""Analyze the following code for security vulnerabilities:
Code Context:
{sanitized_context}

Code:
{sanitized_code}

Focus on:
1. Security vulnerabilities
2. Input validation
3. Authentication/Authorization
4. Data handling
5. Error handling"""

async def make_request(session: AsyncSession, url: str, data: Dict[str, Any]) -> Dict[str, Any]:
    """Make async request with proper error handling"""
    async with session as client:
        response = await client.post(url, json=data, headers={"Content-Type": "application/json"})
        if response.status != 200:
            raise RuntimeError(f"Request failed with status {response.status}")
        return await response.json()

def validate_response(response: Dict[str, Any]) -> bool:
    """Validate response structure"""
    required_fields = {"status", "data", "metadata"}
    return required_fields.issubset(response.keys())

def process_response(response: Dict[str, Any]) -> Dict[str, Any]:
    """Process and transform response data"""
    if not validate_response(response):
        raise ValueError("Invalid response format")

    # Process response data
    result = {
        "status": response["status"],
        "data": response["data"],
        "processed_at": response["metadata"].get("timestamp")
    }
    return result
