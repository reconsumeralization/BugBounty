from typing import List, Dict, Any, Optional, TypedDict, Sequence
from dataclasses import dataclass
import os
import logging
from .o1_analyzer import O1Analyzer, SecurityAnalysisRequest, AnalysisResult

@dataclass
class WebEndpoint:
    url: str
    method: str
    parameters: Dict[str, Any]
    authentication: Optional[Dict[str, Any]] = None
    rate_limits: Optional[Dict[str, Any]] = None

@dataclass
class WebVulnerabilityContext:
    framework: str
    endpoint: WebEndpoint
    dependencies: List[Dict[str, str]]
    security_headers: Dict[str, str]
    authentication_type: str
    input_validation: Dict[str, Any]

class SecurityFinding(TypedDict):
    title: str
    description: str
    severity: str
    fix: str
    reasoning: str
    prerequisites: List[str]
    affected_components: List[str]

class SecurityRecommendation(TypedDict):
    title: str
    description: str
    fix: str
    reasoning: str
    prerequisites: List[str]
    affected_components: List[str]

class WebVulnerabilityAnalyzer:
    """Specialized analyzer for web vulnerabilities using O1's reasoning"""

    def __init__(self):
        self.analyzer = O1Analyzer()
        self.logger = logging.getLogger(__name__)
        self.min_code_size = int(os.getenv("MIN_CODE_SIZE", 10))
        self.max_code_size = int(os.getenv("MAX_CODE_SIZE", 10000))

    def _prepare_web_context(self, context: WebVulnerabilityContext) -> Dict[str, Any]:
        """Prepare specialized web context for analysis"""
        return {
            "framework": context.framework,
            "endpoint": {
                "url": context.endpoint.url,
                "method": context.endpoint.method,
                "parameters": context.endpoint.parameters,
                "authentication": context.endpoint.authentication,
                "rate_limits": context.endpoint.rate_limits
            },
            "dependencies": context.dependencies,
            "security_headers": context.security_headers,
            "authentication_type": context.authentication_type,
            "input_validation": context.input_validation
        }

    def _get_web_vulnerability_types(self) -> List[str]:
        """Get web-specific vulnerability types"""
        return [
            "xss",
            "sql_injection",
            "csrf",
            "ssrf",
            "authentication_bypass",
            "authorization_bypass",
            "rate_limiting_bypass",
            "information_disclosure",
            "business_logic",
            "api_security"
        ]

    def _get_web_focus_areas(self) -> List[str]:
        """Get web-specific focus areas"""
        return [
            "input_validation",
            "output_encoding",
            "authentication",
            "authorization",
            "session_management",
            "api_security",
            "rate_limiting",
            "error_handling",
            "logging_monitoring",
            "business_logic"
        ]

    async def analyze_endpoint(
        self,
        code: str,
        context: WebVulnerabilityContext
    ) -> AnalysisResult:
        """Analyze web endpoint for vulnerabilities"""
        # Validate input
        code_lines = code.strip().split("\n")
        if not (self.min_code_size <= len(code_lines) <= self.max_code_size):
            raise ValueError(
                f"Code size must be between {self.min_code_size} "
                f"and {self.max_code_size} lines"
            )

        request = SecurityAnalysisRequest(
            code=code,
            context=self._prepare_web_context(context),
            vulnerability_types=self._get_web_vulnerability_types(),
            focus_areas=self._get_web_focus_areas()
        )

        return await self.analyzer.analyze(request)

    async def analyze_api_endpoints(
        self,
        endpoints: List[tuple[str, WebVulnerabilityContext]]
    ) -> Sequence[AnalysisResult]:
        """Analyze multiple API endpoints"""
        requests = [
            SecurityAnalysisRequest(
                code=code,
                context=self._prepare_web_context(context),
                vulnerability_types=self._get_web_vulnerability_types(),
                focus_areas=self._get_web_focus_areas()
            )
            for code, context in endpoints
        ]

        batch_size = int(os.getenv("ANALYSIS_BATCH_SIZE", 5))
        results: List[AnalysisResult] = []

        # Process in batches
        for i in range(0, len(requests), batch_size):
            batch = requests[i:i + batch_size]
            batch_results = await self.analyzer.analyze_batch(batch)
            results.extend(batch_results)

        return results

    def get_security_recommendations(self, results: List[AnalysisResult]) -> Dict[str, List[SecurityRecommendation]]:
        """Generate security recommendations based on analysis results"""
        recommendations: Dict[str, List[SecurityRecommendation]] = {
            "high_priority": [],
            "medium_priority": [],
            "low_priority": [],
            "best_practices": []
        }

        for result in results:
            for finding in result["findings"]:
                rec: SecurityRecommendation = {
                    "title": finding["title"],
                    "description": finding["description"],
                    "fix": finding["fix"],
                    "reasoning": finding["reasoning"],
                    "prerequisites": finding["prerequisites"],
                    "affected_components": finding["affected_components"]
                }

                if finding["severity"] == "critical":
                    recommendations["high_priority"].append(rec)
                elif finding["severity"] == "high":
                    recommendations["high_priority"].append(rec)
                elif finding["severity"] == "medium":
                    recommendations["medium_priority"].append(rec)
                else:
                    recommendations["low_priority"].append(rec)

        return recommendations
