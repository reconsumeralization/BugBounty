from dataclasses import dataclass
from typing import List, Dict, Any, Tuple
from pathlib import Path
import json
from datetime import datetime
from .scope_manager import ScopeManager, ScopeStatus
import aiohttp
from typing import Protocol, TypedDict

# Type definitions
class LLMResponse(TypedDict):
    findings: List[Dict[str, Any]]
    status: str
    confidence: float

class AsyncResponse(Protocol):
    async def json(self) -> Dict[str, Any]: ...

class AsyncSession(Protocol):
    async def post(self, url: str, json: Dict[str, Any]) -> AsyncResponse: ...
    async def __aenter__(self) -> 'AsyncSession': ...
    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None: ...

@dataclass
class CodeAnalysisRequest:
    code_snippet: str
    context: str
    focus_areas: List[str]
    vulnerability_types: List[str]
    confidence_threshold: float = 0.8

@dataclass
class VulnerabilityReport:
    title: str
    severity: str
    confidence: float
    description: str
    code_location: str
    potential_impact: str
    reproduction_steps: str
    recommendations: List[str]
    references: List[str]
    vulnerability_type: str
    impact_areas: List[str]

class LLMAnalyzer:
    """Helper class for LLM-based code analysis"""

    def __init__(self, config_path: Path, scope_path: Path):
        self.config = self._load_config(config_path)
        self.scope_manager = ScopeManager(scope_path)
        self.findings: Dict[ScopeStatus, List[VulnerabilityReport]] = {
            ScopeStatus.IN_SCOPE: [],
            ScopeStatus.OUT_OF_SCOPE: [],
            ScopeStatus.REQUIRES_CLARIFICATION: []
        }

    def _load_config(self, path: Path) -> Dict[str, Any]:
        """Load configuration from JSON file"""
        with open(path) as f:
            return json.load(f)

    async def _perform_analysis(self, endpoint_config: Dict[str, Any]) -> List[VulnerabilityReport]:
        """Perform the actual analysis using LLM API"""
        async with aiohttp.ClientSession() as session:
            prompt = self.prepare_analysis_prompt(
                endpoint_config.get('code', ''),
                endpoint_config.get('context', {})
            )

            async with session.post(
                self.config['llm_api_endpoint'],
                json={
                    'prompt': prompt,
                    'max_tokens': self.config.get('max_tokens', 1000),
                    'temperature': self.config.get('temperature', 0.7)
                }
            ) as response:
                result = await response.json()
                return self._parse_llm_response(LLMResponse(result))

    def _parse_llm_response(self, response: LLMResponse) -> List[VulnerabilityReport]:
        """Parse LLM API response into VulnerabilityReport objects"""
        findings: List[VulnerabilityReport] = []

        for finding in response['findings']:
            if isinstance(finding, dict):
                findings.append(VulnerabilityReport(
                    title=str(finding.get('title', '')),
                    severity=str(finding.get('severity', 'unknown')),
                    confidence=float(finding.get('confidence', 0.0)),
                    description=str(finding.get('description', '')),
                    code_location=str(finding.get('location', '')),
                    potential_impact=str(finding.get('impact', '')),
                    reproduction_steps=str(finding.get('steps', '')),
                    recommendations=list(finding.get('recommendations', [])),
                    references=list(finding.get('references', [])),
                    vulnerability_type=str(finding.get('type', '')),
                    impact_areas=list(finding.get('impact_areas', []))
                ))

        return findings

    async def analyze_endpoint(self, endpoint_config: Dict[str, Any]) -> Tuple[List[VulnerabilityReport], List[VulnerabilityReport]]:
        """Analyze endpoint and separate findings by scope"""
        all_findings = await self._perform_analysis(endpoint_config)

        in_scope_findings: List[VulnerabilityReport] = []
        out_of_scope_findings: List[VulnerabilityReport] = []

        for finding in all_findings:
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

        return in_scope_findings, out_of_scope_findings
