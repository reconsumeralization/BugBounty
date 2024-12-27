"""E-voting security analysis tools."""

from typing import Dict, Any, TypedDict, List, cast, Optional
import json
from openai import AsyncOpenAI

class VotingEndpoint(TypedDict):
    """Voting endpoint specification."""
    url: str
    method: str
    parameters: Dict[str, str]
    authentication: Dict[str, str]
    rate_limits: Dict[str, int]

class EVotingTarget(TypedDict):
    """E-voting target specification."""
    domain: str
    endpoints: List[VotingEndpoint]
    technology_stack: Dict[str, str]
    scope_rules: Dict[str, List[str]]
    known_vulnerabilities: List[Dict[str, Any]]
    reward_range: Dict[str, float]
    excluded_paths: set[str]
    special_conditions: Dict[str, Any]

class Finding(TypedDict):
    """Vulnerability finding."""
    id: str
    vulnerability_type: str
    severity: str
    confidence: float
    entry_points: List[str]
    prerequisites: List[str]
    affected_components: List[str]
    requires_special_conditions: bool

class AnalysisResponse(TypedDict):
    """Analysis response format."""
    findings: List[Finding]

class EVotingAnalyzer:
    """E-voting security analyzer."""

    def __init__(self, client: AsyncOpenAI) -> None:
        """Initialize analyzer."""
        self.client = client
        self.web_analyzer = None  # Will be initialized later

    async def analyze_target(self, target: EVotingTarget) -> Dict[str, List[Finding]]:
        """Analyze e-voting target for vulnerabilities."""
        try:
            response = await self.client.chat.completions.create(
                model="gpt-4",
                messages=[{
                    "role": "system",
                    "content": "You are a security expert analyzing e-voting systems."
                }, {
                    "role": "user",
                    "content": json.dumps(target)
                }]
            )

            content = response.choices[0].message.content
            data = cast(Optional[AnalysisResponse], json.loads(content) if content else None)
            result: Dict[str, List[Finding]] = {
                "critical": [],
                "high": [],
                "medium": [],
                "low": []
            }

            if data and "findings" in data:
                for finding in data["findings"]:
                    severity = finding.get("severity", "").lower()
                    if severity in result:
                        result[severity].append(finding)

            return result

        except Exception as exc:
            print(f"Error analyzing target: {exc}")
            return {
                "critical": [],
                "high": [],
                "medium": [],
                "low": []
            }
