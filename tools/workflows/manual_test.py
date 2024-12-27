from pathlib import Path
from typing import Dict, Any, List
from ..analysis.llm_helper import LLMAnalyzer, VulnerabilityReport
import yaml
import json

class ManualTestWorkflow:
    def __init__(self, target_config: Path, llm_config: Path):
        self.target_config = self._load_config(target_config)
        self.llm_analyzer = LLMAnalyzer(llm_config)
        self.findings: List[VulnerabilityReport] = []

    async def analyze_endpoint(self, endpoint: str, method: str) -> None:
        """Analyze a specific endpoint with LLM assistance"""
        # Load endpoint configuration
        endpoint_config = self._get_endpoint_config(endpoint, method)

        # Prepare context for analysis
        context = self._prepare_context(endpoint_config)

        # Get LLM analysis
        vulnerabilities = self.llm_analyzer.analyze_endpoint(endpoint_config)

        # Record findings
        self.findings.extend(vulnerabilities)

        # Generate testing guide based on findings
        self._generate_test_guide(endpoint, vulnerabilities)

    def _generate_test_guide(self, endpoint: str, vulnerabilities: List[VulnerabilityReport]) -> None:
        """Generate a manual testing guide based on LLM analysis"""
        guide_path = Path("guides") / f"{endpoint.replace('/', '_')}_test_guide.md"

        with open(guide_path, 'w') as f:
            f.write(f"# Manual Testing Guide: {endpoint}\n\n")

            for vuln in vulnerabilities:
                f.write(f"## Testing for: {vuln.title}\n")
                f.write(f"Severity: {vuln.severity}\n")
                f.write(f"Confidence: {vuln.confidence}\n\n")
                f.write("### Test Steps\n")
                f.write(f"{vuln.reproduction_steps}\n\n")
                f.write("### Expected Results\n")
                f.write(f"{vuln.potential_impact}\n\n")
                f.write("### Notes\n")
                f.write(f"{vuln.description}\n\n")
                f.write("---\n\n")
