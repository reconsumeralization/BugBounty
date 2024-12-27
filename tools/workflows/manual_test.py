from pathlib import Path
from typing import List, Dict, Any, TypedDict, cast
from datetime import datetime
from ..analysis.llm_helper import LLMAnalyzer, VulnerabilityReport
import yaml
from dataclasses import dataclass
import logging
from collections import Counter

class EndpointParameters(TypedDict):
    parameters: Dict[str, Any]
    auth_required: bool
    rate_limits: Dict[str, int]

@dataclass
class EndpointConfig:
    parameters: Dict[str, Any]
    auth_required: bool
    rate_limits: Dict[str, int]

class ManualTestWorkflow:
    def __init__(self, target_config: Path, llm_config: Path, scope_path: Path):
        """Initialize the manual test workflow.

        Args:
            target_config: Path to target configuration file
            llm_config: Path to LLM configuration file
            scope_path: Path to scope configuration file
        """
        self.target_config = self._load_yaml_config(target_config)
        self.llm_analyzer = LLMAnalyzer(llm_config, scope_path)
        self.findings: List[VulnerabilityReport] = []

    def _load_yaml_config(self, config_path: Path) -> Dict[str, Dict[str, Any]]:
        """Load YAML configuration file.

        Args:
            config_path: Path to YAML config file

        Returns:
            Loaded configuration as dictionary

        Raises:
            yaml.YAMLError: If YAML parsing fails
            IOError: If file cannot be read
        """
        try:
            with open(config_path) as f:
                config = yaml.safe_load(f)
                if not isinstance(config, dict):
                    raise ValueError("Config must be a dictionary")
                return cast(Dict[str, Dict[str, Any]], config)
        except yaml.YAMLError as e:
            logging.error(f"Error loading YAML config: {e}")
            raise
        except IOError as e:
            logging.error(f"Error reading config file: {e}")
            raise

    def _get_endpoint_config(self, endpoint: str, method: str) -> EndpointConfig:
        """Get configuration for specific endpoint.

        Args:
            endpoint: API endpoint path
            method: HTTP method

        Returns:
            Endpoint configuration

        Raises:
            ValueError: If rate limits format is invalid
        """
        endpoints = self.target_config.get('endpoints', {})
        config = endpoints.get(f"{method}:{endpoint}", {})

        if not config:
            logging.warning(f"No configuration found for {method}:{endpoint}")

        rate_limits = config.get('rate_limits', {})
        if rate_limits and not isinstance(rate_limits, dict):
            raise ValueError(f"Invalid rate_limits format for {method}:{endpoint}")

        params: EndpointParameters = {
            'parameters': config.get('parameters', {}),
            'auth_required': config.get('auth_required', False),
            'rate_limits': {str(k): int(v) for k, v in cast(Dict[Any, Any], rate_limits).items()}
        }

        return EndpointConfig(**params)

    def _prepare_context(self, endpoint_config: EndpointConfig) -> Dict[str, Any]:
        """Prepare analysis context from endpoint config.

        Args:
            endpoint_config: Endpoint configuration

        Returns:
            Analysis context dictionary
        """
        return {
            'parameters': endpoint_config.parameters,
            'auth_required': endpoint_config.auth_required,
            'rate_limits': endpoint_config.rate_limits,
        }

    async def analyze_endpoint(self, endpoint: str, method: str) -> None:
        """Analyze a specific endpoint with LLM assistance.

        Args:
            endpoint: API endpoint path to analyze
            method: HTTP method to analyze

        Raises:
            Exception: If analysis fails
        """
        try:
            endpoint_config = self._get_endpoint_config(endpoint, method)
            analysis_context = self._prepare_context(endpoint_config)

            vulnerabilities = await self.llm_analyzer.analyze_endpoint(analysis_context)

            if vulnerabilities:
                if isinstance(vulnerabilities, list):
                    for vuln in vulnerabilities:
                        if isinstance(vuln, VulnerabilityReport):
                            self.findings.append(vuln)
                elif isinstance(vulnerabilities, VulnerabilityReport):
                    self.findings.append(vulnerabilities)

            await self._generate_test_guide(endpoint, self.findings)
        except Exception as e:
            logging.error(f"Error analyzing endpoint {method}:{endpoint}: {e}")
            raise

    async def _generate_test_guide(self, endpoint: str, vulnerabilities: List[VulnerabilityReport]) -> None:
        """Generate a manual testing guide based on LLM analysis.

        Args:
            endpoint: API endpoint path
            vulnerabilities: List of vulnerability reports
        """
        guide_path = Path("guides") / f"{endpoint.replace('/', '_')}_test_guide.md"

        # Create guides directory if it doesn't exist
        guide_path.parent.mkdir(exist_ok=True)

        # Add metadata and summary section
        content = [
            f"# Manual Testing Guide: {endpoint}",
            f"Generated: {datetime.now().isoformat()}",
            f"Total Vulnerabilities: {len(vulnerabilities)}",
            "\n## Summary",
            "| Severity | Count |",
            "|----------|--------|",
        ]

        # Add severity summary
        severity_counts = Counter(v.severity for v in vulnerabilities)
        for severity, count in severity_counts.items():
            content.append(f"| {severity} | {count} |")

        # Add individual vulnerability sections
        for vuln in vulnerabilities:
            content.extend([
                f"\n## Testing for: {vuln.title}",
                f"Severity: {vuln.severity}",
                f"Confidence: {vuln.confidence}",
                "\n### Test Steps",
                vuln.reproduction_steps,
                "\n### Expected Results",
                vuln.potential_impact,
                "\n### Notes",
                vuln.description,
                "\n---"
            ])

        guide_path.write_text('\n'.join(content))
