#!/usr/bin/env python3

from typing import Dict, List, Optional, Any, Type, TypeVar, Protocol
from dataclasses import dataclass, field
import yaml
import logging
import json
from datetime import datetime
from pathlib import Path
from types import TracebackType
import asyncio
from rich.console import Console
from rich.progress import Progress
from asyncio import Semaphore
from urllib.parse import urlparse

T = TypeVar('T')

# Type aliases for improved type safety
ConfigDict = Dict[str, Any]
ScannerConfig = Dict[str, Any]

class SupportsIndex(Protocol):
    def __index__(self) -> int: ...

console = Console()

@dataclass
class ScanResult:
    scan_type: str
    target: str
    findings: List[Dict[str, Any]]
    timestamp: str
    risk_score: float = 0.0
    recommendations: List[str] = field(default_factory=list)

    def validate(self) -> bool:
        """Validate scan result data"""
        if not self.findings:
            return False
        if not isinstance(self.risk_score, float) or self.risk_score < 0 or self.risk_score > 10:
            return False
        return True

class VulnerabilityFinding:
    def __init__(
        self,
        title: str,
        severity: str,
        description: str,
        proof: str,
        impact: str,
        remediation: str
    ) -> None:
        self.title = title
        self.severity = severity.lower()
        self.description = description
        self.proof = proof
        self.impact = impact
        self.remediation = remediation
        self.timestamp = datetime.now().isoformat()
        self.risk_score = self.calculate_risk_score()

    def calculate_risk_score(self) -> float:
        """Calculate risk score based on severity and impact"""
        severity_weights = {
            'critical': 1.0,
            'high': 0.8,
            'medium': 0.5,
            'low': 0.2
        }

        base_score = severity_weights.get(self.severity, 0.0)
        impact_modifier = 1.0 if self.impact else 0.8

        return base_score * impact_modifier * 10

    def to_dict(self) -> Dict[str, Any]:
        return {
            "title": self.title,
            "severity": self.severity,
            "description": self.description,
            "proof": self.proof,
            "impact": self.impact,
            "remediation": self.remediation,
            "timestamp": self.timestamp,
            "risk_score": self.risk_score
        }

class ReconScanner:
    """Base class for all reconnaissance scanners"""
    def __init__(self, target: str, output_dir: Path, config: Optional[ScannerConfig] = None):
        self.target = target
        self.output_dir = output_dir
        self.findings: List[VulnerabilityFinding] = []
        self.config = config or {}
        self.timeout = self.config.get('timeout', 30)
        self.max_retries = self.config.get('max_retries', 3)

    async def __aenter__(self) -> 'ReconScanner':
        return self

    async def __aexit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc_val: Optional[BaseException],
        exc_tb: Optional[TracebackType]
    ) -> None:
        await self.cleanup()

    async def cleanup(self) -> None:
        """Clean up scanner resources"""
        pass

    async def scan(self) -> List[VulnerabilityFinding]:
        """Execute scan with error handling and retries"""
        for attempt in range(self.max_retries):
            try:
                results: Optional[List[VulnerabilityFinding]] = await self._perform_scan()
                if results:
                    return results
            except asyncio.TimeoutError:
                logging.warning(f"Scan timeout on attempt {attempt + 1}/{self.max_retries}")
                if attempt == self.max_retries - 1:
                    logging.error("Max retries exceeded")
                    return []
                await asyncio.sleep(2 ** attempt)  # Exponential backoff
            except Exception as e:
                logging.error(f"{self.__class__.__name__} scan failed: {str(e)}")
                return []
        return []

    async def _perform_scan(self) -> List[VulnerabilityFinding]:
        raise NotImplementedError("_perform_scan method must be implemented by subclass")

    def save_results(self) -> None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = self.output_dir / f"scan_{timestamp}.json"

        with open(output_file, 'w') as f:
            json.dump(
                [finding.to_dict() for finding in self.findings],
                f,
                indent=2
            )

class SubdomainScanner(ReconScanner):
    async def _perform_scan(self) -> List[VulnerabilityFinding]:
        # Implement subdomain scanning logic
        return []

class PortScanner(ReconScanner):
    async def _perform_scan(self) -> List[VulnerabilityFinding]:
        # Implement port scanning logic
        return []

class ContentScanner(ReconScanner):
    async def _perform_scan(self) -> List[VulnerabilityFinding]:
        # Implement content discovery logic
        return []

class VulnerabilityScanner(ReconScanner):
    async def _perform_scan(self) -> List[VulnerabilityFinding]:
        # Implement vulnerability scanning logic
        return []

class ReconAutomation:
    def __init__(self, config_path: Optional[Path] = None) -> None:
        self.config_dir = Path("config")
        self.output_dir = Path("scans")
        self.config_path = config_path or self.config_dir / "config.yaml"
        self.scanners: List[ReconScanner] = []
        self.findings: List[VulnerabilityFinding] = []
        self.semaphore = Semaphore(5)  # Limit concurrent scans
        self.config: ConfigDict = {}

        self.setup_logging()
        self.load_config()
        self.setup_directories()

    def setup_logging(self) -> None:
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('recon.log'),
                logging.StreamHandler()
            ]
        )

    def load_config(self) -> None:
        try:
            with open(self.config_path) as f:
                loaded_config = yaml.safe_load(f)
                self.config = loaded_config or {}
        except Exception as e:
            logging.error(f"Failed to load config: {e}")
            self.config = {}

    def setup_directories(self) -> None:
        """Create necessary directories if they don't exist"""
        directories = [
            self.output_dir / "subdomain",
            self.output_dir / "ports",
            self.output_dir / "content",
            self.output_dir / "vulnerabilities"
        ]

        for directory in directories:
            directory.mkdir(parents=True, exist_ok=True)

    def validate_target(self, target: str) -> bool:
        """Validate target URL format"""
        try:
            result = urlparse(target)
            return all([result.scheme, result.netloc])
        except Exception:
            return False

    async def run_scan(self, target: str) -> None:
        """Run all reconnaissance scans for a target"""
        if not self.validate_target(target):
            logging.error(f"Invalid target format: {target}")
            return

        scanners = [
            SubdomainScanner(target, self.output_dir / "subdomain", self.config),
            PortScanner(target, self.output_dir / "ports", self.config),
            ContentScanner(target, self.output_dir / "content", self.config),
            VulnerabilityScanner(target, self.output_dir / "vulnerabilities", self.config)
        ]

        async with self.semaphore:
            with Progress() as progress:
                task_id = progress.add_task("[cyan]Running scans...", total=len(scanners))

                for scanner in scanners:
                    try:
                        findings = await scanner.scan()
                        self.findings.extend(findings)
                        scanner.save_results()
                    except Exception as e:
                        logging.error(f"Scan failed: {e}")
                    finally:
                        progress.advance(task_id)

    async def aggregate_results(self) -> Dict[str, Any]:
        """Aggregate scan results with metrics"""
        results: Dict[str, Any] = {
            'timestamp': datetime.now().isoformat(),
            'total_findings': len(self.findings),
            'severity_counts': {
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0
            },
            'findings_by_type': {}
        }

        for finding in self.findings:
            results['severity_counts'][finding.severity] += 1
            scanner_type = finding.__class__.__name__
            if scanner_type not in results['findings_by_type']:
                results['findings_by_type'][scanner_type] = []
            results['findings_by_type'][scanner_type].append(finding.to_dict())

        return results

    def generate_report(self) -> None:
        """Generate a comprehensive report of all findings"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = Path("reports") / "findings" / f"report_{timestamp}.md"

        with open(report_file, 'w') as f:
            f.write("# Reconnaissance Report\n\n")
            f.write(f"Generated: {datetime.now().isoformat()}\n\n")

            for finding in self.findings:
                f.write(f"## {finding.title}\n")
                f.write(f"Severity: {finding.severity}\n")
                f.write(f"Risk Score: {finding.risk_score:.1f}\n\n")
                f.write(f"### Description\n{finding.description}\n\n")
                f.write(f"### Impact\n{finding.impact}\n\n")
                f.write(f"### Proof\n```\n{finding.proof}\n```\n\n")
                f.write(f"### Remediation\n{finding.remediation}\n\n")
                f.write("---\n\n")

async def main() -> None:
    recon = ReconAutomation()
    targets = recon.config.get('targets', [])

    for target in targets:
        console.print(f"[bold green]Starting scan for {target}[/bold green]")
        await recon.run_scan(target)

    recon.generate_report()
    console.print("[bold green]Scan complete! Report generated.[/bold green]")

if __name__ == "__main__":
    asyncio.run(main())
