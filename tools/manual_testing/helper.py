import requests
import yaml
from pathlib import Path
from rich.console import Console  # type: ignore
from rich.table import Table  # type: ignore
from typing import Dict, Any

console = Console()  # type: ignore

class ManualTestHelper:
    def __init__(self, service_config: Path):
        """Initialize the manual test helper.

        Args:
            service_config: Path to the service configuration file
        """
        self.config: Dict[str, Any] = self._load_config(service_config)
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Infomaniak-YWH-Bugbounty'
        })

    def _load_config(self, config_path: Path) -> Dict[str, Any]:
        """Load configuration from YAML file.

        Args:
            config_path: Path to the configuration file

        Returns:
            Dict containing the configuration
        """
        with open(config_path) as f:
            return yaml.safe_load(f)

    def _get_test_config(self, test_name: str) -> Dict[str, Any]:
        """Get test configuration by name.

        Args:
            test_name: Name of the test

        Returns:
            Dict containing the test configuration
        """
        test_configs = self.config.get('tests', {})
        return test_configs.get(test_name, {})

    def prepare_test(self, test_name: str) -> None:
        """Setup environment for specific test.

        Args:
            test_name: Name of the test to prepare
        """
        console.print(f"[bold blue]Preparing test: {test_name}[/bold blue]")  # type: ignore
        test_config: Dict[str, Any] = self._get_test_config(test_name)

        table = Table(title=f"Test Plan: {test_name}")  # type: ignore
        table.add_column("Step", style="cyan")  # type: ignore
        table.add_column("Description", style="white")  # type: ignore
        table.add_column("Expected Result", style="green")  # type: ignore

        for idx, step in enumerate(test_config.get('steps', []), 1):
            table.add_row(  # type: ignore
                f"Step {idx}",
                step.get('description', ''),
                step.get('expected', '')
            )

        console.print(table)  # type: ignore

    def log_finding(
        self,
        title: str,
        severity: str,
        description: str,
        reproduction: str,
        impact: str
    ) -> None:
        """Log a potential vulnerability finding.

        Args:
            title: Title of the finding
            severity: Severity level of the finding
            description: Detailed description of the finding
            reproduction: Steps to reproduce the finding
            impact: Impact assessment of the finding
        """
        finding_path = Path("findings") / f"{title.lower().replace(' ', '_')}.md"

        with open(finding_path, 'w') as f:
            f.write(f"# {title}\n\n")
            f.write(f"**Severity:** {severity}\n\n")
            f.write(f"## Description\n{description}\n\n")
            f.write(f"## Reproduction Steps\n{reproduction}\n\n")
            f.write(f"## Impact\n{impact}\n\n")
