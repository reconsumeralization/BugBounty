from dataclasses import dataclass
from typing import Dict, Any, Set
from enum import Enum
from pathlib import Path
import yaml

class ScopeStatus(Enum):
    IN_SCOPE = "in_scope"
    OUT_OF_SCOPE = "out_of_scope"
    REQUIRES_CLARIFICATION = "needs_clarification"

@dataclass
class ScopeDefinition:
    domains: Set[str]
    endpoints: Set[str]
    vulnerability_types: Set[str]
    excluded_paths: Set[str]
    excluded_vulnerabilities: Set[str]
    special_conditions: Dict[str, str]

class ScopeManager:
    def __init__(self, scope_config_path: Path):
        self.config = self._load_scope_config(scope_config_path)
        self.scope_definition = self._parse_scope_definition()

    def _load_scope_config(self, path: Path) -> Dict[str, Any]:
        with open(path) as f:
            return yaml.safe_load(f)

    def _flatten_endpoints(self, assets: Dict[str, Any]) -> Set[str]:
        """Flatten nested asset endpoints into a set"""
        endpoints: Set[str] = set()
        for asset in assets.values():
            if 'endpoints' in asset:
                endpoints.update(set(str(ep) for ep in asset['endpoints']))
        return endpoints

    def _parse_scope_definition(self) -> ScopeDefinition:
        """Parse scope configuration into structured definition"""
        config = self.config
        return ScopeDefinition(
            domains=set(config['domains']['primary'] + config['domains'].get('secondary', [])),
            endpoints=self._flatten_endpoints(config['assets']),
            vulnerability_types=set(config['vulnerability_types']['qualifying']),
            excluded_paths=set(config['excluded']['paths']),
            excluded_vulnerabilities=set(config['excluded']['vulnerabilities']),
            special_conditions=config.get('special_conditions', {})
        )

    def check_scope(self, finding: Dict[str, Any]) -> ScopeStatus:
        """Check if a finding is in scope"""
        # Check domain
        if not self._is_domain_in_scope(finding['target']):
            return ScopeStatus.OUT_OF_SCOPE

        # Check vulnerability type
        if finding['type'] in self.scope_definition.excluded_vulnerabilities:
            return ScopeStatus.OUT_OF_SCOPE

        # Check path
        if self._is_path_excluded(finding['path']):
            return ScopeStatus.OUT_OF_SCOPE

        # Check special conditions
        if not self._meets_special_conditions(finding):
            return ScopeStatus.OUT_OF_SCOPE

        return ScopeStatus.IN_SCOPE

    def _is_domain_in_scope(self, domain: str) -> bool:
        """Check if a domain is in scope"""
        return domain in self.scope_definition.domains

    def _is_path_excluded(self, path: str) -> bool:
        """Check if a path matches any excluded patterns"""
        return path in self.scope_definition.excluded_paths

    def _meets_special_conditions(self, finding: Dict[str, Any]) -> bool:
        """Check if finding meets any special scope conditions"""
        for condition_name, condition_value in self.scope_definition.special_conditions.items():
            if condition_name in finding and finding[condition_name] != condition_value:
                return False
        return True
