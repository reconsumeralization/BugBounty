from dataclasses import dataclass
from typing import List, Dict, Any, Optional, Set
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

    def _parse_scope_definition(self) -> ScopeDefinition:
        """Parse scope configuration into structured definition"""
        config = self.config
        return ScopeDefinition(
            domains=set(config['domains']['primary'] + config['domains'].get('secondary', [])),
            endpoints=set(self._flatten_endpoints(config['assets'])),
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
        """Check if domain is in scope"""
        return any(
            domain.endswith(scope_domain)
            for scope_domain in self.scope_definition.domains
        )

    def _is_path_excluded(self, path: str) -> bool:
        """Check if path is explicitly excluded"""
        return any(
            excluded in path
            for excluded in self.scope_definition.excluded_paths
        )

    def _meets_special_conditions(self, finding: Dict[str, Any]) -> bool:
        """Check if finding meets special conditions"""
        conditions = self.scope_definition.special_conditions

        # Check critical BAC condition
        if finding['type'] == 'broken_access_control':
            return self._is_critical_bac(finding)

        # Check rate limiting condition
        if finding['type'] == 'rate_limiting':
            return self._has_business_impact(finding)

        return True

    def _is_critical_bac(self, finding: Dict[str, Any]) -> bool:
        """Check if BAC finding meets critical criteria"""
        return (
            'information_leak' in finding.get('impact', []) or
            'personal_data' in finding.get('impact', []) or
            'business_critical' in finding.get('impact', [])
        )
