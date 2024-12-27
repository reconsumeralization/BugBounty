"""Azure-specific security analyzer for Microsoft bug bounty program."""

from __future__ import annotations

from typing import List, Dict, Any, Optional, Set, TypedDict, cast
from dataclasses import dataclass
from enum import Enum
import logging
import json
from pathlib import Path

from tools.analysis.o1_analyzer import O1Analyzer, SecurityContext, SecurityAnalysisRequest
from tools.analysis.web_analyzer import WebVulnerabilityAnalyzer, WebEndpoint
from tools.llm.tool_manager import ToolExecutor, ToolResult

class AzureServiceType(Enum):
    """Types of Azure services."""
    APP_SERVICE = "app_service"
    FUNCTIONS = "functions"
    STORAGE = "storage"
    SQL = "sql"
    COSMOS = "cosmos"
    CONTAINER = "container"
    IDENTITY = "identity"

class AzureFinding(TypedDict):
    """Azure-specific finding format."""
    id: str
    vulnerability_type: str
    severity: str
    confidence: float
    azure_context: Dict[str, str]
    compliance_impact: Optional[Dict[str, List[str]]]
    azure_severity: str
    remediation: List[str]

class AzureAnalysisResult(TypedDict):
    """Azure analysis result format."""
    findings: List[AzureFinding]
    summary: Dict[str, Any]

@dataclass
class AzureContext:
    """Azure-specific security context."""
    service_type: AzureServiceType
    region: str
    subscription_id: str
    resource_group: str
    instance_name: str
    access_tier: str
    network_rules: Dict[str, Any]
    security_controls: Dict[str, Any]
    compliance_requirements: Set[str]

class AzureAnalyzer(ToolExecutor):
    """Analyzer for Azure-specific security issues."""

    def __init__(
        self,
        config_path: Optional[Path] = None,
        o1_analyzer: Optional[O1Analyzer] = None,
        web_analyzer: Optional[WebVulnerabilityAnalyzer] = None
    ):
        self.config = self._load_config(config_path) if config_path else {}
        self.o1_analyzer = o1_analyzer or O1Analyzer()
        self.web_analyzer = web_analyzer or WebVulnerabilityAnalyzer()
        self.logger = logging.getLogger(__name__)

    def _load_config(self, path: Path) -> Dict[str, Any]:
        """Load Azure-specific configuration."""
        with open(path) as f:
            return json.load(f)

    async def analyze_app_service(
        self,
        endpoint: WebEndpoint,
        context: AzureContext
    ) -> ToolResult:
        """Analyze Azure App Service for vulnerabilities."""
        security_context = SecurityContext(
            service="azure_app_service",
            endpoint=endpoint.url,
            method=endpoint.method,
            parameters={
                "subscription": context.subscription_id,
                "resource_group": context.resource_group,
                "instance": context.instance_name,
                **endpoint.parameters
            }
        )

        request = SecurityAnalysisRequest(
            code=self._get_app_service_config(context),
            context=security_context,
            focus_areas=[
                "authentication",
                "authorization",
                "network_security",
                "configuration",
                "deployment"
            ],
            vulnerability_types=[
                "rce",
                "privilege_escalation",
                "information_disclosure",
                "ssrf"
            ]
        )

        try:
            result = await self.o1_analyzer.analyze(request)
            analysis_result = self._process_findings(result["findings"], context)
            return ToolResult(
                success=True,
                data=cast(Dict[str, Any], analysis_result)
            )
        except Exception as e:
            self.logger.error(f"Azure App Service analysis failed: {e}")
            return ToolResult(
                success=False,
                error=f"Analysis failed: {str(e)}"
            )

    async def analyze_storage(
        self,
        endpoint: WebEndpoint,
        context: AzureContext
    ) -> ToolResult:
        """Analyze Azure Storage for vulnerabilities."""
        security_context = SecurityContext(
            service="azure_storage",
            endpoint=endpoint.url,
            method=endpoint.method,
            parameters={
                "subscription": context.subscription_id,
                "resource_group": context.resource_group,
                "instance": context.instance_name,
                "access_tier": context.access_tier,
                **endpoint.parameters
            }
        )

        request = SecurityAnalysisRequest(
            code=self._get_storage_config(context),
            context=security_context,
            focus_areas=[
                "access_control",
                "encryption",
                "network_security",
                "logging",
                "data_protection"
            ],
            vulnerability_types=[
                "data_exposure",
                "misconfiguration",
                "access_control",
                "encryption_bypass"
            ]
        )

        try:
            result = await self.o1_analyzer.analyze(request)
            analysis_result = self._process_findings(result["findings"], context)
            return ToolResult(
                success=True,
                data=cast(Dict[str, Any], analysis_result)
            )
        except Exception as e:
            self.logger.error(f"Azure Storage analysis failed: {e}")
            return ToolResult(
                success=False,
                error=f"Analysis failed: {str(e)}"
            )

    def _get_app_service_config(self, context: AzureContext) -> str:
        """Get App Service configuration for analysis."""
        return f"""
        App Service Configuration:
        - Region: {context.region}
        - Resource Group: {context.resource_group}
        - Instance: {context.instance_name}

        Network Rules:
        {json.dumps(context.network_rules, indent=2)}

        Security Controls:
        {json.dumps(context.security_controls, indent=2)}

        Compliance Requirements:
        {json.dumps(list(context.compliance_requirements), indent=2)}
        """

    def _get_storage_config(self, context: AzureContext) -> str:
        """Get Storage configuration for analysis."""
        return f"""
        Storage Configuration:
        - Region: {context.region}
        - Resource Group: {context.resource_group}
        - Instance: {context.instance_name}
        - Access Tier: {context.access_tier}

        Network Rules:
        {json.dumps(context.network_rules, indent=2)}

        Security Controls:
        {json.dumps(context.security_controls, indent=2)}

        Compliance Requirements:
        {json.dumps(list(context.compliance_requirements), indent=2)}
        """

    def _process_findings(
        self,
        findings: List[Dict[str, Any]],
        context: AzureContext
    ) -> AzureAnalysisResult:
        """Process and enrich findings with Azure context."""
        processed_findings: List[AzureFinding] = []

        for finding in findings:
            azure_finding = cast(AzureFinding, {
                "id": finding["id"],
                "vulnerability_type": finding["vulnerability_type"],
                "severity": finding["severity"],
                "confidence": finding["confidence"],
                "azure_context": {
                    "service_type": context.service_type.value,
                    "region": context.region,
                    "subscription_id": context.subscription_id,
                    "resource_group": context.resource_group,
                    "instance_name": context.instance_name
                },
                "compliance_impact": None,
                "azure_severity": "medium",
                "remediation": []
            })

            # Add compliance impact if applicable
            if context.compliance_requirements:
                azure_finding["compliance_impact"] = self._assess_compliance_impact(
                    finding,
                    context.compliance_requirements
                )

            # Calculate Azure-specific severity
            azure_finding["azure_severity"] = self._calculate_azure_severity(
                finding,
                context
            )

            # Add remediation steps
            azure_finding["remediation"] = self._get_azure_remediation(
                finding,
                context
            )

            processed_findings.append(azure_finding)

        return {
            "findings": processed_findings,
            "summary": self._generate_summary(processed_findings, context)
        }

    def _assess_compliance_impact(
        self,
        finding: Dict[str, Any],
        compliance_requirements: Set[str]
    ) -> Dict[str, List[str]]:
        """Assess impact on compliance requirements."""
        impacts: Dict[str, List[str]] = {}

        for req in compliance_requirements:
            if req == "PCI-DSS" and finding["vulnerability_type"] in [
                "data_exposure",
                "encryption_bypass",
                "access_control"
            ]:
                impacts[req] = [
                    "May affect PCI-DSS compliance",
                    "Requires immediate remediation",
                    "Must be reported to QSA"
                ]
            elif req == "HIPAA" and finding["vulnerability_type"] in [
                "data_exposure",
                "encryption_bypass"
            ]:
                impacts[req] = [
                    "Potential HIPAA violation",
                    "May require breach notification",
                    "Must be reported to privacy officer"
                ]

        return impacts

    def _calculate_azure_severity(
        self,
        finding: Dict[str, Any],
        context: AzureContext
    ) -> str:
        """Calculate Azure-specific severity based on context."""
        base_severity = finding.get("severity", "medium").lower()

        # Increase severity for production resources
        if "production" in context.resource_group.lower():
            if base_severity == "medium":
                base_severity = "high"
            elif base_severity == "high":
                base_severity = "critical"

        # Increase severity for compliance-related issues
        if context.compliance_requirements and finding.get("compliance_impact"):
            if base_severity == "medium":
                base_severity = "high"

        return base_severity

    def _get_azure_remediation(
        self,
        finding: Dict[str, Any],
        context: AzureContext
    ) -> List[str]:
        """Get Azure-specific remediation steps."""
        remediation_steps: List[str] = []

        if context.service_type == AzureServiceType.APP_SERVICE:
            remediation_steps.extend([
                "Review App Service authentication settings",
                "Enable Azure AD integration if applicable",
                "Configure proper IP restrictions",
                "Enable HTTPS-only mode"
            ])
        elif context.service_type == AzureServiceType.STORAGE:
            remediation_steps.extend([
                "Enable Azure Storage encryption",
                "Configure proper network access rules",
                "Enable soft delete and versioning",
                "Configure proper CORS rules"
            ])

        return remediation_steps

    def _generate_summary(
        self,
        findings: List[AzureFinding],
        context: AzureContext
    ) -> Dict[str, Any]:
        """Generate summary of findings."""
        severity_counts = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0
        }

        for finding in findings:
            severity = finding["azure_severity"].lower()
            severity_counts[severity] += 1

        return {
            "total_findings": len(findings),
            "severity_distribution": severity_counts,
            "affected_service": context.service_type.value,
            "region": context.region,
            "resource_group": context.resource_group,
            "compliance_requirements": list(context.compliance_requirements)
        }
