from __future__ import annotations

from typing import List, Dict, Any, Optional, Set, TypedDict, cast, Sequence, TypeGuard
from dataclasses import dataclass, field
from enum import Enum
import logging
from pathlib import Path
import json
import asyncio
from datetime import datetime
import hashlib

from .bug_bounty_analyzer import ChainableVulnerability, BugBountyImpact
from .o1_analyzer import O1Analyzer, SecurityContext, SecurityAnalysisRequest

class ChainAnalysisMode(Enum):
    DEEP = "deep"      # Use o1 for thorough analysis
    QUICK = "quick"    # Use o1-mini for faster initial assessment

@dataclass
class ChainContext:
    """Context for vulnerability chain analysis"""
    entry_points: Set[str]
    affected_components: Set[str]
    technology_stack: Dict[str, str]
    security_controls: Dict[str, Any]
    known_bypasses: List[str]
    chain_history: List[str]

    def validate(self) -> bool:
        """Validate chain context data"""
        if not self.entry_points or not self.affected_components:
            return False
        if not self.technology_stack:
            return False
        return True

@dataclass
class AnalysisMetrics:
    """Metrics for chain analysis"""
    start_time: datetime = field(default_factory=datetime.now)
    end_time: Optional[datetime] = None
    total_chains: int = 0
    successful_analyses: int = 0
    failed_analyses: int = 0
    average_analysis_time: float = 0.0
    error_counts: Dict[str, int] = field(default_factory=dict)
    reasoning_tokens_used: int = 0
    completion_tokens_used: int = 0

class ChainAnalysisResult(TypedDict):
    """Result of chain analysis"""
    feasibility: float
    complexity: float
    impact_score: float
    detection_likelihood: float
    reasoning: str
    prerequisites: List[str]
    mitigations: List[str]
    attack_steps: List[str]

class O1ChainAnalyzer:
    """Advanced vulnerability chain analyzer using O1's reasoning capabilities"""

    def __init__(
        self,
        analyzer: Optional[O1Analyzer] = None,
        mode: ChainAnalysisMode = ChainAnalysisMode.DEEP,
        max_concurrent: int = 3,
        cache_size: int = 1000
    ):
        self.analyzer = analyzer or O1Analyzer()
        self.mode = mode
        self.max_concurrent = max_concurrent
        self.logger = logging.getLogger(__name__)
        self.metrics = AnalysisMetrics()
        self.semaphore = asyncio.Semaphore(max_concurrent)
        self._analysis_cache: Dict[str, ChainAnalysisResult] = {}

        # Load chain analysis prompts
        self.prompts = self._load_prompts()

    def _load_prompts(self) -> Dict[str, str]:
        """Load specialized prompts for chain analysis"""
        with open(Path(__file__).parent / "prompts" / "chain_analysis.json") as f:
            return json.load(f)

    def _get_cached_analysis(self, chain_hash: str) -> Optional[ChainAnalysisResult]:
        """Get cached analysis result if available"""
        return self._analysis_cache.get(chain_hash)

    def _compute_chain_hash(self, chain: List[ChainableVulnerability]) -> str:
        """Compute unique hash for vulnerability chain"""
        chain_str = json.dumps([{
            "id": v.id,
            "vulnerability_type": v.vulnerability_type,
            "entry_points": sorted(list(v.entry_points)),
            "prerequisites": sorted(list(v.prerequisites)),
            "impact": v.impact.value,
            "affected_components": sorted(list(v.affected_components)),
            "chain_probability": v.chain_probability
        } for v in chain], sort_keys=True)
        return hashlib.sha256(chain_str.encode()).hexdigest()

    async def analyze_chain(
        self,
        chain: List[ChainableVulnerability],
        context: ChainContext
    ) -> ChainAnalysisResult:
        """Perform deep analysis of vulnerability chain using O1"""
        if not chain:
            raise ValueError("Empty vulnerability chain")
        if not context.validate():
            raise ValueError("Invalid chain context")

        start_time = datetime.now()
        try:
            # Check cache first
            chain_hash = self._compute_chain_hash(chain)
            cached_result = self._get_cached_analysis(chain_hash)
            if cached_result:
                return cached_result

            # Prepare detailed analysis prompt
            prompt = self._prepare_chain_prompt(chain, context)

            # Get model based on mode
            model_name = "o1" if self.mode == ChainAnalysisMode.DEEP else "o1-mini"

            # Create analysis request
            request = self._create_analysis_request(prompt, chain, context)

            # Perform analysis with selected model
            self.analyzer.model = model_name
            result = await self.analyzer.analyze(request)

            # Parse and validate results
            analysis_result = self._parse_chain_analysis(cast(Dict[str, Any], result))

            # Update metrics
            self._update_metrics(True, (datetime.now() - start_time).total_seconds())

            # Cache result
            self._analysis_cache[chain_hash] = analysis_result
            return analysis_result

        except Exception as e:
            self._update_metrics(False, (datetime.now() - start_time).total_seconds(), str(e))
            raise

    def _update_metrics(self, success: bool, duration: float, error: Optional[str] = None) -> None:
        """Update analysis metrics"""
        self.metrics.total_chains += 1
        if success:
            self.metrics.successful_analyses += 1
        else:
            self.metrics.failed_analyses += 1
            if error:
                self.metrics.error_counts[error] = self.metrics.error_counts.get(error, 0) + 1

        # Update average analysis time
        current_total = self.metrics.average_analysis_time * (self.metrics.total_chains - 1)
        self.metrics.average_analysis_time = (current_total + duration) / self.metrics.total_chains

    def _score_analysis_quality(self, result: ChainAnalysisResult) -> float:
        """Score the quality of analysis results"""
        scores: List[float] = []

        # Check completeness
        if result["reasoning"]:
            scores.append(1.0)
        if result["prerequisites"]:
            scores.append(1.0)
        if result["mitigations"]:
            scores.append(1.0)
        if result["attack_steps"]:
            scores.append(1.0)

        # Check reasonableness of numeric scores
        if 0 <= result["feasibility"] <= 1:
            scores.append(1.0)
        if 0 <= result["complexity"] <= 1:
            scores.append(1.0)
        if 0 <= result["impact_score"] <= 1:
            scores.append(1.0)

        return sum(scores) / len(scores) if scores else 0.0

    async def analyze_chain_batch(
        self,
        chains: Sequence[List[ChainableVulnerability]],
        context: ChainContext,
        batch_size: int = 5
    ) -> List[ChainAnalysisResult]:
        """Analyze multiple vulnerability chains in batches"""
        results: List[ChainAnalysisResult] = []

        async def analyze_with_semaphore(chain: List[ChainableVulnerability]) -> ChainAnalysisResult:
            async with self.semaphore:
                return await self.analyze_chain(chain, context)

        # Process chains in batches
        for i in range(0, len(chains), batch_size):
            batch = chains[i:i + batch_size]
            batch_results = await asyncio.gather(
                *[analyze_with_semaphore(chain) for chain in batch],
                return_exceptions=True
            )

            # Filter out any failed analyses
            valid_results = [
                r for r in batch_results
                if isinstance(r, dict) and self._is_valid_result(r)
            ]
            results.extend(valid_results)

        return results

    def _is_valid_result(self, result: Any) -> TypeGuard[ChainAnalysisResult]:
        """Type guard to validate chain analysis results"""
        try:
            if not isinstance(result, dict):
                return False
            if not all(k in result for k in ChainAnalysisResult.__annotations__):
                return False
            return self._score_analysis_quality(cast(ChainAnalysisResult, result)) > 0.7
        except Exception:
            return False

    def _prepare_chain_prompt(
        self,
        chain: List[ChainableVulnerability],
        context: ChainContext
    ) -> str:
        """Prepare detailed prompt for chain analysis"""
        # Get base prompt template based on mode
        template = self.prompts["deep_analysis" if self.mode == ChainAnalysisMode.DEEP else "quick_analysis"]

        # Build chain description
        chain_desc = self._build_chain_description(chain)

        # Build context description
        context_desc = self._build_context_description(context)

        # Format prompt with chain and context details
        return template.format(
            chain_description=chain_desc,
            context_description=context_desc,
            chain_length=len(chain),
            entry_points=", ".join(context.entry_points),
            affected_components=", ".join(context.affected_components),
            known_bypasses=", ".join(context.known_bypasses)
        )

    def _build_chain_description(self, chain: List[ChainableVulnerability]) -> str:
        """Build detailed description of vulnerability chain"""
        steps: List[str] = []
        for i, vuln in enumerate(chain, 1):
            steps.append(
                f"Step {i}:\n"
                f"Type: {vuln.vulnerability_type}\n"
                f"Impact: {vuln.impact.value}\n"
                f"Entry Points: {', '.join(vuln.entry_points)}\n"
                f"Prerequisites: {', '.join(vuln.prerequisites)}\n"
                f"Affected Components: {', '.join(vuln.affected_components)}\n"
                f"Chain Probability: {vuln.chain_probability:.2f}\n"
            )
        return "\n".join(steps)

    def _build_context_description(self, context: ChainContext) -> str:
        """Build detailed description of analysis context"""
        return (
            f"Technology Stack:\n"
            f"{json.dumps(context.technology_stack, indent=2)}\n\n"
            f"Security Controls:\n"
            f"{json.dumps(context.security_controls, indent=2)}\n\n"
            f"Known Bypasses:\n"
            f"{json.dumps(context.known_bypasses, indent=2)}\n\n"
            f"Chain History:\n"
            f"{json.dumps(context.chain_history, indent=2)}"
        )

    def _create_analysis_request(
        self,
        prompt: str,
        chain: List[ChainableVulnerability],
        context: ChainContext
    ) -> SecurityAnalysisRequest:
        """Create security analysis request for O1"""
        return SecurityAnalysisRequest(
            code=prompt,
            context=SecurityContext(
                service="chain_analysis",
                endpoint="analyze_chain",
                method="POST",
                parameters={
                    "chain_length": len(chain),
                    "vulnerability_types": [v.vulnerability_type for v in chain],
                    "impact_levels": [v.impact.value for v in chain],
                    "entry_points": list(context.entry_points),
                    "affected_components": list(context.affected_components),
                    "technology_stack": context.technology_stack,
                    "security_controls": context.security_controls
                }
            ),
            focus_areas=["chain_analysis", "vulnerability_correlation"],
            vulnerability_types=[v.vulnerability_type for v in chain]
        )

    def _parse_chain_analysis(self, result: Dict[str, Any]) -> ChainAnalysisResult:
        """Parse and validate chain analysis results"""
        if not result.get("findings"):
            raise ValueError("No analysis results found")

        finding = result["findings"][0]

        return ChainAnalysisResult(
            feasibility=float(finding.get("feasibility", 0.0)),
            complexity=float(finding.get("complexity", 0.0)),
            impact_score=float(finding.get("impact_score", 0.0)),
            detection_likelihood=float(finding.get("detection_likelihood", 0.0)),
            reasoning=str(finding.get("reasoning", "")),
            prerequisites=list(finding.get("prerequisites", [])),
            mitigations=list(finding.get("mitigations", [])),
            attack_steps=list(finding.get("attack_steps", []))
        )

    def estimate_chain_complexity(self, chain: List[ChainableVulnerability]) -> float:
        """Estimate complexity of vulnerability chain"""
        if not chain:
            return 0.0

        # Base complexity factors
        length_factor = len(chain) * 0.2
        probability_factor = sum(v.chain_probability for v in chain) / len(chain)

        # Impact weights
        impact_weights = {
            BugBountyImpact.CRITICAL: 1.0,
            BugBountyImpact.HIGH: 0.8,
            BugBountyImpact.MEDIUM: 0.5,
            BugBountyImpact.LOW: 0.2
        }

        # Calculate weighted impact
        impact_factor = sum(
            impact_weights[v.impact] for v in chain
        ) / len(chain)

        # Combine factors
        return (length_factor + probability_factor + impact_factor) / 3.0
