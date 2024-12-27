"""Configuration loader for LLM tools."""

from typing import Dict, List
from dataclasses import dataclass, field
from pathlib import Path
import yaml
import logging
import logging.handlers

@dataclass
class O1ModelConfig:
    """O1 model configuration."""
    model_name: str = "o1"  # or "o1-mini"
    max_completion_tokens: int = 25000  # Reserve space for reasoning
    response_format: Dict[str, str] = field(default_factory=lambda: {"type": "json_object"})
    developer_message: str = ""  # For chain of command behavior
    markdown_enabled: bool = False  # Control markdown formatting
    timeout_seconds: int = 300  # Models can take longer for complex reasoning

    # Unsupported parameters in current O1 models:
    # temperature, top_p, presence_penalty, frequency_penalty, logprobs,
    # top_logprobs, logit_bias

@dataclass
class RateLimitConfig:
    """Rate limiting configuration."""
    requests_per_minute: int
    burst: int

@dataclass
class TimeoutConfig:
    """Timeout configuration."""
    vulnerability_analysis: int
    chain_analysis: int
    recommendations: int
    default: int

@dataclass
class CacheConfig:
    """Cache configuration."""
    enabled: bool
    ttl_hours: int
    max_entries: int
    excluded_tools: List[str]

@dataclass
class AnalysisConfig:
    """Analysis configuration."""
    min_confidence: float
    max_vulnerabilities: int
    max_chain_length: int
    severity_thresholds: Dict[str, float]

@dataclass
class CategoryConfig:
    """Tool category configuration."""
    name: str
    description: str
    enabled: bool

@dataclass
class LoggingConfig:
    """Logging configuration."""
    level: str
    file: str
    format: str
    max_size_mb: int
    backup_count: int

@dataclass
class SecurityConfig:
    """Security configuration."""
    require_authentication: bool
    validate_inputs: bool
    sanitize_outputs: bool
    max_payload_size_mb: int
    allowed_file_extensions: List[str]

@dataclass
class LLMToolsConfig:
    """Main configuration for LLM tools."""
    o1_model: O1ModelConfig
    rate_limits: Dict[str, RateLimitConfig]
    timeouts: TimeoutConfig
    cache: CacheConfig
    analysis: AnalysisConfig
    categories: List[CategoryConfig]
    logging: LoggingConfig
    security: SecurityConfig

def load_config(config_path: Path) -> LLMToolsConfig:
    """Load configuration from YAML file."""
    try:
        with open(config_path) as f:
            config_data = yaml.safe_load(f)

        # Load O1 model config
        o1_model = O1ModelConfig(**config_data['o1_model'])

        # Load rate limits
        rate_limits = {
            name: RateLimitConfig(**limits)
            for name, limits in config_data['rate_limits'].items()
        }

        # Load timeouts
        timeouts = TimeoutConfig(**config_data['timeouts'])

        # Load cache config
        cache = CacheConfig(**config_data['cache'])

        # Load analysis config
        analysis = AnalysisConfig(**config_data['analysis'])

        # Load categories
        categories = [
            CategoryConfig(**category)
            for category in config_data['categories']
        ]

        # Load logging config
        logging_config = LoggingConfig(**config_data['logging'])

        # Load security config
        security = SecurityConfig(**config_data['security'])

        return LLMToolsConfig(
            o1_model=o1_model,
            rate_limits=rate_limits,
            timeouts=timeouts,
            cache=cache,
            analysis=analysis,
            categories=categories,
            logging=logging_config,
            security=security
        )

    except Exception as e:
        logging.error(f"Failed to load config from {config_path}: {e}")
        raise

def setup_logging(config: LoggingConfig) -> None:
    """Set up logging based on configuration."""
    logging.basicConfig(
        level=getattr(logging, config.level.upper()),
        format=config.format,
        handlers=[
            logging.handlers.RotatingFileHandler(
                config.file,
                maxBytes=config.max_size_mb * 1024 * 1024,
                backupCount=config.backup_count
            ),
            logging.StreamHandler()
        ]
    )
