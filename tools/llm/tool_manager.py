"""LLM Tool Manager for handling tool registration and execution."""

from typing import Dict, Any, List, Optional, Protocol, TypeVar, runtime_checkable
from dataclasses import dataclass
from enum import Enum
import logging

T = TypeVar('T')

class ToolCategory(Enum):
    """Categories of LLM tools."""
    ANALYSIS = "analysis"
    RECON = "reconnaissance"
    EXPLOIT = "exploit"
    REPORT = "report"
    UTILITY = "utility"

@dataclass
class ToolMetadata:
    """Metadata for registered tools."""
    name: str
    description: str
    category: ToolCategory
    version: str
    author: str
    requires_auth: bool = False
    rate_limit: Optional[int] = None
    timeout: Optional[int] = None

@dataclass
class ToolResult:
    """Result from a tool execution."""
    success: bool
    error: Optional[str] = None
    data: Optional[Dict[str, Any]] = None

@runtime_checkable
class ToolExecutor(Protocol):
    """Protocol for tool execution."""
    async def execute(self, **kwargs: Any) -> ToolResult: ...

@runtime_checkable
class LLMToolManager(Protocol):
    """Protocol for LLM tool manager."""
    tools: Dict[str, ToolExecutor]
    metadata: Dict[str, ToolMetadata]
    logger: logging.Logger

    def register_tool(self, metadata: ToolMetadata, executor: ToolExecutor) -> None: ...
    def get_tool_metadata(self, name: str) -> Optional[ToolMetadata]: ...
    def list_tools(self, category: Optional[ToolCategory] = None) -> List[ToolMetadata]: ...
    async def execute_tool(self, name: str, **kwargs: Any) -> ToolResult: ...
    async def execute_chain(self, tools: List[tuple[str, Dict[str, Any]]]) -> List[ToolResult]: ...
