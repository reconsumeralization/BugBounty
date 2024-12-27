"""Concrete implementation of the LLM Tool Manager."""

from typing import Dict, Any, List, Optional
import logging
import asyncio
from .tool_manager import (
    ToolExecutor,
    ToolResult,
    ToolMetadata,
    ToolCategory
)

class DefaultLLMToolManager:
    """Default implementation of LLM tool manager."""

    def __init__(self) -> None:
        """Initialize the tool manager."""
        self.tools: Dict[str, ToolExecutor] = {}
        self.metadata: Dict[str, ToolMetadata] = {}
        self.logger = logging.getLogger(__name__)

    def register_tool(
        self,
        metadata: ToolMetadata,
        executor: ToolExecutor
    ) -> None:
        """Register a new tool with metadata."""
        if metadata.name in self.tools:
            raise ValueError(f"Tool {metadata.name} already registered")

        self.tools[metadata.name] = executor
        self.metadata[metadata.name] = metadata
        self.logger.info(f"Registered tool: {metadata.name}")

    def get_tool_metadata(self, name: str) -> Optional[ToolMetadata]:
        """Get metadata for a registered tool."""
        return self.metadata.get(name)

    def list_tools(self, category: Optional[ToolCategory] = None) -> List[ToolMetadata]:
        """List all registered tools, optionally filtered by category."""
        tools = list(self.metadata.values())
        if category:
            tools = [t for t in tools if t.category == category]
        return tools

    async def execute_tool(self, name: str, **kwargs: Any) -> ToolResult:
        """Execute a registered tool."""
        if name not in self.tools:
            return ToolResult(
                success=False,
                data=None,
                error=f"Tool {name} not found"
            )

        tool = self.tools[name]
        metadata = self.metadata[name]

        try:
            if metadata.timeout:
                async with asyncio.timeout(metadata.timeout):
                    result = await tool.execute(**kwargs)
            else:
                result = await tool.execute(**kwargs)

            return result
        except asyncio.TimeoutError:
            return ToolResult(
                success=False,
                data=None,
                error=f"Tool {name} execution timed out"
            )
        except Exception as e:
            self.logger.error(f"Tool {name} execution failed: {e}")
            return ToolResult(
                success=False,
                data=None,
                error=str(e)
            )

    async def execute_chain(
        self,
        tools: List[tuple[str, Dict[str, Any]]]
    ) -> List[ToolResult]:
        """Execute a chain of tools in sequence."""
        results: List[ToolResult] = []
        for tool_name, tool_args in tools:
            result = await self.execute_tool(tool_name, **tool_args)
            results.append(result)
            if not result.success:
                break
        return results
