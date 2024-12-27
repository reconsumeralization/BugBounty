"""Type definitions for LLM tools."""

from dataclasses import dataclass
from typing import List, Dict
@dataclass
class ChatMessage:
    """Chat message."""
    role: str
    content: str

@dataclass
class ChatChoice:
    """Chat completion choice."""
    index: int
    message: ChatMessage

@dataclass
class ChatCompletion:
    """Chat completion response."""
    id: str
    choices: List[ChatChoice]
    usage: Dict[str, int]
