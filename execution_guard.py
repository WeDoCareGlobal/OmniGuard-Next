"""Fail-closed execution adapter for OmniGuard inspection decisions.

The gateway is an inspector, not an LLM or tool executor. The caller must route
every protected action through this boundary before invoking the action.
"""
from collections.abc import Callable
from typing import TypeVar

from client_sdk import OmniGuardClient, OmniGuardError

T = TypeVar("T")


def execute_guarded(client: OmniGuardClient, messages: list[dict], action: Callable[[], T]) -> T:
    """Execute only after a successful, explicit gateway ALLOW.

    Exceptions, missing decisions and HTTP failures prevent action execution.
    This does not authenticate or integrate an external AgentGuard runtime.
    """
    if not callable(action):
        raise TypeError("action must be callable")
    # OmniGuardClient checks both HTTP 200 and X-Governance-Decision == ALLOW.
    client.chat_completion(messages)
    return action()
