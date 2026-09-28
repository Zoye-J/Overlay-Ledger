"""
Shared utilities for the ZTA Overlay Network.

This package contains cross-cutting concerns used by all services:
- logging_config: ECS-aligned JSON logging with trace_id correlation
- events: Canonical event taxonomy (names + ATT&CK hints)

Import pattern:
    from shared.logging_config import setup_logger
    from shared.events import AUTH_LOGIN_SUCCESS
"""