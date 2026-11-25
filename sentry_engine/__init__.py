"""SENTRY — Guards Against Intrusions.

Detect. Defend. Restore.

The ``sentry_engine`` package is the trusted security execution engine. AI agents
reason about its output through the CLI, the MCP server or the REST API. They
cannot approve destructive actions. Only a human holding the approver
passphrase can do that (see ``sentry_engine.approval``).
"""

from .version import __version__

__all__ = ["__version__"]
