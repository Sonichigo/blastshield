"""blastshield: safety primitives for database MCP tools.

Every write goes through the same lifecycle:

    estimate -> dry_run (issues a signed ticket) -> apply (requires ticket) -> rollback

No tool in this server will execute a write it has not analyzed first.
"""

__version__ = "0.1.0"
