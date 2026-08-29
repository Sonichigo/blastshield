"""Entry point: `blastshield` or `python -m blastshield`."""

from __future__ import annotations

import argparse
import sys

from .server import mcp, runtime


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="blastshield",
        description="MCP server with safety primitives for PostgreSQL and MongoDB changes.",
    )
    parser.add_argument(
        "--transport",
        choices=["stdio", "streamable-http"],
        default="stdio",
        help="stdio for local clients (default); streamable-http for remote access",
    )
    args = parser.parse_args()

    rt = runtime()  # fail fast on bad config, start the audit log
    if rt.settings.ephemeral_secret:
        print(
            "WARNING: BLAST_TICKET_SECRET is not set; using an ephemeral secret. "
            "Tickets will not survive a server restart.",
            file=sys.stderr,
        )

    try:
        if args.transport == "streamable-http":
            mcp.run(transport="streamable-http")
        else:
            mcp.run()
    finally:
        rt.close()


if __name__ == "__main__":
    main()
