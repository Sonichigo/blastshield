FROM python:3.12-slim

WORKDIR /app
COPY pyproject.toml README.md ./
COPY src/ src/
RUN pip install --no-cache-dir .

# Non-root; state dir for audit log + rollback snapshots
RUN useradd -r -u 10001 blast && mkdir -p /state && chown blast /state
USER blast
ENV BLAST_STATE_DIR=/state

# stdio by default; pass --transport streamable-http for remote use
ENTRYPOINT ["blastshield"]
