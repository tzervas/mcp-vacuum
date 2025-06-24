# Extend the base Warp Terminal image
FROM ghcr.io/tzervas/warp-term-container:latest

USER root

# Install additional dependencies for MCP Vacuum
RUN apt-get update && apt-get install -y \
    # Network tools for MCP server discovery
    nmap \
    netcat-openbsd \
    dnsutils \
    # Security tools
    openssl \
    ca-certificates \
    # Python build dependencies
    python3-dev \
    && rm -rf /var/lib/apt/lists/*

# Switch back to warp user
USER warp

# Copy project files
COPY --chown=warp:warp . /home/warp/project/

# Set working directory
WORKDIR /home/warp/project

# Install project dependencies
RUN uv venv && \
    . .venv/bin/activate && \
    uv pip install -e ".[dev]"

# Keep the original entrypoint
ENTRYPOINT ["/home/warp/entrypoint.sh"]
