FROM python:3.12-slim-bookworm

# Install system dependencies
RUN export DEBIAN_FRONTEND=noninteractive \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
        git \
        curl \
        build-essential \
        python3-dev \
        ca-certificates \
        gpg \
        ssh \
        # Add Windows Git line ending support
        dos2unix \
    && rm -rf /var/lib/apt/lists/*

# Install UV package manager globally
RUN curl -LsSf https://astral.sh/uv/install.sh | sh \
    && cp /root/.local/bin/uv /usr/local/bin/ \
    && cp /root/.local/bin/uvx /usr/local/bin/ \
    && rm -rf /root/.local/bin

# Set Python environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/workspaces/mcp-vacuum \
    # Add Windows/WSL compatibility
    PYTHONIOENCODING=UTF-8

# Create non-root user and set up directory structure
ARG USERNAME=developer
ARG USER_UID=1000
ARG USER_GID=1000

RUN groupadd --gid $USER_GID $USERNAME \
    && useradd --uid $USER_UID --gid $USER_GID -m $USERNAME \
    && mkdir -p /workspaces/mcp-vacuum \
    && mkdir -p /home/$USERNAME/.cache/pip \
    && mkdir -p /home/$USERNAME/.cache/uv \
    && mkdir -p /home/$USERNAME/.local/share \
    && chown -R $USERNAME:$USERNAME /workspaces/mcp-vacuum \
    && chown -R $USERNAME:$USERNAME /home/$USERNAME/.cache \
    && chown -R $USERNAME:$USERNAME /home/$USERNAME/.local \
    # Add sudo support for non-root user
    && apt-get update \
    && apt-get install -y sudo \
    && echo $USERNAME ALL=\(root\) NOPASSWD:ALL > /etc/sudoers.d/$USERNAME \
    && chmod 0440 /etc/sudoers.d/$USERNAME \
    && rm -rf /var/lib/apt/lists/*

# Configure Git for cross-platform compatibility
RUN git config --system core.autocrlf input \
    && git config --system core.eol lf

USER $USERNAME

# Set up UV and pip cache directories
ENV PIP_CACHE_DIR=/home/$USERNAME/.cache/pip \
    UV_CACHE_DIR=/home/$USERNAME/.cache/uv \
    UV_SYSTEM_PYTHON=/usr/local/bin/python3 \
    UV_NO_VENV=1

# Create cache directories with correct permissions and setup script
RUN mkdir -p "$PIP_CACHE_DIR" \
    && mkdir -p "$UV_CACHE_DIR" \
    && chown -R $USERNAME:$USERNAME "$PIP_CACHE_DIR" \
    && chown -R $USERNAME:$USERNAME "$UV_CACHE_DIR"

# Create initialization script as root (before switching to developer user)
USER root
RUN echo '#!/bin/bash' > /usr/local/bin/init-dev.sh \
    && echo 'set -e' >> /usr/local/bin/init-dev.sh \
    && echo 'export UV_SYSTEM_PYTHON=/usr/local/bin/python3' >> /usr/local/bin/init-dev.sh \
    && echo 'export UV_NO_VENV=1' >> /usr/local/bin/init-dev.sh \
    && echo '/usr/local/bin/uv pip install -e ".[dev]"' >> /usr/local/bin/init-dev.sh \
    && echo 'python -m pytest tests/' >> /usr/local/bin/init-dev.sh \
    && chmod +x /usr/local/bin/init-dev.sh

# Switch back to developer user
USER $USERNAME

WORKDIR /workspaces/mcp-vacuum
