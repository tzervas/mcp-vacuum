FROM python:3.12-slim-bookworm

# Install minimal system dependencies and UV package manager
RUN apt-get update && apt-get install -y \
    git \
    curl \
    build-essential \
    python3-dev \
    && rm -rf /var/lib/apt/lists/* \
    && curl -LsSf https://astral.sh/uv/install.sh | sh

# Set Python environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/workspaces/mcp-vacuum

# Create non-root user
ARG USERNAME=developer
ARG USER_UID=1000
ARG USER_GID=$USER_UID

RUN groupadd --gid $USER_GID $USERNAME \
    && useradd --uid $USER_UID --gid $USER_GID -m $USERNAME \
    && mkdir -p /workspaces/mcp-vacuum \
    && chown -R $USERNAME:$USERNAME /workspaces/mcp-vacuum

USER $USERNAME

# Set up UV configuration
ENV UV_HOME=/home/$USERNAME/.uv
ENV PATH=$UV_HOME/bin:$PATH

WORKDIR /workspaces/mcp-vacuum
