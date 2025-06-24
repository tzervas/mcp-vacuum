FROM python:3.12-slim-bookworm

# Install system dependencies
RUN apt-get update && apt-get install -y \
    git \
    curl \
    gpg \
    gnupg2 \
    sudo \
    libsecret-tools \\
    && rm -rf /var/lib/apt/lists/*

# Install UV
RUN curl -LsSf https://astral.sh/uv/install.sh | sh

# Install GitHub CLI
RUN curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg | dd of=/usr/share/keyrings/githubcli-archive-keyring.gpg \
    && chmod go+r /usr/share/keyrings/githubcli-archive-keyring.gpg \
    && echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" | tee /etc/apt/sources.list.d/github-cli.list > /dev/null \
    && apt-get update \
    && apt-get install -y gh \
    && rm -rf /var/lib/apt/lists/*

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
    && apt-get update \
    && apt-get install -y sudo \
    && echo $USERNAME ALL=\(root\) NOPASSWD:ALL > /etc/sudoers.d/$USERNAME \
    && chmod 0440 /etc/sudoers.d/$USERNAME

USER $USERNAME

# Set up UV configuration
ENV UV_HOME=/home/$USERNAME/.uv
ENV PATH=$UV_HOME/bin:$PATH

WORKDIR /workspaces/mcp-vacuum
