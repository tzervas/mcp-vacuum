#!/bin/bash
set -e

echo "Verifying development environment setup..."

# Check GPG key
echo "Checking GPG key..."
if ! gpg --list-secret-keys --keyid-format=long | grep "884E9E08D0C7DF6C" > /dev/null; then
    echo "Error: Warp Terminal AI GPG key not found"
    exit 1
fi

# Check Git configuration
echo "Checking Git configuration..."
if ! git config --get user.name | grep "Warp Terminal AI" > /dev/null; then
    echo "Error: Git user.name not set correctly"
    exit 1
fi

if ! git config --get user.email | grep "ai-assistant@warp.dev" > /dev/null; then
    echo "Error: Git user.email not set correctly"
    exit 1
fi

if ! git config --get user.signingkey | grep "884E9E08D0C7DF6C" > /dev/null; then
    echo "Error: Git signing key not set correctly"
    exit 1
fi

# Check GitHub CLI authentication
echo "Checking GitHub CLI authentication..."
if ! gh auth status &> /dev/null; then
    echo "Warning: GitHub CLI not authenticated"
    echo "Please run 'gh auth login' to authenticate"
fi

# Verify Python and UV
echo "Checking Python and UV..."
python_version=$(python --version 2>&1)
if [[ ! $python_version == *"3.12"* ]]; then
    echo "Error: Python 3.12 not found"
    exit 1
fi

if ! command -v uv &> /dev/null; then
    echo "Error: UV package manager not found"
    exit 1
fi

echo "Setup verification complete!"
