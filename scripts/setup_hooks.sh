#!/bin/bash

# Exit on error
set -e

echo "Installing pre-commit..."
pip install pre-commit

echo "Installing git hook scripts..."
pre-commit install

echo "Installing additional dependencies..."
pip install black mypy pylint isort ruff safety

echo "Updating hooks to latest version..."
pre-commit autoupdate

echo "Running hooks against all files..."
pre-commit run --all-files

echo "Setup completed successfully!"
