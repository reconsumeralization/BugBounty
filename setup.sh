#!/bin/bash

# Create directory structure
mkdir -p config/scope
mkdir -p core
mkdir -p modules
mkdir -p analysis
mkdir -p tests
mkdir -p tools/manual_testing
mkdir -p tools/analysis

# Create virtual environment
python -m venv venv
source venv/Scripts/activate  # Windows specific

# Install required packages
pip install -r requirements.txt

# Initialize git repository if not already initialized
if [ ! -d .git ]; then
    git init
    # Add initial .gitignore
    cp .gitignore.template .gitignore
fi

# Set up pre-commit hooks
cp pre-commit .git/hooks/
chmod +x .git/hooks/pre-commit

echo "Environment setup complete!"
