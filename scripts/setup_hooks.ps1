# Error handling
$ErrorActionPreference = "Stop"

try {
    Write-Host "Installing pre-commit..."
    python -m pip install pre-commit

    Write-Host "Installing git hook scripts..."
    pre-commit install

    Write-Host "Installing additional dependencies..."
    python -m pip install black mypy pylint isort ruff safety

    Write-Host "Updating hooks to latest version..."
    pre-commit autoupdate

    Write-Host "Running hooks against all files..."
    pre-commit run --all-files

    Write-Host "Setup completed successfully!"
} catch {
    Write-Host "Error during setup: $_" -ForegroundColor Red
    exit 1
}
