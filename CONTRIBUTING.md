# Contributing to KernelWatch

Thank you for your interest in contributing to KernelWatch! This project aims to empower security researchers to proactively identify vulnerable drivers.

## Code of Conduct

This project adheres to a standard Code of Conduct. By participating, you are expected to uphold this code. Please report unacceptable behavior to the project maintainers.

## Getting Started

1.  **Fork the repository** on GitHub.
2.  **Clone your fork** locally:
    ```bash
    git clone https://github.com/your-username/KernelWatch.git
    cd KernelWatch
    ```
3.  **Install dependencies**:
    ```bash
    uv sync
    cd ui && npm install
    ```
4.  **Install pre-commit hooks** (Important!):
    ```bash
    uv run lefthook install
    ```

## Development Workflow

### Backend (Python)

We use `uv` for dependency management and `ruff`/`mypy` for code quality.

*   **Lint & Format**: `uv run ruff check src/ tests/` / `uv run ruff format src/ tests/`
*   **Type Check**: `uv run mypy src/`
*   **Run Tests**: `uv run pytest tests/`

### Frontend (Tauri/SolidJS)

*   **Dev Server**: `cd ui && npm run tauri:dev`
*   **Linting**: `cd ui && npm run build` (runs tsc)

### Making Changes

1.  Create a new branch: `git checkout -b feature/my-new-feature`.
2.  Make your changes.
3.  Ensure all checks pass (`uv run lefthook run pre-commit`).
4.  Commit your changes using conventional commits (e.g., `feat: add new vendor scraper`).
5.  Push to your branch and submit a Pull Request.

## Project Structure

*   `src/kernel_watch/`: Python backend logic (CLI, Analysis, Sources).
*   `ui/`: Tauri frontend (SolidJS + Tailwind v4).
*   `tests/`: Pytest suite.
*   `scripts/`: Build helpers.

## Security

If you discover a potential security vulnerability in KernelWatch itself, please refer to our [Security Policy](SECURITY.md).

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
