# DSM Development Toolchain

This document describes the comprehensive development toolchain set up for the DSM project.

## CI/CD Pipeline

The DSM project uses GitHub Actions for its CI/CD needs. The following workflows are available:

### Core Workflows

- **CI**: Runs on every push and pull request to validate basic code quality
  - Builds the code
  - Runs tests
  - Checks formatting with `rustfmt`
  - Lints with `clippy`
  - Runs security audit with `cargo-audit` and `cargo-deny`
  - Generates code coverage reports

- **Release**: Creates GitHub releases when a new tag is pushed
  - Builds binaries for multiple platforms
  - Packages them as release assets
  - Generates release notes

### Additional Workflows

- **PR Benchmarks**: Runs on PRs labeled with `run-benchmarks`
  - Measures performance impact of changes
  - Reports results as PR comments

- **Documentation**: Builds and deploys API documentation to GitHub Pages
  - Runs on pushes to `main`
  - Generates comprehensive documentation

- **Scheduled Benchmarks**: Runs weekly to track performance over time
  - Records benchmark results
  - Publishes to GitHub Pages

- **Dependency Review**: Analyzes dependency changes on PRs
  - Checks for security issues
  - Validates license compliance

- **Issue Management**: Automates issue and PR triage
  - Adds labels based on changed files
  - Assigns reviewers automatically

- **Cache Optimizer**: Keeps build caches fresh
  - Runs weekly to update caches

- **Stale**: Manages inactive issues and PRs

## Development Environment

### Required Tools

- **Rust** (stable toolchain): Primary language
- **Cargo**: Package manager
- **Additional cargo extensions**:
  - `cargo-audit`: Security auditing
  - `cargo-deny`: License checking
  - `cargo-criterion`: Benchmarking
  - `cargo-llvm-cov`: Code coverage

### Editor Support

VSCode integration is provided with:
- Recommended extensions
- Workspace settings
- Launch configurations for debugging

### Cloud Development

Gitpod configuration allows for immediate development in the cloud:
- Pre-configured Dockerfile
- Workspace setup

## Pre-commit Hooks

Local validation before committing can be set up using the `.pre-commit-config.yaml` file:

```bash
# Install pre-commit
pip install pre-commit

# Install the hooks
pre-commit install
```

## Repository Settings

The repository includes:

- **Dependabot configuration**: Automated dependency updates
- **Pull request template**: Standardized PR descriptions
- **Issue templates**: Structured bug reports and feature requests
- **Auto-assignment**: Automatic reviewer assignment

## Continuous Integration Checks

The CI pipeline runs these checks:

- **Security**: Dependency scanning, SAST
- **Quality**: Code style, linting, best practices
- **Testing**: Unit tests, integration tests
- **Performance**: Regular benchmarking
- **Documentation**: API docs validation

## How to Use

1. **Local Development**: Use VSCode with recommended extensions
2. **PR Workflow**: Submit PRs for review, ensure CI passes
3. **Documentation**: Run `cargo doc --open` locally to view API docs
4. **Benchmarking**: Use `cargo criterion` for performance testing

## Best Practices

- Run `cargo fmt` and `cargo clippy` before committing
- Write tests for new functionality
- Add documentation for public APIs
- Label PRs appropriately for automatic workflows

## Troubleshooting

- Check CI logs for specific error details
- Run problematic jobs locally to debug
- Use GitHub Actions local debugging tools
