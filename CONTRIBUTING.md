# Contributing to DSM

Thank you for your interest in contributing to the Decentralized State Machine (DSM) project! This document outlines the process and guidelines for contributing.

## Development Toolchain

### Required Tools

- **Rust** (stable channel): The project uses the latest stable Rust toolchain
- **Cargo**: Rust's package manager (comes with Rust installation)
- **Git**: For version control
- **GitHub account**: For submitting pull requests

### Recommended Tools

- **cargo-audit**: For security vulnerability scanning (`cargo install cargo-audit`)
- **cargo-deny**: For license and dependency checking (`cargo install cargo-deny`)
- **cargo-criterion**: For running benchmarks (`cargo install cargo-criterion`)
- **cargo-llvm-cov**: For code coverage analysis (`cargo install cargo-llvm-cov`)

## Development Workflow

1. **Fork the repository** on GitHub
2. **Clone your fork** to your local machine
3. **Create a new branch** for your feature or bugfix:
   ```
   git checkout -b feature/your-feature-name
   ```
4. **Make your changes** and write tests
5. **Run local checks** before submitting:
   ```
   # Format code
   cargo fmt --all
   
   # Run clippy lints
   cargo clippy --all-targets --all-features
   
   # Run tests
   cargo test --workspace
   
   # Check security
   cargo audit
   cargo deny check
   
   # Generate docs
   cargo doc --workspace --no-deps
   ```
6. **Commit your changes** with descriptive commit messages
7. **Push to your fork**
8. **Submit a pull request** to the main repository

## Pull Request Guidelines

- PRs should target the `main` branch
- Follow the PR template when submitting
- Each PR should focus on a single issue or feature
- Include tests for new functionality
- Ensure all CI checks pass
- Request reviews from maintainers when ready

## Continuous Integration

The repository uses GitHub Actions for CI/CD with the following checks:

- **Build & Test**: Compiles the code and runs all tests
- **Formatting**: Ensures code follows our style guidelines
- **Linting**: Runs clippy to catch common issues
- **Security Audit**: Scans dependencies for vulnerabilities
- **Documentation**: Checks that docs build without warnings
- **Code Coverage**: Measures test coverage

## Benchmark Requirements

For changes that might affect performance:

1. Label your PR with "run-benchmarks" to trigger benchmark CI
2. Use `cargo criterion` to run benchmarks locally
3. Compare before/after results in your PR description

## Code Style Guidelines

- Follow the Rust standard style guidelines
- Use `cargo fmt` with our repository's rustfmt.toml configuration
- Document all public interfaces
- Write clear, concise commit messages
- Use descriptive variable names

## License Compliance

All contributions must be compatible with our licensing terms:

- All code is dual-licensed under MIT OR Apache-2.0
- Run `cargo deny check` to ensure dependencies are compliant

## Getting Help

If you need help with the contribution process:

- Open a discussion on the GitHub repository
- Reach out to the maintainers

Thank you for contributing to DSM!
