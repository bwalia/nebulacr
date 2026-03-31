# Contributing to NebulaCR

Thank you for your interest in contributing to NebulaCR! We welcome contributions of all kinds, whether you are reporting a bug, suggesting a feature, improving documentation, or writing code.

## Reporting Bugs

If you find a bug, please open a GitHub issue at <https://github.com/bwalia/nebulacr/issues> and include:

- A clear, descriptive title.
- Steps to reproduce the issue.
- Expected behavior versus actual behavior.
- Your environment details (OS, Rust version, NebulaCR version).
- Any relevant logs or error messages.

## Suggesting Features

Feature requests are welcome. Please open a GitHub issue and describe:

- The problem you are trying to solve.
- Your proposed solution or the behavior you would like to see.
- Any alternatives you have considered.

We will discuss the proposal in the issue before any implementation begins.

## Development Setup

NebulaCR is written in Rust. To get started:

1. Install the Rust toolchain via [rustup](https://rustup.rs/).
2. Clone the repository:
   ```
   git clone https://github.com/bwalia/nebulacr.git
   cd nebulacr
   ```
3. Build the project:
   ```
   cargo build
   ```
4. Run the test suite:
   ```
   cargo test
   ```

## Pull Request Process

1. Fork the repository and create a new branch from `main`.
2. Make your changes in focused, well-scoped commits.
3. Ensure all tests pass (`cargo test`) and the project builds without warnings.
4. Open a pull request against `main` with a clear description of what your change does and why.
5. A maintainer will review your PR. Please be responsive to feedback.
6. Once approved, a maintainer will merge your pull request.

## Code Style

- Format all code with `rustfmt` before committing:
  ```
  cargo fmt
  ```
- Run `clippy` and address any warnings:
  ```
  cargo clippy -- -D warnings
  ```
- Write clear, concise commit messages.
- Add tests for new functionality where practical.

## License

By contributing to NebulaCR, you agree that your contributions will be licensed under the Apache License 2.0.
