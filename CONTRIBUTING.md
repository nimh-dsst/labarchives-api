# Contributing to labapi

Thank you for your interest in contributing to **labapi**!

## Quick Start

1. Fork the repository
2. Clone your fork
3. Create a feature branch
4. Make your changes
5. Run tests
6. Submit a pull request

## Setup

Install from source:

```bash
git clone https://github.com/your-username/labarchives-api.git
cd labarchives-api
pip install -e .
```

## Making Changes

1. Create a feature branch:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. Make your changes following these guidelines:
   - Add type hints to all new code
   - Write tests for new features
   - Follow existing code style

3. Run tests:
   ```bash
   pytest
   ```

4. Format and lint your code:
   ```bash
   ruff format .
   ruff check --fix .
   ```

## Submitting a Pull Request

1. Commit your changes:
   ```bash
   git add .
   git commit -m "Add feature: description"
   ```

2. Push to your fork:
   ```bash
   git push origin feature/your-feature-name
   ```

3. Open a pull request on GitHub:
   - Describe your changes
   - Reference any related issues
   - Wait for review

## Code Style

- Use type hints on all functions and methods
- Follow PEP 8 style guidelines
- Keep code simple and readable
- Write docstrings for public APIs

## Questions?

- **Issues:** https://github.com/nimh-dsst/labarchives-api/issues
- **Discussions:** https://github.com/nimh-dsst/labarchives-api/discussions

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
