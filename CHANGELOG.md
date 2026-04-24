# Changelog

All notable changes to `labapi` are documented here in release order.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [1.1.0] - Unreleased

### Added

- Lazy loading for interactive auth environment settings.
- Package typing metadata via `py.typed`.
- Zenodo citation metadata and a GitHub bug report template.
- Broader CI coverage for pushes and pull requests.

### Changed

- Reworked entry fallback handling and attachment loading.
- Refined the client authentication flow and browser detection.
- Simplified tree path handling and aligned the related docs.
- Refreshed release automation, project metadata, and publishing
  configuration.
- Updated `lxml`, `pillow`, `pytest`, `python-dotenv`, and the Python 3.10
  documentation toolchain.

### Fixed

- Restored datetime-based URL signing support.
- Hardened browser capability parsing for unexpected input types.
- Improved `Attachment.from_file()` support for random-access binary streams
  that do not expose `seekable()`.
- Fixed test compatibility issues, including dotenv cache handling in client
  initialization tests.

## [1.0.3] - 2026-04-15

### Changed

- Refined the client auth flow and browser detection behavior.
- Simplified tree path handling.
- Switched the `1.0` type-check workflow from `mypy` to `ty`.
- Refreshed package metadata, README content, and Zenodo configuration.
- Updated `pillow` and `pytest`.

### Fixed

- Restored datetime-based URL signing support.
- Improved browser detection robustness when detectable values arrive with
  incorrect types.
- Fixed test compatibility issues in the `1.0` maintenance branch.
- Reduced tree creation complexity in the `v1.0.3` stabilization pass.

## [1.0.2] - 2026-04-10

### Changed

- Cleaned up the PyPI README and related package metadata.

## [1.0.1] - 2026-04-10

### Added

- Initial TestPyPI publishing workflow.
- GitHub issue templates.
- Reusable GitHub Actions checks and broader local tooling support.

### Changed

- Improved versioning and generated documentation metadata.
- Refreshed contributor and Sphinx configuration docs.
- Updated `cryptography`, `pygments`, and `requests`.

## [1.0.0] - 2026-04-01

### Added

- Initial stable release of `labapi`.
- Support for LabArchives authentication, notebook tree traversal, and
  page and entry operations from Python.
- Project documentation and example workflows for common notebook automation
  tasks.

[1.1.0]: https://github.com/nimh-dsst/labapi/compare/v1.0.3...1.1
[1.0.3]: https://github.com/nimh-dsst/labapi/compare/v1.0.2...v1.0.3
[1.0.2]: https://github.com/nimh-dsst/labapi/compare/v1.0.1...v1.0.2
[1.0.1]: https://github.com/nimh-dsst/labapi/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/nimh-dsst/labapi/tree/v1.0.0
