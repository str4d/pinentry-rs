# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to Rust's notion of
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). All versions prior
to 1.0.0 are beta releases.

## [Unreleased]
- MSRV has been increased to 1.65.0
- Migrated to `nom 8`, `which 5`.

## [0.6.1] - 2026-01-03
### Added
- Support for configuring Unix-specific pinentry options, behind `#[cfg(unix)]`:
  - `pinentry::unix` module.
  - `pinentry::ConfirmationDialog::with_unix_options`
  - `pinentry::MessageDialog::with_unix_options`
  - `pinentry::PassphraseInput::with_unix_options`

### Fixed
- Zombie processes are now avoided by waiting for the child process to terminate.

## [0.6.0] - 2024-11-03
- MSRV has been increased to 1.60.0
- Bumped `secrecy` crate to 0.10

## [0.5.1] - 2024-08-31
### Fixed
- Client requests are now correctly percent-encoded when necessary.

## [0.5.0] - 2021-08-28
- Bumped `nom` crate to 7.*

## [0.4.0] - 2021-08-03
- MSRV has been increased to 1.51.0
- Bumped `secrecy` crate to 0.8

## [0.3.0] - 2021-01-11
- MSRV has been increased to 1.44.0
- Bumped `nom` crate to 6.*

## [0.2.0] - 2020-07-13
- MSRV has been increased to 1.39.0
- Percent-encoded responses are now correctly handled.
- Bumped `secrecy` crate to 0.7

## [0.1.0] - 2020-01-30

Initial release!
