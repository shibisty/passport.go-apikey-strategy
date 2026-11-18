# Changelog

## Unreleased

## 0.2.1 — 2026-11-19

### Fixed
- Keys whose random part contains "_" (about half of them: base64url) were refused as
  malformed: the prefix was taken up to the last "_". It now ends 44 characters from the end.

### Changed
- Renamed from `passport-apikey` to `@passport/apikey` (gtr ADR-0012): `gtr add @passport/apikey`, `import "passport/apikey"`; published to the gtr registry. Dependencies on other passport packages are registry ranges (`^0.2`) instead of `github:` sources.

## 0.1.1 — 2026-11-09

### Changed
- Requires `passport ^0.2` (the first published release of the core; `^0.1` matched no tag).

### Added
- The `passport-apikey` package.
