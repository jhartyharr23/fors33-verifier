# Changelog

All notable changes to fors33-verifier are documented here.

## [0.3.0] - 2026-03-10

### Added

- **--root**: Primary flag for target directory; --target-dir retained as deprecated alias.
- **Multi-root manifest support**: JSON manifests with `roots` and per-file `root_index`; backward compatible.
- **Digest key bridge**: manifest_core accepts `digest`, `hash`, or `checksum` JSON keys.
- **Generator manifest ingestion**: GNU/BSD parsers remain generators; no full manifest materialization.
- **Environment variables**: FORS33_ALGO, FORS33_ROOT, FORS33_FOLLOW_SYMLINKS, FORS33_IGNORE_PATTERN, FORS33_EXCLUDE_DIR.
- **ANSI color hierarchy**: [VERIFIED] green, [MISMATCH]/[TAMPERED] bold red, [SKIPPED] dim gray (TTY only).
- **Forensic hand-off**: Mutated-during-hash messages suggest active log vs tampering.
- **--force-insecure**: Override to allow MD5/SHA-1 in manifests (rejected by default).
- **[SYS] Building manifest tree...**: Initialization pulse at manifest verify start.
- **Blake3 fail-fast**: Exit with clear error if --algo blake3 requested but blake3 not installed.
- **Ctrl+C handling**: ThreadPoolExecutor wrapped for responsive KeyboardInterrupt (exit 130).

### Changed

- Progress bar: `\r\033[K[VERIFY] Hashing {rel}: {pct}%` for glitch-free display.
- Quiet CTA: `[TOOLCHAIN] : FORS33 Data Provenance Kit`.
- Repositioned as agnostic high-speed data-integrity utility in LLM_CONTEXT.

### Security

- MD5/SHA-1 rejected by default; use --force-insecure for legacy manifests.

## [0.2.0] - 2026-03-02

### Added

- **Manifest mode**: Verify directories against GNU/BSD-style checksum files or JSON manifests. Detects `modified`, `created`, `deleted`, `mutated_during_verification`, and `skipped` files.
- **Sidecar mode**: Walk a directory tree and verify `.f33`, `.sha256`, `.sha512`, and `.md5` sidecars in place.
- **Ignore patterns**: Root-level `.f33ignore` and CLI `--ignore-pattern` / `--exclude-dir` for excluding files from verification.
- **Symlinks**: `--follow-symlinks` to traverse symlinked directories (default: no symlink traversal).
- **Warn-only mode**: `--warn-only` reports drift without exiting non-zero.
- **Progress indicator**: In-place progress for large files (≥500MB) when stderr is a TTY.
- **Bounded concurrency**: ThreadPoolExecutor with configurable worker count for parallel hashing.
- **Standardized stderr**: `[WARNING]` / `[ERROR]` prefixes; machine-readable output on stdout only.
- **Exit codes**: Exit 2 for misuse, 1 for drift (0 when `--warn-only`).

### Changed

- Chunk size fixed at 4MB for hashing.
- Manifest parsing supports both `file`/`path` and `hash`/`checksum` JSON keys.
- GNU fast-path preserves filenames with leading spaces or `*`.

### Dependencies

- `cryptography>=41.0` (required). Optional `blake3` for faster hashing.

### Support matrix

- Python 3.9, 3.10, 3.11, 3.12
- Linux, macOS, Windows
