# Changelog

## 0.1.1 (2026-11-24)

- Environment managed by uv: dev dependencies moved to `[dependency-groups].dev`, `uv.lock` committed,
  `.python-version` pinned to 3.12. Use `uv sync` and `uv run pytest -q`.
- CI uses `astral-sh/setup-uv` and `uv sync --locked`.
- Generated project READMEs show uv commands (pip still works).

## 0.1.0 (2026-11-24)

First release.

- Protocol spec format (`protoforge: 1`) with JSON Schema and semantic lint gates.
- `pf import`: camoufox-reverse-mcp export (schema_version 1) and HAR 1.2 to a draft spec; multi-sample field
  classification; upstream value detection (token/csrf echoed from earlier responses); JSON type and null preservation.
- `pf fixtures` / `pf verify [--record]`: offline signer verification with first-mismatch reporting; `--record`
  rewrites only the `verified:` line and keeps comments.
- Signer contract with python (R1), node (R2/R3) and http (R4/R5) adapters.
- `pf fp-check`: impersonate / User-Agent / client-hint consistency, nearest-target suggestion.
- `pf gen`: curl_cffi client project and Scrapy project (scrapy-impersonate), sharing one runtime.
  Rebuild-on-retry (fresh timestamps, nonces, signatures), stop on business rejection, result classes.
- `pf run-check`: bounded online check reporting S1/S2/S3; S4 never asserted from one run.
- `pf drift`: spec vs fresh capture, spec vs spec.
- Local demo site, capture, spec, signers, fixtures; end-to-end tests.
