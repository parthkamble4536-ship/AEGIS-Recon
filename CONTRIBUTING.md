# Contributing to AEGIS-Recon

Thank you for considering contributing! Please read this guide before opening
a pull request.

## Scope

AEGIS-Recon is a **defensive authorized-security-assessment tool**. Contributions
must stay within this scope. We will not accept:

- Auto-exploitation features
- Credential-brute-force features
- Evasion / stealth scan features
- Kubernetes, message queues, blockchain, or other infrastructure bloat
- Microservice rewrites of existing functionality

## Development Setup

```bash
python -m venv venv
venv\Scripts\activate       # Windows
# source venv/bin/activate  # Linux/macOS
pip install -r requirements.txt
pip install -r requirements-dev.txt
```

## Running Tests

```bash
pytest tests/ -q --tb=short -m "not integration"
```

All new features **must include tests**. The test count should increase with every PR.

## Code Quality

Before submitting a PR, run:

```bash
ruff check .          # Lint
ruff format .         # Format
bandit -r app/ -c pyproject.toml -q   # Security scan
```

All checks must pass with exit code 0.

## Safety Rules

1. **Never** allow `version match == confirmed vulnerability`. Always use `hypothesis` evidence type.
2. **Never** let missing EPSS equal `0.0`. Unavailable data must be `None`.
3. **Never** add `shell=True` to any subprocess call.
4. **Never** fabricate test results, CVE data, benchmarks, or metrics.
5. **Always** add `# nosec B###` (Bandit) and `# noqa: S###` (ruff) on the same line for intentional suppressions.

## Pull Request Checklist

- [ ] New feature has unit tests
- [ ] `ruff check .` passes
- [ ] `bandit -r app/ -c pyproject.toml -q` passes
- [ ] All existing tests still pass
- [ ] No fabricated data, metrics, or CVEs
- [ ] CHANGELOG.md updated

## Commit Message Convention

```
type(scope): short description (N tests passing)
```

Types: `feat`, `fix`, `docs`, `test`, `refactor`, `chore`, `security`

Examples:
```
feat(p5): Scan Diff engine (418 tests passing)
fix(intel): Handle malformed CPE strings gracefully
security(ai): Block prompt injection in CVE analysis
```

