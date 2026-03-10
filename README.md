# rediver-gitleaks

[Rediver](https://rediver.ai) integration for [gitleaks](https://github.com/zricethezav/gitleaks).


Scans git repositories for hardcoded secrets (API keys, tokens, passwords) and reports findings to the Rediver platform.

## Quick Start

### Docker (recommended)

```bash
docker run --rm \
  -e REDIVER_TOKEN=your-cluster-token \
  -e MODE=ci \
  ghcr.io/califio/rediver-gitleaks:latest
```

### Binary

```bash
go install github.com/califio/rediver-gitleaks@latest

REDIVER_TOKEN=your-cluster-token rediver-gitleaks
```

## Getting REDIVER_TOKEN

1. Log in to [Rediver](https://app.rediver.ai)
2. Go to **Agent Clusters** page: `https://app.rediver.ai/tenant/{your-tenant}/agents`
3. Create a new agent cluster (or select an existing one)
4. Copy the generated token — this is your `REDIVER_TOKEN`

## Configuration

All options can be set via CLI flags or environment variables.

| Env Variable | Flag | Default | Description |
|-------------|------|---------|-------------|
| `REDIVER_URL` | `--url` | `https://api.rediver.ai` | Rediver API URL |
| `REDIVER_TOKEN` | `--token` | _(required)_ | Cluster authentication token |
| `MODE` | `--mode` | `ci` | Run mode: `worker`, `ci`, or `task` |
| `MAX_CONCURRENT_JOB` | `--max-concurrent-job` | `10` | Max parallel scan jobs |
| `POLLING_INTERVAL` | `--polling-interval` | `10` | Poll interval in seconds (worker mode) |
| `REPO_DIR` | `--repo-dir` | | Override repository directory |
| `FULL_HISTORY` | `--full-history` | `false` | Scan all commits instead of only HEAD |
| `VERBOSE` | `--verbose` | `false` | Show detailed output with redacted secrets |

### Run Modes

- **`worker`** — Long-running process that polls for scan jobs
- **`ci`** — Auto-detects CI environment, scans the current repo, exits
- **`task`** — Runs a single assigned job, then exits

## Scanner Parameters

These parameters are configurable per scan job from the Rediver platform:

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `full_history` | bool | `false` | Scan all git commits instead of only HEAD |
| `verbose` | bool | `false` | Detailed output with 20% secret redaction |

## CI/CD Integration

### GitHub Actions

Add to `.github/workflows/gitleaks.yml` in your repository:

```yaml
name: Secret Scan

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  gitleaks:
    runs-on: ubuntu-latest
    container:
      image: ghcr.io/califio/rediver-gitleaks:latest
      env:
        REDIVER_TOKEN: ${{ secrets.REDIVER_TOKEN }}
        MODE: ci
        FULL_HISTORY: false
```

To scan full git history on the default branch only:

```yaml
jobs:
  gitleaks:
    runs-on: ubuntu-latest
    container:
      image: ghcr.io/califio/rediver-gitleaks:latest
      env:
        REDIVER_TOKEN: ${{ secrets.REDIVER_TOKEN }}
        MODE: ci
        FULL_HISTORY: ${{ github.event_name == 'push' && github.ref == 'refs/heads/main' }}
```

### GitLab CI

Add to `.gitlab-ci.yml` in your repository:

```yaml
gitleaks:
  stage: test
  image:
    name: ghcr.io/califio/rediver-gitleaks:latest
    entrypoint: [""]
  variables:
    REDIVER_TOKEN: $REDIVER_TOKEN
    MODE: ci
    FULL_HISTORY: "false"
  script:
    - /usr/bin/rediver-gitleaks
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
```

To scan full history only on the default branch:

```yaml
gitleaks:
  stage: test
  image:
    name: ghcr.io/califio/rediver-gitleaks:latest
    entrypoint: [""]
  variables:
    REDIVER_TOKEN: $REDIVER_TOKEN
    MODE: ci
  script:
    - /usr/bin/rediver-gitleaks
  rules:
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
      variables:
        FULL_HISTORY: "true"
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
      variables:
        FULL_HISTORY: "false"
```

> **Note:** Add `REDIVER_TOKEN` as a CI/CD variable in your project settings (GitHub: repository secrets, GitLab: Settings → CI/CD → Variables).

## Development

```bash
# Run tests
go test -v ./...

# Build
go build -o rediver-gitleaks

# Run locally with .env
cp .env.example .env  # edit with your token
go run .
```

## License

Proprietary — see [Rediver](https://rediver.ai) for licensing details.
