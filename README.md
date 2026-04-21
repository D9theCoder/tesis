# tesis

LLM-Based Autonomous Web Penetration Testing Framework (DVWA target) with a Stage 7 CLI interface for reproducible runs, config-driven execution, and report rendering.

## Quick start

- Configure your environment variables in `.env`.
- Ensure DVWA target is reachable.

## CLI usage

### Run a single engagement

`python -m tesis run --target http://localhost/dvwa --provider gemini --level low --iterations 30`

### Run matrix mode

`python -m tesis run --matrix --providers gemini --levels low medium high --repeats 2 --output-dir ./results`

### Validate config only

`python -m tesis run --dry-run --config ./config.yaml`

### Framework metadata

`python -m tesis info`

### Configure models interactively

`python -m tesis config --interactive`

### Configure provider/model directly

`python -m tesis config --set-provider gemini --model gemini-3-flash-preview`

### Render reports

`python -m tesis report ./results/runs/gemini-low-0.json --show-scores --show-rejections`

## Config file notes

`config.yaml` supports baseline execution settings and optional model settings:

- `target_url`
- `default_llm_provider`
- `default_security_level`
- `default_max_iterations`
- `llm_providers`
- `security_levels`
- `models.<provider>.model_name`
- `models.<provider>.api_key` (prefer `${ENV_VAR}` references)
- `models.<provider>.temperature`
- `models.<provider>.timeout`

Secrets are masked in CLI output and should be sourced from environment variables.
