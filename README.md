# TESIS

LLM-assisted autonomous penetration-testing experiments for an authorized DVWA sandbox. The framework is restricted to SQL injection, access control, and brute force, with a static payload-aware Attack Knowledge Graph and fixed method agents.

## Quick start

From the repository root:

```bash
uv sync
uv run tesis run
```

This opens mission control and reads the repository-root `config.yaml`. Use `uv run tesis run --dry-run` for local configuration checks. See the [usage guide](guide.md) for headless runs, Doctor, and detailed operation; see [architecture](docs/reference/architecture.md) and [methodology and artifact schema](docs/reference/summary_en.md) for research references. Scoped validation guidance is in [AGENTS.md](AGENTS.md).

For multiple API providers and models, open **Settings → Model profile → Add API
provider**. Configure Responses, Chat Completions, or Anthropic Messages, fetch
and select models, and save API keys to `.env`. See the
[provider setup guide](docs/reference/api_providers.md).

## Mission control quick reference

Mission control requires a TTY of at least 60x18. At 120x24 or wider, pipeline, coordinates, and evidence are visible together; smaller layouts collapse panes into drawers.

Press `/`, `:`, or Ctrl+P to open the command launcher. `/run` and `/matrix` open the guided launcher; Review freezes the request and is the only step with Start. Available commands include `run`, `matrix`, `plan`, `cancel`, `coordinates`, `evidence`, `failure`, `trace`, `doctor`, `results`, `settings`, `export`, `about`, `help`, and `quit`.

Keys: `r` single run; `m` matrix; `p` plan; `d` Doctor; `1`/`2`/`3` pipeline/coordinates/evidence; Tab changes focus; Enter inspects; `?` shows help; `q` quits while idle. Ctrl+C requests cancellation; after the active LLM or HTTP call returns, no later graph or matrix work is scheduled. Press Ctrl+C again to close if an active call is stuck.

## Results and artifact identity

The results drawer reads historical and current JSON artifacts, ignores malformed files, supports metadata filters, and offers triage export (`Export JSON` writes `tui-results-export.json`). Historical artifacts are read without rewriting; existing flat artifacts remain untouched.

Each new execution records:

- `execution_id`: unique physical artifact identity and filename.
- `run_id`: stable logical experiment coordinate retained for analysis.
- `config_fingerprint`: secret-free hash of effective experiment setup, excluding timestamps, output paths, execution identity, and repeat index.

Repeated fingerprints are marked `SAME CONFIG ×N`. New TUI and headless runs are grouped under `results/runs` in `single-run-YYYY-MM-DD` or `matrix-YYYY-MM-DD` directories. Each matrix folder contains one coordinate folder per run and an `experiment.manifest.json` index; same-day collisions receive a numeric suffix.
