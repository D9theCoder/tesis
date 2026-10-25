# Sign in with ChatGPT

`openai_codex_auth` is an additional provider using official Sign in with
ChatGPT (SIWC). Existing `openai`, `openai_compatible`, Gemini, and Claude
profiles keep their authentication paths. The provider name does not imply
Codex CLI credential sharing: TESIS registers its own OAuth client and uses
the public OpenAI Responses API.

## Connect an account

Install the locked dependencies and start browser sign-in on the computer
running TESIS:

```bash
uv sync
.venv/bin/python -m tesis auth login --account default
.venv/bin/python -m tesis auth status
.venv/bin/python -m tesis auth models --account default
```

The first command requiring your browser is `auth login`. Choose your ChatGPT
account and workspace, review the TESIS registration, and approve ChatGPT plan
usage. The listener binds only to `127.0.0.1` at `/auth/callback`, with an
available port. `--port PORT` selects a port and `--no-browser` prints a one-time
URL without a retained identity token. Complete it within five minutes. Cancel
with Ctrl+C. An SSH session needs a browser on that host or an SSH tunnel for
the chosen loopback port; the callback still uses `127.0.0.1`.

Use distinct local labels, such as `--account personal` and `--account lab`,
for different registrations. Reusing a label reauthorizes that registration
and checks the verified identity before replacing tokens. Duplicate email
addresses do not merge registrations. If identity sign-in succeeds without
plan permission, TESIS saves the connection and disables inference. To request
permission again explicitly:

```bash
.venv/bin/python -m tesis auth login --account default --enable-plan-usage
```

## Choose a model and provider

Open the TUI with `.venv/bin/python -m tesis run`, then `/settings` and expand
**Model profile**. Choose the ChatGPT profile and saved account label. Press
**Refresh OpenAI models**, select a model, press **Use selected model**, then
**Save** in Advanced YAML. This creates the provider profile if needed.

Choices come from the selected account's `GET /v1/models` response. The picker
shows every entry with `visibility: list`, preserves server ordering, displays
`display_name`, and saves its `slug`. There is no bundled model list or default
model guess. Refresh to discover changes; changing accounts clears old choices.
Empty catalogs and failed requests leave the picker disabled. Fetches run in
a background worker and never start an experiment or inference request.

The equivalent profile, merged into your existing `models` mapping, is:

```yaml
models:
  openai_codex_auth:
    provider: openai_codex_auth
    model_name: ""  # Select an actual account model in Settings before running.
    timeout: 60
    reasoning_effort: null
    extra:
      account: default
```

In the launch drawer, explicitly select provider `openai_codex_auth` and the
matching model profile. Review any role-specific profile/model overrides,
which still take precedence. Adding or editing this profile does not select
it for existing experiments. Do not put an API key or OAuth token in YAML.
The adapter rejects API keys, alternate base URLs, unknown request overrides,
and hidden inference retries. There is no automatic billing fallback.
The provider is also excluded from implicit all-provider matrix defaults;
include it explicitly when defining a matrix.

## Storage, renewal, and sign-out

Credentials live in `$XDG_CONFIG_HOME/tesis/siwc/accounts.json`, defaulting to
`~/.config/tesis/siwc/accounts.json`. `TESIS_SIWC_HOME` overrides the private
directory. Keep it outside the repository, logs, and shared storage. On Unix,
the directory is `0700` and credential files are `0600`; symbolic links and
publicly readable credential files are rejected. File permissions protect
local storage; the JSON itself is not encrypted. On other systems, protect
the directory with the operating system's user access controls.

The stable host UUID is saved before authorization. Each account record keeps
its issued client ID, verified identity, granted scopes, expiry, and token set.
Writes use atomic replacement. A process lock serializes refresh and logout
against other TESIS processes using the same store. Inference gets credentials
at dispatch time; tokens never enter model configuration or run artifacts.
Access tokens refresh near expiry, respecting a supplied earliest-refresh
time. Refresh replaces the rotating token and expiry together. Terminal refresh
errors clear unusable tokens; temporary infrastructure errors preserve them.

```bash
.venv/bin/python -m tesis auth logout --account default
```

Sign-out attempts discovery-based refresh-token revocation with bounded retries,
then clears local access, refresh, and ID tokens. It retains the registration
and host ID for later sign-in. If remote revocation cannot be confirmed, the
command reports that fact and exits nonzero; disconnect TESIS in ChatGPT
Settings. Stop an active experiment before signing out.

## Availability and request limits

OpenAI currently describes plan usage for eligible Plus and Pro accounts,
open-source or local personal projects, and selected private apps. Workspace,
region, policy, and rollout restrictions can prevent admission. Paid or
remotely hosted applications have a separate interest process. Your browser
consent and successful account-specific requests establish actual access.
[Availability](https://developers.openai.com/cookbook/articles/sign-in-with-chatgpt),
[OSS scope](https://developers.openai.com/siwc/token-sharing-open-source).

TESIS requests `openid profile email offline_access resource.invoke
chatgpt.tokens.use.direct`. Inference requires the two resource/plan scopes,
uses `POST https://api.openai.com/v1/responses`, and sends `store: false`,
`stream: true`, full input context, and developer messages. SIWC credentials
cannot replace API keys in other provider profiles.
[Authorization](https://developers.openai.com/siwc/token-sharing-open-source/sign-in),
[inference](https://developers.openai.com/siwc/token-sharing-open-source/models-and-inference).

The SIWC preview rejects `temperature` and `max_output_tokens`, among other
fields. TESIS omits shared temperature/token-limit controls from this provider's
HTTP requests and records that limitation in provider call telemetry. The
configured request timeout still bounds network waits and is checked while
reading stream lines. Do not describe its output-token budget as equivalent to
providers that enforce `max_tokens`. The research conditions, candidate budgets,
payload validation, containment, agents, and scoring remain unchanged.
[Preview limitations](https://developers.openai.com/siwc/token-sharing-open-source/preview-limitations).

Only `response.completed` is successful. Incomplete output, interrupted streams,
refusals, admission failures, and streamed usage-limit errors remain distinct.
Errors retain sanitized status, code, parameter, body shape, and request ID.
Eligibility failures stop; usage-limit failures point to ChatGPT Settings >
Usage; transient failures preserve credentials for a later retry. No error
silently selects API-key billing.
[Recovery](https://developers.openai.com/siwc/token-sharing-open-source/errors-and-recovery),
[sessions](https://developers.openai.com/siwc/token-sharing-open-source/profiles-and-sessions).

## Focused validation

```bash
.venv/bin/python -m pytest -q tests/test_siwc.py tests/test_siwc_tui.py \
  tests/test_provider.py tests/test_reasoning_config.py tests/test_llm_runtime.py \
  tests/test_cli.py tests/test_config_loader.py tests/test_doctor.py \
  --junitxml=results/validation/junit.xml
```

These are isolated OAuth/storage/provider/runtime and Settings widget checks
using generated signing keys and mocked HTTP. They do not authorize or prove
a real account, subscription inference, DVWA execution, or E2E acceptance.
Real browser authorization is an operator step; no live call is made by the
test commands above.
