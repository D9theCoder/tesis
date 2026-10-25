# API providers with multiple models

Settings can register multiple API providers, each with its own endpoint,
credential, protocol, and selected models. Existing `models` profiles continue
to work. `openai_codex_auth` uses the separate
[ChatGPT sign-in flow](sign_in_with_chatgpt.md).

## TUI setup

1. Open `/settings`, expand **Model profile**, and choose **Add API provider**.
2. Enter a unique provider ID, an optional display name, a base URL, a protocol,
   and an API key. IDs begin with a lowercase letter and accept lowercase
   letters, digits, underscores, and hyphens, up to 64 characters. An empty
   display name becomes the provider ID.
3. Choose **Fetch available models**. The optional **Fetch URL** overrides the
   default catalog URL. Search by ID or display name, move with the arrow keys,
   and press Space or Enter to toggle a model. **Select shown** and
   **Ignore shown** affect only the filtered rows. A checked row has `x` in
   its Use column.
4. Add unlisted models with **Manual model ID** and **Add model**. Exact model
   IDs are also supported when the endpoint cannot list models. Saved/manual
   IDs survive a catalog refresh; newly fetched models start unchecked.
5. Choose **Apply provider**, then **Save** in Settings. Apply stages the draft;
   Save validates and writes it. Cancel/Escape discards changes in the provider
   form. Closing Settings without saving discards staged keys.
6. Open `/run` or `/matrix`. Select the provider/model pair under **Provider**
   or **Providers**. Each selected model has its own coordinate and artifact
   identity. Explicit global/role model-profile overrides retain their existing
   precedence; clear those pins when comparing models across matrix coordinates.

To add models later, select the saved API provider and choose
**Edit provider / models**. Uncheck models to remove them from future pickers.
Update any default or role profile that references a removed model before
saving. Provider IDs are permanent; add a new entry to use a different ID.

The form uses one scrolling column with fixed Apply/Cancel actions at 80×24
and at 60×18. Below 80 columns the drawer takes the full width. Below 60×18 the
app displays its existing terminal-size notice. Catalog rows use a virtualized
table, and network requests and Settings file writes run outside the UI loop.

## Protocols and discovery

| Protocol value | Inference | Default catalog | Catalog authentication |
| --- | --- | --- | --- |
| `openai` | OpenAI Responses | `<base_url>/models` | Bearer API key |
| `openai_compatible` | OpenAI Chat Completions | `<base_url>/models` | Bearer API key |
| `anthropic` | Anthropic Messages | `<base_url>/v1/models`, or `<base_url>/models` if the base already ends in `/v1` | `x-api-key`, `anthropic-version: 2023-06-01` |

For example, an OpenAI base URL is `https://api.openai.com/v1`. An Anthropic
base URL can be `https://api.anthropic.com` or `https://api.anthropic.com/v1`;
the adapter normalizes the version suffix before invoking the SDK.

Catalogs must return a JSON `data` array containing model objects with `id`
and optionally `display_name`. Discovery follows `has_more` cursor pages using
`last_id`, with `after_id` for Anthropic and `after` for OpenAI-compatible
pagination extensions. Duplicate IDs are removed without reordering the
catalog. A malformed page, looping cursor, or more than 100 pages produces an
error instead of presenting a truncated catalog as complete.

Discovery has no model allowlist. Listing a model does not establish that it
supports text generation, the selected wire protocol, structured output,
reasoning settings, or the experiment's token budget. Select suitable models;
provider capability errors follow the existing runtime diagnostics.

Fetches use the URL and key currently in the form, or the provider's saved key.
A custom Fetch URL receives that credential. Redirects are disabled. Timeout,
authentication, malformed JSON, and unsupported listing errors leave manual
model entry available and do not echo response bodies or credentials.

## Configuration and keys

The new optional registry is separate from the existing `providers` matrix
selector and `models` profile mapping:

```yaml
api_providers:
  lab_gateway:
    display_name: Lab gateway
    protocol: openai_compatible
    base_url: https://gateway.example/v1
    fetch_url: https://gateway.example/v1/models  # optional
    api_key: ${LAB_GATEWAY_API_KEY}
    models:
      - vendor/model-a
      - vendor/model-b
```

Put `LAB_GATEWAY_API_KEY='your-key'` in the `.env` beside the configuration
file. The TUI generates a distinct environment variable for each provider and
saves entered keys there. YAML receives only `${VARIABLE}` references.
Credentials remain write-only in the form: leave the key input blank to retain
the saved key. Saving preserves unrelated dotenv entries/comments, uses mode
0600 and atomic replacement, validates before writes, and restores the previous
dotenv contents if replacing YAML fails. A symlinked `.env` is rejected.
Process environment variables take precedence on load; a key explicitly changed
in Settings also updates the running process after a successful save.

Each selected model expands into a stable profile ID of the form
`<provider_id>__<model-slug>_<12-character-hash>`. The hash preserves distinct
IDs when gateway names differ in case or punctuation. The TUI displays
`<display name> / <model ID>`. Headless `--provider`, matrix `--providers`,
`--model-profile`, and role-profile selectors accept these generated profile
IDs. To inspect their exact spelling without making network calls:

```bash
.venv/bin/python - <<'PY'
from tesis.config_loader import load_and_resolve_config
config = load_and_resolve_config(config_path="config.yaml", cli_args={})
for profile_id, profile in config.models.items():
    print(profile_id, profile.provider, profile.model_name)
PY
```

Provider entries also accept shared `temperature`, `timeout`, `max_tokens`,
`reasoning_effort`, and `extra` options. New `openai` entries explicitly enable
Responses with `store: false`; new `openai_compatible` entries explicitly select
Chat Completions. Historical profiles retain their configured behavior.

## Independent AI evaluator

`scoring_evaluator.provider` accepts the same provider/model profile ID as the
run `provider` and matrix `providers` selectors:

```yaml
scoring_mode: ai
scoring_evaluator:
  provider: tokenharbor__deepseek-v4-1-flash_eb1394ac7fc4
  max_attempts: 2
  max_tokens: 1024
  timeout: 60
```

The example ID requires the matching `api_providers.tokenharbor` entry and
selected model. The provider entry owns its endpoint, credential, API protocol,
and model list. Here `provider` selects one registered provider/model pair;
`openai`, `openai_compatible`, and `anthropic` name wire protocols in the registry.
The evaluator's model, endpoint, credentials, and protocol resolve from that
selection. Its review attempts, token limit, and timeout remain independent.
Switching the experiment's model does not switch the evaluator.

In `/settings`, expand **AI evaluator**, choose the review mode and **Evaluator
provider / model**, and inspect its API format and endpoint. Set the review
limits, choose **Apply evaluator**, then **Save** in Advanced YAML. Choices
include registered models and standalone profiles, including configured ChatGPT
sign-in profiles. Add or edit providers in **Model profile** first. New model
choices and edits in Advanced YAML refresh the evaluator choices. Applying
updates the draft; closing without Save discards it. Selecting or saving never
starts an experiment, model discovery, or evaluation.

New resolved evaluator records retain the selected provider/model ID as
`provider` and keep the execution `adapter` separately. Legacy evaluator
sections with an adapter `provider`, explicit `model`, and optional
`model_profile` still load with their historical resolved shape. When a profile
is selected, conflicting endpoint, credential, model, or protocol overrides are
rejected. Historical inline evaluators without a profile also remain supported.

Every new execution freezes the complete resolved evaluator settings. Changing
the provider/model, endpoint, or API format cannot silently regrade an existing
queue: evaluation requires an exact match with that queue's frozen evaluator.
Keep the original legacy configuration when reviewing an older artifact;
changing to the new selector creates a distinct frozen evaluator identity.

## Sources and validation scope

Discovery follows the official [OpenAI Models API](https://developers.openai.com/api/reference/resources/models/methods/list)
and [Anthropic Models API](https://platform.claude.com/docs/en/api/models/list).
The Anthropic header uses the SDK's existing supported version, described in
[API versioning](https://platform.claude.com/docs/en/api/versioning).
Responses routing uses the existing LangChain integration's documented
[`use_responses_api` setting](https://docs.langchain.com/oss/python/integrations/chat/openai#responses-api).
The provider form and explicit catalog selection were informed by
[DeepSeek Harness provider configuration](https://github.com/deepseek-ai/deepseek-harness/blob/master/docs/user/guide/providers.md).

Focused offline tests cover provider expansion and role resolution, separate
matrix identities, dotenv writes and rollback, paginated discovery and errors,
mocked inference requests for all three protocols, and keyboard-driven provider
widgets at 120×40, 80×24, and 60×18. No live provider calls or DVWA/E2E runs are
part of these checks. No browser authorization is needed for this API-key flow.
