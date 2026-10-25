"""Model discovery for API-key protocols; never used for ChatGPT OAuth."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import httpx

from tesis.provider_registry import API_PROTOCOLS, validate_api_url
from llm.reasoning import advertised_efforts


class ModelCatalogError(ValueError):
    """An endpoint did not provide a usable complete model catalog."""


def catalog_url(base_url: str, protocol: str, fetch_url: str = "") -> str:
    if protocol not in API_PROTOCOLS:
        raise ModelCatalogError("This protocol does not support API-key model discovery.")
    if fetch_url:
        return validate_api_url(fetch_url)
    parsed = urlsplit(validate_api_url(base_url))
    path = parsed.path.rstrip("/")
    if protocol == "anthropic" and not path.endswith("/v1"):
        path += "/v1"
    return urlunsplit((parsed.scheme, parsed.netloc, path + "/models", parsed.query, ""))


def fetch_models(*, base_url: str, protocol: str, api_key: str, fetch_url: str = "",
                 transport: httpx.BaseTransport | None = None,
                 cancelled: Callable[[], bool] = lambda: False) -> list[dict]:
    """Read the configured endpoint, following cursor pages on the same URL.

    Redirects are deliberately disabled: credentials belong to the explicitly
    chosen fetch URL. Errors exclude response bodies and request credentials.
    """
    url = catalog_url(base_url, protocol, fetch_url)
    headers = {"Accept": "application/json"}
    if api_key:
        if protocol == "anthropic":
            headers["x-api-key"] = api_key
        else:
            headers["Authorization"] = f"Bearer {api_key}"
    if protocol == "anthropic":
        headers["anthropic-version"] = "2023-06-01"
    models: dict[str, dict[str, Any]] = {}
    cursors: set[str] = set()
    try:
        with httpx.Client(transport=transport, timeout=20, follow_redirects=False) as client:
            for _ in range(100):
                if cancelled():
                    raise ModelCatalogError("Model discovery cancelled.")
                response = client.get(url, headers=headers)
                if not response.is_success:
                    raise ModelCatalogError(f"Model discovery returned HTTP {response.status_code}. Check the fetch URL, protocol, and API key; manual model IDs are also supported.")
                payload = response.json()
                data = payload.get("data") if isinstance(payload, dict) else None
                if not isinstance(data, list):
                    raise ModelCatalogError("The catalog must contain a data array of model objects. Add model IDs manually if listing is unsupported.")
                for item in data:
                    model_id = item.get("id") if isinstance(item, dict) else None
                    if not isinstance(model_id, str) or not model_id or any(c.isspace() or ord(c) < 32 for c in model_id):
                        raise ModelCatalogError("The catalog contains an invalid model ID.")
                    display = str(item.get("display_name") or model_id)
                    models.setdefault(model_id, {"id": model_id, "display_name": display})
                    efforts = advertised_efforts(item)
                    if efforts is not None:
                        models[model_id]["reasoning_efforts"] = efforts
                if not payload.get("has_more"):
                    return list(models.values())
                cursor = payload.get("last_id") or (data[-1].get("id") if data else None)
                if not isinstance(cursor, str) or not cursor or cursor in cursors:
                    raise ModelCatalogError("The model catalog returned an invalid pagination cursor.")
                cursors.add(cursor)
                parsed = urlsplit(url)
                query = dict(parse_qsl(parsed.query, keep_blank_values=True))
                query["after_id" if protocol == "anthropic" else "after"] = cursor
                url = urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urlencode(query), ""))
        raise ModelCatalogError("The catalog exceeded 100 pages; narrow the fetch URL or add models manually.")
    except ModelCatalogError:
        raise
    except (httpx.HTTPError, ValueError, TypeError) as exc:
        raise ModelCatalogError("Unable to load the model catalog. Check connectivity, URL, and credentials, or add models manually.") from None
