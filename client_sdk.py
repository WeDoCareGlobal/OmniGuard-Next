"""Synchronous client for the OmniGuard inspection gateway (not an LLM provider)."""
import json
import urllib.error
import urllib.request


class OmniGuardError(RuntimeError):
    """A rejected, unavailable or malformed gateway response."""


class OmniGuardClient:
    def __init__(self, base_url, api_key=None, timeout=30):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout

    def _request(self, endpoint, data=None, root=False):
        base = self.base_url.removesuffix("/v1") if root else self.base_url
        headers = {"Accept": "application/json"}
        if self.api_key:
            headers["X-API-Key"] = self.api_key
        payload = None
        if data is not None:
            headers["Content-Type"] = "application/json"
            payload = json.dumps(data).encode("utf-8")
        request = urllib.request.Request(
            f"{base}/{endpoint.lstrip('/')}", data=payload, headers=headers,
            method="POST" if data is not None else "GET",
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                result = json.loads(response.read().decode("utf-8"))
                if not isinstance(result, dict):
                    raise OmniGuardError("Malformed gateway response")
                if data is not None and (
                    response.status != 200
                    or response.headers.get("X-Governance-Decision") != "ALLOW"
                ):
                    raise OmniGuardError("Gateway did not explicitly allow this request")
                return result
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            try:
                error = json.loads(body)
                reason = error.get("block_reason") or error.get("error") or error.get("detail")
            except (ValueError, AttributeError):
                reason = "Gateway rejected request"
            raise OmniGuardError(f"HTTP {exc.code}: {reason}") from exc
        except (urllib.error.URLError, TimeoutError, ValueError) as exc:
            raise OmniGuardError("Gateway unavailable or response invalid") from exc

    def chat_completion(self, messages, model="omniguard-2.0", temperature=0.7):
        return self._request("chat/completions", {
            "model": model, "messages": messages, "temperature": temperature,
        })

    def health_check(self):
        return self._request("healthz", root=True)

    def get_metrics(self):
        return self._request("metrics", root=True)
