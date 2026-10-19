"""
OmniGuard Client SDK
Zero-dependency Python client for integrating with OmniGuard gateway.
Usage:
    from omnisdk import OmniGuardClient
    client = OmniGuardClient(base_url="http://localhost:8000/v1")
    response = client.chat_completion(messages=[{"role": "user", "content": "Hello"}])
"""

import json
import urllib.request
from typing import List, Dict, Any, Optional


class OmniGuardClient:
    def __init__(self, base_url: str, api_key: Optional[str] = None):
        """
        Initialize the OmniGuard client.
        :param base_url: Base URL of the OmniGuard gateway (e.g., "http://localhost:8000/v1")
        :param api_key: Optional API key for authentication
        """
        self.base_url = base_url.rstrip('/')
        self.api_key = api_key

    def _request(self, endpoint: str, data: dict) -> dict:
        url = f"{self.base_url}/{endpoint.lstrip('/')}"
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        req = urllib.request.Request(url, data=json.dumps(data).encode('utf-8'), headers=headers, method='POST')
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return json.loads(resp.read().decode('utf-8'))
        except urllib.request.HTTPError as e:
            error_body = e.read().decode('utf-8') if e.read() else ''
            raise Exception(f"HTTP {e.code}: {error_body}")
        except Exception as e:
            raise Exception(f"Request failed: {e}")

    def chat_completion(self, messages: List[Dict[str, str]], model: str = "omniguard-0.1", temperature: float = 0.7) -> dict:
        """
        Send a chat completion request through the OmniGuard gateway.
        :param messages: List of message dicts with 'role' and 'content'
        :param model: Model name (default: omniguard-0.1)
        :param temperature: Sampling temperature (default: 0.7)
        :return: Response dict from the gateway
        """
        data = {
            "model": model,
            "messages": messages,
            "temperature": temperature
        }
        return self._request("chat/completions", data)

    def health_check(self) -> dict:
        """
        Check the health of the OmniGuard gateway.
        :return: Health check response
        """
        return self._request("healthz", {})

    def get_metrics(self) -> str:
        """
        Get Prometheus metrics from the gateway.
        :return: Metrics as plain text
        """
        url = f"{self.base_url}/metrics"
        req = urllib.request.Request(url, headers={"Accept": "text/plain"})
        if self.api_key:
            req.add_header("Authorization", f"Bearer {self.api_key}")
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                return resp.read().decode('utf-8')
        except Exception as e:
            raise Exception(f"Failed to fetch metrics: {e}")
