# SPDX-FileCopyrightText: Christian Amsüss and the aiocoap contributors
# SPDX-License-Identifier: MIT

import os
import sys
from pathlib import Path
from urllib.parse import urlparse
import asyncio
import signal
import json
import urllib.request
import urllib.error

import aiocoap
from aiocoap.proxy.server import ProxyWithPooledObservations, UnconditionalRedirector
from aiocoap.util import hostportsplit


class HttpPSKCredentials(aiocoap.credentials.CredentialsMap):
    """DTLS-PSK 凭据动态获取器：用客户端的 identity 作为序列号调用 HTTP API。"""

    def __init__(self, api_url: str, timeout: float = 5.0):
        super().__init__()
        self.api_url = api_url
        self.timeout = timeout
        self._cache = {}

    @staticmethod
    def _identity_to_serial(identity) -> str:
        if isinstance(identity, bytes):
            try:
                return identity.decode("ascii")
            except UnicodeDecodeError:
                return ""
        return str(identity or "")

    def _fetch_psk(self, serial: str) -> bytes:
        payload = json.dumps({"serialNumber": serial}).encode("utf-8")
        req = urllib.request.Request(
            self.api_url,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        psk_str = data.get("psk")
        if not psk_str:
            raise KeyError(f"PSK API 未返回 psk 字段，serial={serial}")
        try:
            return bytes.fromhex(psk_str)
        except ValueError:
            return psk_str.encode("utf-8")

    def find_dtls_psk(self, identity):
        serial = self._identity_to_serial(identity)
        if not serial:
            raise KeyError("无法从 identity 解出序列号")

        if serial in self._cache:
            return (self._cache[serial], f"serial:{serial}")

        try:
            psk_bytes = self._fetch_psk(serial)
        except (urllib.error.URLError, urllib.error.HTTPError, KeyError, json.JSONDecodeError) as e:
            raise KeyError(f"PSK 获取失败: {e}") from e

        self._cache[serial] = psk_bytes
        return (psk_bytes, f"serial:{serial}")


async def run_proxy():
    backend = os.environ.get("BACKEND_URI")
    if not backend:
        sys.exit("Environment variable BACKEND_URI is required, eg. coap://upstream:5683")

    parsed = urlparse(backend)
    if parsed.scheme != "coap":
        sys.exit("BACKEND_URI 必须是明文后端，形如 coap://host[:port]")
    if not parsed.netloc:
        sys.exit("BACKEND_URI must include a host (and optional port)")

    bind = os.environ.get("BIND", ":5684")
    psk_api_url = os.environ.get("PSK_API_URL")
    if not psk_api_url:
        sys.exit("必须提供 PSK_API_URL，用于通过序列号获取 DTLS PSK")

    # Ensure DTLS server transport is enabled
    os.environ.setdefault("AIOCOAP_DTLSSERVER_ENABLED", "1")

    # Parse bind
    try:
        host, port = hostportsplit(bind)
    except ValueError as e:
        sys.exit(f"无效的 BIND: {e}")
    bind_tuple = (host, port)

    # Outgoing client (to upstream)
    outgoing_context = await aiocoap.Context.create_client_context()

    # Reverse proxy
    proxy = ProxyWithPooledObservations(outgoing_context)
    proxy.add_redirector(UnconditionalRedirector(backend))

    # Dynamic DTLS-PSK credentials for inbound clients
    server_credentials = HttpPSKCredentials(psk_api_url)

    server_context = await aiocoap.Context.create_server_context(
        proxy, bind=bind_tuple, server_credentials=server_credentials
    )

    stop_event = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, stop_event.set)

    await stop_event.wait()

    await server_context.shutdown()
    await outgoing_context.shutdown()


def main() -> None:
    asyncio.run(run_proxy())


if __name__ == "__main__":
    main()

