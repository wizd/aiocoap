# SPDX-FileCopyrightText: Christian Amsüss and the aiocoap contributors
# SPDX-License-Identifier: MIT

import os
import sys
from urllib.parse import urlparse
import asyncio
import signal
import json
import urllib.request
import urllib.error
import socket
import logging

import aiocoap
from aiocoap.proxy.server import ProxyWithPooledObservations, UnconditionalRedirector
from aiocoap.util import hostportsplit, hostportjoin


class HttpPSKCredentials(aiocoap.credentials.CredentialsMap):
    """DTLS-PSK 凭据动态获取器：用客户端的 identity 作为序列号调用 HTTP API。"""

    def __init__(self, api_url: str, timeout: float = 5.0):
        super().__init__()
        self.api_url = api_url
        self.timeout = timeout
        self._cache = {}
        self._logger = logging.getLogger("proxy.psk")

    @staticmethod
    def _identity_to_serial(identity) -> str:
        if isinstance(identity, bytes):
            try:
                return identity.decode("ascii")
            except UnicodeDecodeError:
                return ""
        return str(identity or "")

    def _fetch_psk(self, serial: str) -> bytes:
        self._logger.debug("向 PSK API 请求序列号 %s", serial)
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
            self._logger.debug("PSK 命中缓存 serial=%s", serial)
            return (self._cache[serial], f"serial:{serial}")

        try:
            psk_bytes = self._fetch_psk(serial)
        except (urllib.error.URLError, urllib.error.HTTPError, KeyError, json.JSONDecodeError) as e:
            self._logger.warning("PSK 获取失败 serial=%s err=%s", serial, e)
            raise KeyError(f"PSK 获取失败: {e}") from e

        self._cache[serial] = psk_bytes
        self._logger.info("PSK 已缓存 serial=%s", serial)
        return (psk_bytes, f"serial:{serial}")


async def run_proxy():
    logger = logging.getLogger("proxy")
    backend = os.environ.get("BACKEND_URI")
    if not backend:
        sys.exit("Environment variable BACKEND_URI is required, eg. coap://upstream:5683")

    parsed = urlparse(backend)
    if parsed.scheme != "coap":
        sys.exit("BACKEND_URI 必须是明文后端，形如 coap://host[:port]")
    if not parsed.netloc:
        sys.exit("BACKEND_URI must include a host (and optional port)")
    backend_host, backend_port = hostportsplit(parsed.netloc)
    backend_port = backend_port or 5683
    backend_target = f"{backend_host}:{backend_port}"

    bind = os.environ.get("BIND", ":5684")
    plain_bind = os.environ.get("PLAIN_BIND", ":5683")
    psk_api_url = os.environ.get("PSK_API_URL")
    if not psk_api_url:
        sys.exit("必须提供 PSK_API_URL，用于通过序列号获取 DTLS PSK")

    # Ensure DTLS server transport is enabled
    os.environ.setdefault("AIOCOAP_DTLSSERVER_ENABLED", "1")

    # Parse bind and normalize any-address to a concrete IP (tinydtls_server limitation).
    def _auto_pick_host():
        # Prefer a concrete IPv4 local address; does not send data.
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                return s.getsockname()[0]
        except OSError:
            return "127.0.0.1"

    def _normalize_bind(raw_bind: str, label: str):
        try:
            host, port = hostportsplit(raw_bind)
        except ValueError as e:
            sys.exit(f"无效的 {label}: {e}")

        if host in ("0.0.0.0", "::", "", None):
            host = _auto_pick_host()
        return (host, port), host

    bind_tuple, host = _normalize_bind(bind, "BIND")
    plain_bind_tuple, plain_host = _normalize_bind(plain_bind, "PLAIN_BIND")

    logger.info("启动 CoAP 反向代理")
    logger.info("后端: %s (解析为 %s)", backend, backend_target)
    logger.info("监听 DTLS: %s:%s (原始 BIND=%s)", host, bind_tuple[1], bind)
    logger.info(
        "监听 明文: %s:%s (原始 PLAIN_BIND=%s)",
        plain_host,
        plain_bind_tuple[1],
        plain_bind,
    )
    logger.info("PSK API: %s", psk_api_url)
    logger.info(
        "AIOCOAP_DTLSSERVER_ENABLED=%s", os.environ.get("AIOCOAP_DTLSSERVER_ENABLED")
    )

    # Outgoing client (to upstream)
    outgoing_context = await aiocoap.Context.create_client_context()
    logger.info("已创建上游客户端上下文")

    # Reverse proxy
    class _HostSettingRedirector(UnconditionalRedirector):
        """确保被转发请求带上 uri_host/uri_port，避免上层因缺失 netloc 抛错。"""

        def __init__(self, target: str, scheme: str = "coap"):
            super().__init__(target)
            self.scheme = scheme
            host, port = hostportsplit(target)
            self.host = host
            self.port = port or 5683

        def apply_redirection(self, request):
            req = super().apply_redirection(request)
            if req is None:
                return None
            req.requested_scheme = self.scheme
            req.opt.uri_host = self.host
            req.opt.uri_port = self.port
            req.remote = aiocoap.message.UndecidedRemote(
                self.scheme, hostportjoin(self.host, self.port)
            )
            return req

    proxy = ProxyWithPooledObservations(outgoing_context)
    proxy.add_redirector(_HostSettingRedirector(backend_target))
    logger.info("已创建代理并指向后端")

    # Dynamic DTLS-PSK credentials for inbound clients
    server_credentials = HttpPSKCredentials(psk_api_url)

    server_context = await aiocoap.Context.create_server_context(
        proxy, bind=bind_tuple, server_credentials=server_credentials
    )
    logger.info("DTLS 服务器已启动，等待客户端连接")

    # Plain CoAP server (no DTLS)
    plain_server_context = await aiocoap.Context.create_server_context(
        proxy, bind=plain_bind_tuple
    )
    logger.info("明文 CoAP 服务器已启动，等待客户端连接")

    stop_event = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, stop_event.set)

    await stop_event.wait()

    await server_context.shutdown()
    await plain_server_context.shutdown()
    await outgoing_context.shutdown()


def main() -> None:
    log_level_name = os.environ.get("LOG_LEVEL", "INFO").upper()
    log_level = getattr(logging, log_level_name, logging.INFO)
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
        handlers=[logging.StreamHandler(sys.stdout)],
    )
    logging.getLogger("aiocoap").setLevel(log_level)
    logging.getLogger("coap-server").setLevel(log_level)
    logging.getLogger("coap").setLevel(log_level)
    logging.getLogger("tinydtls").setLevel(log_level)
    asyncio.run(run_proxy())


if __name__ == "__main__":
    main()

