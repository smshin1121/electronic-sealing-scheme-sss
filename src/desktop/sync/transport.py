"""Transport rules shared by every desktop sync sender (stage E, E2d).

The records carry identity values, so every request of the sync client's
two backends and of the standalone portal sender (``push_seal_record``,
``push_seal_record_safe`` and the backfill command line) goes through
:func:`post`:

  - the URL must be HTTPS, or plain HTTP to a loopback address (a local test
    or a local reverse proxy); anything else is refused before a connection
    is opened;
  - a redirect is never followed: it could downgrade the transport or end
    on an unrelated page (a login form) whose HTTP 200 would pass for a
    delivery; a 3xx answer is refused;
  - the answer comes back as (HTTP status, body, at most 64 KiB) for the
    caller to check against its endpoint's documented acknowledgement.

Errors name the host only, never the whole URL (it may carry credentials).
"""

from __future__ import annotations

import ipaddress
import json
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any, Mapping, Optional

MAX_ANSWER_BYTES = 64 * 1024
_MAX_DETAIL = 200


class TransportError(RuntimeError):
    """The request was refused before sending, or could not be completed."""


@dataclass(frozen=True)
class Answer:
    """An HTTP answer: status and (bounded) body."""

    status: int
    body: bytes

    def json_object(self) -> Optional[dict[str, Any]]:
        """The body as a JSON object, or None when it is not one."""
        try:
            value = json.loads(self.body.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            return None
        return value if isinstance(value, dict) else None

    def message(self) -> str:
        """The ``message`` of a JSON answer (clipped), or ''."""
        value = self.json_object() or {}
        return clip(str(value.get("message", "")))


def clip(text: str) -> str:
    """Shorten ``text`` for logs and stored errors."""
    return text if len(text) <= _MAX_DETAIL else text[:_MAX_DETAIL] + "..."


def require_safe_url(url: str) -> None:
    """HTTPS, or plain HTTP to a loopback host; anything else is refused.

    Raises:
        TransportError: Naming the host only.
    """
    parts = urllib.parse.urlsplit(url or "")
    host = parts.hostname or ""
    if parts.scheme == "https" and host:
        return
    if parts.scheme == "http" and _is_loopback(host):
        return
    raise TransportError(
        f"refusing to send the record to {host or '(no host)'} without HTTPS "
        f"(plain HTTP is allowed to loopback only)")


def post(url: str, body: bytes, headers: Mapping[str, str],
         timeout: float) -> Answer:
    """POST ``body`` under the rules above.

    Returns:
        The answer, for any status that is not a redirect.

    Raises:
        TransportError: An unsafe URL (nothing is sent), a redirect, or a
            network failure.
    """
    require_safe_url(url)
    request = urllib.request.Request(url, data=body, method="POST",
                                     headers=dict(headers))
    try:
        with _open(request, timeout) as response:
            return Answer(response.status, response.read(MAX_ANSWER_BYTES))
    except urllib.error.HTTPError as exc:
        if 300 <= exc.code < 400:
            raise TransportError(
                f"unexpected redirect (HTTP {exc.code}); redirects are not "
                f"followed") from exc
        return Answer(exc.code, _read_error_body(exc))
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise TransportError(f"network: {clip(str(exc))}") from exc


class _RefuseRedirects(urllib.request.HTTPRedirectHandler):
    """Never follow a redirect: the 3xx answer reaches the caller as such."""

    def redirect_request(self, req: Any, fp: Any, code: int, msg: str,
                         headers: Any, newurl: str) -> None:
        return None


def _open(request: urllib.request.Request, timeout: float) -> Any:
    """Open ``request`` with an opener that follows no redirect."""
    opener = urllib.request.build_opener(_RefuseRedirects())
    return opener.open(request, timeout=timeout)


def _read_error_body(exc: urllib.error.HTTPError) -> bytes:
    try:
        return exc.read(MAX_ANSWER_BYTES) or b""
    except Exception:
        return b""


def _is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False
