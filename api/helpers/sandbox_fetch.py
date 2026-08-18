#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ctypes
import errno
import hashlib
import http.client
import json
import os
import re
import secrets
import socket
import sys
from typing import TypedDict

_SOCKET_PATH = "/tmp/tcs.sock"
_ROOT = "/mnt/data"
_GRANT_FILE = "/run/codeapi/egress-grant"
_GRANT_ENV = "SANDBOX_EGRESS_GRANT"
_MAX_RESPONSE_BYTES = 26_214_400
_ALLOWED_ERRORS = {
    "HOST_NOT_ALLOWED",
    "URL_REJECTED",
    "ADDRESS_NOT_GLOBAL",
    "REDIRECT_REJECTED",
    "CONTENT_TYPE_REJECTED",
    "RESPONSE_TOO_LARGE",
    "FETCH_TIMEOUT",
    "FETCH_BUDGET_EXCEEDED",
    "FETCH_FAILED",
}
_HOST_RE = re.compile(r"^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$")
_CONTENT_TYPE_RE = re.compile(
    r"^[a-z0-9][a-z0-9!#$&^_.+-]{0,63}/[a-z0-9][a-z0-9!#$&^_.+-]{0,127}$"
)
_RENAME_NOREPLACE = 1


class SandboxFetchResult(TypedDict):
    host: str
    bytes: int
    content_type: str
    sha256: str
    redirects: int


class SandboxFetchError(RuntimeError):
    def __init__(self, code: str):
        safe_code = code if code in _ALLOWED_ERRORS else "FETCH_FAILED"
        super().__init__(safe_code)
        self.code = safe_code


class _UnixHTTPConnection(http.client.HTTPConnection):
    def connect(self) -> None:
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.connect(_SOCKET_PATH)


class _TrailerResponse(http.client.HTTPResponse):
    trailers: dict[str, str]

    def begin(self) -> None:
        self.trailers = {}
        super().begin()

    def _read_and_discard_trailer(self) -> None:
        while True:
            line = self.fp.readline(65_537)
            if len(line) > 65_536:
                raise http.client.LineTooLong("trailer line")
            if line in (b"\r\n", b"\n", b""):
                break
            name, separator, value = line.decode("iso-8859-1").partition(":")
            if separator:
                self.trailers[name.strip().lower()] = value.strip()


_UnixHTTPConnection.response_class = _TrailerResponse


def _open_output_parent(output_path: str) -> tuple[int, str]:
    if not isinstance(output_path, str) or "\x00" in output_path or not os.path.isabs(output_path):
        raise SandboxFetchError("FETCH_FAILED")
    components = output_path.split("/")
    if ".." in components or output_path == _ROOT or not output_path.startswith(f"{_ROOT}/"):
        raise SandboxFetchError("FETCH_FAILED")
    relative = output_path[len(_ROOT) + 1 :]
    parts = relative.split("/")
    if not parts[-1] or any(part in ("", ".", "..") for part in parts):
        raise SandboxFetchError("FETCH_FAILED")

    directory_fd = os.open(_ROOT, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for component in parts[:-1]:
            next_fd = os.open(
                component,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=directory_fd,
            )
            os.close(directory_fd)
            directory_fd = next_fd
        try:
            os.stat(parts[-1], dir_fd=directory_fd, follow_symlinks=False)
        except FileNotFoundError:
            return directory_fd, parts[-1]
        raise SandboxFetchError("FETCH_FAILED")
    except Exception:
        os.close(directory_fd)
        raise


def _atomic_rename_no_replace(directory_fd: int, source: str, destination: str) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    renameat2 = getattr(libc, "renameat2", None)
    if renameat2 is None:
        raise SandboxFetchError("FETCH_FAILED")
    renameat2.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    renameat2.restype = ctypes.c_int
    result = renameat2(
        directory_fd,
        os.fsencode(source),
        directory_fd,
        os.fsencode(destination),
        _RENAME_NOREPLACE,
    )
    if result == 0:
        return
    error_number = ctypes.get_errno()
    if error_number in (errno.EEXIST, errno.ELOOP):
        raise SandboxFetchError("FETCH_FAILED")
    raise OSError(error_number, os.strerror(error_number))


def _safe_error_from_response(response: http.client.HTTPResponse) -> SandboxFetchError:
    payload = response.read(8_193)
    if len(payload) > 8_192:
        return SandboxFetchError("FETCH_FAILED")
    try:
        parsed = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return SandboxFetchError("FETCH_FAILED")
    if not isinstance(parsed, dict):
        return SandboxFetchError("FETCH_FAILED")
    code = parsed.get("error")
    return SandboxFetchError(code if isinstance(code, str) else "FETCH_FAILED")


def _read_grant() -> str:
    try:
        with open(_GRANT_FILE, "r", encoding="utf-8") as grant_file:
            grant = grant_file.read(16_385)
    except FileNotFoundError:
        grant = os.environ.get(_GRANT_ENV, "")
    if not grant.strip() or len(grant) > 16_384:
        raise SandboxFetchError("FETCH_FAILED")
    return grant


def sandbox_fetch(url: str, output_path: str) -> SandboxFetchResult:
    if not isinstance(url, str) or len(url.encode("utf-8")) > 8_192:
        raise SandboxFetchError("URL_REJECTED")
    grant = _read_grant()
    directory_fd, output_name = _open_output_parent(output_path)
    temporary_name = f".sandbox-fetch-{secrets.token_hex(16)}.tmp"
    temporary_fd = -1
    connection: _UnixHTTPConnection | None = None
    committed = False
    try:
        temporary_fd = os.open(
            temporary_name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
            dir_fd=directory_fd,
        )
        envelope = json.dumps({"url": url}, separators=(",", ":")).encode("utf-8")
        connection = _UnixHTTPConnection("localhost", timeout=20)
        connection.request(
            "POST",
            "/external-fetch",
            body=envelope,
            headers={
                "Content-Type": "application/json",
                "Content-Length": str(len(envelope)),
                "X-CodeAPI-Egress-Grant": grant,
            },
        )
        response = connection.getresponse()
        if response.status != 200:
            raise _safe_error_from_response(response)

        host = response.getheader("X-CodeAPI-Egress-Host", "")
        content_type = response.getheader("Content-Type", "").split(";", 1)[0].strip().lower()
        raw_redirects = response.getheader("X-CodeAPI-Egress-Redirects", "")
        if (
            not _HOST_RE.fullmatch(host)
            or not _CONTENT_TYPE_RE.fullmatch(content_type)
            or not raw_redirects.isdigit()
        ):
            raise SandboxFetchError("FETCH_FAILED")
        redirects = int(raw_redirects)
        if redirects < 0 or redirects > 3:
            raise SandboxFetchError("FETCH_FAILED")

        digest = hashlib.sha256()
        byte_count = 0
        while True:
            chunk = response.read(65_536)
            if not chunk:
                break
            byte_count += len(chunk)
            if byte_count > _MAX_RESPONSE_BYTES:
                raise SandboxFetchError("RESPONSE_TOO_LARGE")
            digest.update(chunk)
            view = memoryview(chunk)
            while view:
                written = os.write(temporary_fd, view)
                view = view[written:]

        outcome = response.trailers.get("x-codeapi-egress-outcome", "")
        if outcome != "OK":
            raise SandboxFetchError(outcome)
        os.fsync(temporary_fd)
        os.close(temporary_fd)
        temporary_fd = -1
        _atomic_rename_no_replace(directory_fd, temporary_name, output_name)
        committed = True
        return {
            "host": host,
            "bytes": byte_count,
            "content_type": content_type,
            "sha256": digest.hexdigest(),
            "redirects": redirects,
        }
    except SandboxFetchError:
        raise
    except (OSError, http.client.HTTPException, TimeoutError):
        raise SandboxFetchError("FETCH_FAILED") from None
    finally:
        if connection is not None:
            connection.close()
        if temporary_fd >= 0:
            os.close(temporary_fd)
        if not committed:
            try:
                os.unlink(temporary_name, dir_fd=directory_fd)
            except FileNotFoundError:
                pass
        os.close(directory_fd)


def _main() -> int:
    parser = argparse.ArgumentParser(add_help=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--url-stdin", action="store_true", required=True)
    args = parser.parse_args()
    raw_url = sys.stdin.buffer.read(8_193)
    if len(raw_url) > 8_192:
        print("URL_REJECTED", file=sys.stderr)
        return 1
    try:
        url = raw_url.decode("utf-8").rstrip("\r\n")
        result = sandbox_fetch(url, args.output)
    except (UnicodeDecodeError, SandboxFetchError) as error:
        code = error.code if isinstance(error, SandboxFetchError) else "URL_REJECTED"
        print(code, file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
