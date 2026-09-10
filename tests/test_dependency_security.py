"""Behavioral security regressions for the installed pricing HTTP dependency."""

import gzip
import sys
import zlib
from collections.abc import Iterator
from types import FrameType

import httpx2
import pytest
from httpx2._sse import _SSELineDecoder


class _CompressedStream(httpx2.SyncByteStream):
    def __init__(self, content: bytes) -> None:
        self.content = content
        self.closed = False

    def __iter__(self) -> Iterator[bytes]:
        yield self.content

    def close(self) -> None:
        self.closed = True


@pytest.mark.parametrize("encoding", ["gzip", "deflate", "gzip, deflate"])
def test_httpx2_bounds_each_inflated_network_chunk(encoding: str) -> None:
    payload = b"a" * (4 * 1024 * 1024)
    encoded = gzip.compress(payload) if encoding.startswith("gzip") else payload
    if encoding.endswith("deflate"):
        encoded = zlib.compress(encoded)
    assert len(encoded) < 64 * 1024
    stream = _CompressedStream(encoded)
    response = httpx2.Response(200, headers={"Content-Encoding": encoding}, stream=stream)

    chunks = list(response.iter_bytes())

    assert b"".join(chunks) == payload
    assert max(map(len, chunks)) <= 1024 * 1024
    assert response.is_closed and stream.closed


def test_httpx2_closes_stream_on_decode_failure() -> None:
    stream = _CompressedStream(b"invalid gzip")
    response = httpx2.Response(200, headers={"Content-Encoding": "gzip"}, stream=stream)
    with pytest.raises(httpx2.DecodingError):
        list(response.iter_bytes())
    assert response.is_closed and stream.closed


@pytest.mark.parametrize("body_kind", ["content", "json", "data", "files"])
def test_httpx2_does_not_add_conflicting_body_framing(body_kind: str) -> None:
    bodies = {
        "content": b"body",
        "json": {"field": "value"},
        "data": {"field": "value"},
        "files": {"field": ("file.txt", b"body", "text/plain")},
    }
    request = httpx2.Request(
        "POST", "https://fixture.invalid/", headers={"Transfer-Encoding": "chunked"},
        **{body_kind: bodies[body_kind]},
    )
    assert request.headers["Transfer-Encoding"] == "chunked"
    assert "Content-Length" not in request.headers
    assert request.read()


@pytest.mark.parametrize(
    ("content_type", "headers"),
    [
        ("text/plain\r\nX-Injected: yes", {}),
        ("text/plain\nX-Injected: yes", {}),
        ("text/plain", {"X-Note": "value\r\nX-Injected: yes"}),
        ("text/plain", {"X-Note\nX-Injected": "yes"}),
    ],
)
def test_httpx2_rejects_multipart_header_injection(
    content_type: str, headers: dict[str, str],
) -> None:
    with pytest.raises(ValueError):
        request = httpx2.Request(
            "POST", "https://fixture.invalid/",
            files={"upload": ("file.txt", b"body", content_type, headers)},
        )
        request.read()


def test_httpx2_preserves_legitimate_multipart_metadata() -> None:
    request = httpx2.Request(
        "POST", "https://fixture.invalid/",
        files={"upload": ("file.txt", b"body", "text/plain", {"X-Note": "value"})},
    )
    body = request.read()
    assert b"Content-Type: text/plain\r\n" in body
    assert b"X-Note: value\r\n" in body
    assert int(request.headers["Content-Length"]) == len(body)
    assert "Transfer-Encoding" not in request.headers


def test_httpx2_sse_does_not_rescan_the_growing_line() -> None:
    """Count scanned characters instead of a flaky CPU-time threshold."""
    decoder = _SSELineDecoder()
    scanned = 0
    decoder_filename = _SSELineDecoder.decode.__code__.co_filename

    def profile(frame: FrameType, event: str, function: object) -> None:
        nonlocal scanned
        if event != "c_call" or frame.f_code.co_filename != decoder_filename:
            return
        receiver = getattr(function, "__self__", None)
        operation = getattr(function, "__name__", "")
        if isinstance(receiver, str) and operation in {"split", "splitlines", "replace", "find"}:
            scanned += len(receiver)

    chunk = "x" * 64
    repeats = 1024
    previous = sys.getprofile()
    sys.setprofile(profile)
    try:
        for _ in range(repeats):
            assert decoder.decode(chunk) == []
        assert decoder.decode("\r\n") == [chunk * repeats]
        assert decoder.flush() == []
    finally:
        sys.setprofile(previous)
    assert 0 < scanned < 20 * len(chunk) * repeats


def test_httpx2_sse_preserves_split_line_endings() -> None:
    decoder = _SSELineDecoder()
    lines = []
    for fragment in ["data: one\r", "\ndata: two\n", "\r", "data: three\r", "\n\n"]:
        lines.extend(decoder.decode(fragment))
    lines.extend(decoder.flush())
    assert lines == ["data: one", "data: two", "", "data: three", ""]
