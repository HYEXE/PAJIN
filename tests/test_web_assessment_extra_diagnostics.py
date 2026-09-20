from __future__ import annotations

import gzip
import json
import random
import zlib
from collections.abc import AsyncIterator

import httpx
import pytest
from pydantic import ValidationError

from pajin.runtime.worker import EgressPolicy
from pajin.web_assessment.extra_diagnostics import (
    FTPDirectoryListingRecipe,
    FTPDirectoryListingResult,
    SecurityHeaderPostureRecipe,
    SecurityHeaderPostureResult,
    diagnose_ftp_directory_listing,
    diagnose_security_header_posture,
)
from pajin.web_assessment.network import AssessmentBoundaryError, AssessmentNetwork
from pajin.web_assessment.recipes import juice_shop_plan


def _html_response(
    status: int,
    body: bytes,
    *,
    headers: dict[str, str] | None = None,
) -> httpx.Response:
    selected_headers = {"content-type": "text/html; charset=utf-8"}
    selected_headers.update(headers or {})
    return httpx.Response(status, headers=selected_headers, content=body)


class _TrackedAsyncStream(httpx.AsyncByteStream):
    def __init__(self, chunks: tuple[bytes, ...]) -> None:
        self.chunks = chunks
        self.iterated = False
        self.closed = False

    async def __aiter__(self) -> AsyncIterator[bytes]:
        self.iterated = True
        for chunk in self.chunks:
            yield chunk

    async def aclose(self) -> None:
        self.closed = True


def test_extra_diagnostic_recipes_pin_paths_methods_and_budgets() -> None:
    security = SecurityHeaderPostureRecipe()
    assert security.path == "/"
    assert security.method == "GET"
    assert security.requests_per_trial == 1
    assert security.total_request_budget == 2

    ftp = FTPDirectoryListingRecipe()
    assert ftp.path == "/ftp/"
    assert ftp.missing_path == "/ftp/pajin-web004-control-missing-v1.md"
    assert ftp.method == "GET"
    assert ftp.requests_per_trial == 2
    assert ftp.total_request_budget == 4

    changed_security = security.model_dump(mode="json")
    changed_security["path"] = "/other"
    with pytest.raises(ValidationError):
        SecurityHeaderPostureRecipe.model_validate(changed_security)

    changed_ftp = ftp.model_dump(mode="json")
    changed_ftp["missing_path"] = "/ftp/runtime-selected/"
    with pytest.raises(ValidationError):
        FTPDirectoryListingRecipe.model_validate(changed_ftp)


@pytest.mark.asyncio
async def test_security_header_posture_observes_missing_protections_without_raw_data() -> None:
    plan = juice_shop_plan("http://127.0.0.1:3000")
    raw_secret = "root-page-private-sentinel"
    seen: list[tuple[str, str]] = []

    def respond(request: httpx.Request) -> httpx.Response:
        seen.append((request.method, str(request.url)))
        return _html_response(
            200,
            f"<!doctype html><html>{raw_secret}</html>".encode(),
        )

    network = AssessmentNetwork(plan, transport=httpx.MockTransport(respond))
    try:
        result = await diagnose_security_header_posture(network=network)
        with pytest.raises(AssessmentBoundaryError, match="outside-campaign-scope"):
            await network.reserve("GET", plan.origin + "/ftp/")
        with pytest.raises(AssessmentBoundaryError, match="request-budget"):
            await network.reserve("GET", plan.origin + "/")
    finally:
        await network.close()

    assert result.status == "locally-observed"
    assert result.finding_authority is False
    assert result.target_write_performed is False
    assert result.external_callback_performed is False
    assert [trial.repetition for trial in result.trials] == ["source", "replay"]
    assert all(trial.reproduced and trial.controls_passed for trial in result.trials)
    assert all(trial.facts.missing_protection_count == 3 for trial in result.trials)
    assert seen == [("GET", plan.origin + "/"), ("GET", plan.origin + "/")]
    assert len(network.evidence) == 2

    serialized = json.dumps(result.model_dump(mode="json"), sort_keys=True)
    assert raw_secret not in serialized
    assert "<!doctype" not in serialized
    assert SecurityHeaderPostureResult.model_validate_json(serialized) == result


@pytest.mark.asyncio
async def test_security_header_posture_accepts_csp_frame_protection_and_rejects_tampering() -> None:
    plan = juice_shop_plan("http://127.0.0.1:3000")
    csp_secret = "nonce-private-sentinel"

    def respond(_: httpx.Request) -> httpx.Response:
        return _html_response(
            200,
            b"<html>secured</html>",
            headers={
                "content-security-policy": (
                    f"default-src 'self' 'nonce-{csp_secret}'; frame-ancestors 'none'"
                ),
                "x-content-type-options": "nosniff",
            },
        )

    network = AssessmentNetwork(plan, transport=httpx.MockTransport(respond))
    try:
        result = await diagnose_security_header_posture(network=network)
    finally:
        await network.close()

    assert result.status == "not-observed"
    assert all(not trial.reproduced and trial.controls_passed for trial in result.trials)
    assert all(trial.facts.frame_protection_present for trial in result.trials)
    assert csp_secret not in json.dumps(result.model_dump(mode="json"))

    wrong_status = result.model_dump(mode="json")
    wrong_status["result_id"] = ""
    wrong_status["status"] = "locally-observed"
    with pytest.raises(ValidationError, match="status differs"):
        SecurityHeaderPostureResult.model_validate(wrong_status)

    wrong_narrative = result.model_dump(mode="json")
    wrong_narrative["result_id"] = ""
    wrong_narrative["title"] = "Generic confirmed vulnerability"
    with pytest.raises(ValidationError, match="narrative differs"):
        SecurityHeaderPostureResult.model_validate(wrong_narrative)

    claimed_finding = result.model_dump(mode="json")
    claimed_finding["result_id"] = ""
    claimed_finding["finding_authority"] = True
    with pytest.raises(ValidationError):
        SecurityHeaderPostureResult.model_validate(claimed_finding)

    reused_evidence = result.model_dump(mode="json")
    reused_evidence["result_id"] = ""
    reused_evidence["trials"][1]["evidence_ids"] = reused_evidence["trials"][0]["evidence_ids"]
    with pytest.raises(ValidationError, match="distinct Evidence"):
        SecurityHeaderPostureResult.model_validate(reused_evidence)


@pytest.mark.asyncio
async def test_security_header_posture_rejects_wildcard_frame_ancestors() -> None:
    plan = juice_shop_plan("http://127.0.0.1:3000")

    def respond(_: httpx.Request) -> httpx.Response:
        return _html_response(
            200,
            b"<html>wildcard framing</html>",
            headers={
                "content-security-policy": "default-src 'self'; frame-ancestors *",
                "x-content-type-options": "nosniff",
            },
        )

    network = AssessmentNetwork(plan, transport=httpx.MockTransport(respond))
    try:
        result = await diagnose_security_header_posture(network=network)
    finally:
        await network.close()

    assert result.status == "locally-observed"
    assert all(trial.facts.content_security_policy_present for trial in result.trials)
    assert all(trial.facts.no_sniff_present for trial in result.trials)
    assert all(not trial.facts.frame_protection_present for trial in result.trials)
    assert all(trial.facts.missing_protection_count == 1 for trial in result.trials)


@pytest.mark.asyncio
async def test_security_header_posture_mixed_replay_is_inconclusive() -> None:
    plan = juice_shop_plan("http://127.0.0.1:3000")
    calls = 0

    def respond(_: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        headers = (
            {}
            if calls == 1
            else {
                "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
                "x-content-type-options": "nosniff",
            }
        )
        return _html_response(200, b"<html>posture</html>", headers=headers)

    network = AssessmentNetwork(plan, transport=httpx.MockTransport(respond))
    try:
        result = await diagnose_security_header_posture(network=network)
    finally:
        await network.close()

    assert result.status == "inconclusive"
    assert [trial.reproduced for trial in result.trials] == [True, False]
    assert all(trial.controls_passed for trial in result.trials)
    assert "inconclusive" in result.title.lower()


@pytest.mark.asyncio
async def test_security_header_redirect_is_not_followed() -> None:
    plan = juice_shop_plan("http://127.0.0.1:3000")
    external_location = "https://observer.invalid/private-query?token=secret"
    seen: list[str] = []

    def respond(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        return httpx.Response(302, headers={"location": external_location})

    network = AssessmentNetwork(plan, transport=httpx.MockTransport(respond))
    try:
        result = await diagnose_security_header_posture(network=network)
    finally:
        await network.close()

    assert result.status == "inconclusive"
    assert seen == [plan.origin + "/", plan.origin + "/"]
    serialized = json.dumps(result.model_dump(mode="json"))
    assert external_location not in serialized
    assert "observer.invalid" not in serialized


@pytest.mark.asyncio
async def test_ftp_directory_listing_uses_fixed_control_without_persisting_names() -> None:
    plan = juice_shop_plan("http://127.0.0.1:3000")
    private_file_name = "private-customer-export.csv"
    listing_body = (
        "<!doctype html><html><title>listing directory /ftp/</title>"
        f'<a href="/ftp/{private_file_name}">{private_file_name}</a>'
        '<a href="/ftp/public.txt">public.txt</a></html>'
    ).encode()
    encoded_listing = gzip.compress(listing_body)
    seen: list[tuple[str, str]] = []
    listing_streams: list[_TrackedAsyncStream] = []

    def respond(request: httpx.Request) -> httpx.Response:
        seen.append((request.method, str(request.url)))
        if request.url.path == "/ftp/":
            assert request.headers["accept-encoding"] == "gzip"
            stream = _TrackedAsyncStream(
                tuple(
                    encoded_listing[index : index + 17]
                    for index in range(0, len(encoded_listing), 17)
                )
            )
            listing_streams.append(stream)
            return httpx.Response(
                200,
                headers={
                    "content-encoding": "gzip",
                    "content-length": str(len(encoded_listing)),
                    "content-type": "text/html; charset=utf-8",
                },
                stream=stream,
            )
        if request.url.path == "/ftp/pajin-web004-control-missing-v1.md":
            return _html_response(404, b"<html>missing</html>")
        raise AssertionError(f"unexpected request {request.url}")

    network = AssessmentNetwork(plan, transport=httpx.MockTransport(respond))
    try:
        result = await diagnose_ftp_directory_listing(network=network)
        with pytest.raises(AssessmentBoundaryError, match="outside-campaign-scope"):
            await network.reserve("GET", plan.origin + "/ftp/package.json.bak")
        with pytest.raises(AssessmentBoundaryError, match="request-budget"):
            await network.reserve("GET", plan.origin + "/ftp/")
    finally:
        await network.close()

    assert result.status == "locally-observed"
    assert result.finding_authority is False
    assert result.file_names_persisted is False
    assert [trial.repetition for trial in result.trials] == ["source", "replay"]
    assert all(trial.reproduced and trial.controls_passed for trial in result.trials)
    assert all(trial.facts.listing_anchor_count == 2 for trial in result.trials)
    assert seen == [
        ("GET", plan.origin + "/ftp/"),
        ("GET", plan.origin + "/ftp/pajin-web004-control-missing-v1.md"),
        ("GET", plan.origin + "/ftp/"),
        ("GET", plan.origin + "/ftp/pajin-web004-control-missing-v1.md"),
    ]
    assert [evidence.path for evidence in network.evidence] == [
        "/ftp/",
        "/ftp/pajin-web004-control-missing-v1.md",
        "/ftp/",
        "/ftp/pajin-web004-control-missing-v1.md",
    ]
    assert len(listing_streams) == 2
    assert all(stream.iterated and stream.closed for stream in listing_streams)

    serialized = json.dumps(result.model_dump(mode="json"), sort_keys=True)
    assert private_file_name not in serialized
    assert "public.txt" not in serialized
    assert "listing directory" not in serialized.lower()
    assert FTPDirectoryListingResult.model_validate_json(serialized) == result

    forged_trial = result.model_dump(mode="json")
    forged_trial["result_id"] = ""
    forged_trial["trials"][0]["reproduced"] = False
    with pytest.raises(ValidationError, match="trial outcome differs"):
        FTPDirectoryListingResult.model_validate(forged_trial)

    impossible_shape = result.model_dump(mode="json")
    impossible_shape["result_id"] = ""
    impossible_shape["trials"][0]["facts"]["listing_anchor_count"] = 0
    with pytest.raises(ValidationError, match="lacks its bounded HTML evidence"):
        FTPDirectoryListingResult.model_validate(impossible_shape)

    reused_evidence = result.model_dump(mode="json")
    reused_evidence["result_id"] = ""
    reused_evidence["trials"][1]["evidence_ids"] = reused_evidence["trials"][0]["evidence_ids"]
    with pytest.raises(ValidationError, match="distinct Evidence"):
        FTPDirectoryListingResult.model_validate(reused_evidence)


@pytest.mark.asyncio
async def test_ftp_gzip_expansion_is_bounded_before_decoded_body_materialization(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan = juice_shop_plan("http://127.0.0.1:3000")
    decoded_body = b"A" * (4 * 1024 * 1024)
    encoded_body = gzip.compress(decoded_body)
    assert len(encoded_body) < FTPDirectoryListingRecipe().max_response_bytes
    stream = _TrackedAsyncStream((encoded_body,))
    max_lengths: list[int] = []
    returned_lengths: list[int] = []
    real_decompressobj = zlib.decompressobj

    class _RecordingDecompressor:
        def __init__(self) -> None:
            self._decoder = real_decompressobj(zlib.MAX_WBITS | 16)

        @property
        def eof(self) -> bool:
            return self._decoder.eof

        @property
        def unconsumed_tail(self) -> bytes:
            return self._decoder.unconsumed_tail

        @property
        def unused_data(self) -> bytes:
            return self._decoder.unused_data

        def decompress(self, data: bytes, max_length: int = 0) -> bytes:
            max_lengths.append(max_length)
            if max_length <= 0:
                raise AssertionError("gzip decoding must always have a positive output bound")
            decoded = self._decoder.decompress(data, max_length)
            returned_lengths.append(len(decoded))
            return decoded

    monkeypatch.setattr(
        zlib,
        "decompressobj",
        lambda _window_bits: _RecordingDecompressor(),
    )

    def respond(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/ftp/"
        return httpx.Response(
            200,
            headers={
                "content-encoding": "gzip",
                "content-type": "text/html; charset=utf-8",
            },
            stream=stream,
        )

    network = AssessmentNetwork(plan, transport=httpx.MockTransport(respond))
    try:
        with pytest.raises(AssessmentBoundaryError, match="response-byte-limit"):
            await diagnose_ftp_directory_listing(network=network)
    finally:
        await network.close()

    assert stream.iterated and stream.closed
    assert network.evidence == []
    assert network.failures == {"response-byte-limit": 1}
    assert max_lengths == [FTPDirectoryListingRecipe().max_response_bytes]
    assert returned_lengths == [FTPDirectoryListingRecipe().max_response_bytes]


@pytest.mark.asyncio
async def test_network_accepts_incompressible_gzip_at_the_decoded_limit() -> None:
    plan = juice_shop_plan("http://127.0.0.1:3000")
    recipe = FTPDirectoryListingRecipe()
    decoded_body = random.Random(0).randbytes(recipe.max_response_bytes)
    encoded_body = gzip.compress(decoded_body)
    assert len(encoded_body) > len(decoded_body)
    streams: list[_TrackedAsyncStream] = []

    def respond(request: httpx.Request) -> httpx.Response:
        assert request.url.path == recipe.path
        stream = _TrackedAsyncStream((encoded_body,))
        streams.append(stream)
        return httpx.Response(
            200,
            headers={
                "content-encoding": "gzip",
                "content-length": str(len(encoded_body)),
                "content-type": "application/octet-stream",
            },
            stream=stream,
        )

    network = AssessmentNetwork(plan, transport=httpx.MockTransport(respond))
    network.begin_phase(
        "incompressible-gzip-control",
        EgressPolicy(
            allow=[plan.origin + recipe.path],
            allowed_methods={"GET"},
            allow_private_networks=True,
            max_response_bytes=recipe.max_response_bytes,
            max_requests=1,
            max_request_bytes=1,
        ),
    )
    try:
        response = await network.exchange(
            "GET",
            plan.origin + recipe.path,
            accept_encoding="gzip",
        )
    finally:
        await network.close()

    assert response.body == decoded_body
    assert len(network.evidence) == 1
    assert network.evidence[0].response_bytes == recipe.max_response_bytes
    assert len(streams) == 1 and streams[0].iterated and streams[0].closed


@pytest.mark.asyncio
async def test_ftp_oversized_wire_content_length_is_rejected_before_stream_read() -> None:
    plan = juice_shop_plan("http://127.0.0.1:3000")
    recipe = FTPDirectoryListingRecipe()
    stream = _TrackedAsyncStream((gzip.compress(b"<html>small</html>"),))

    def respond(request: httpx.Request) -> httpx.Response:
        assert request.url.path == recipe.path
        return httpx.Response(
            200,
            headers={
                "content-encoding": "gzip",
                "content-length": str(recipe.max_response_bytes * 2),
                "content-type": "text/html; charset=utf-8",
            },
            stream=stream,
        )

    network = AssessmentNetwork(plan, transport=httpx.MockTransport(respond))
    try:
        with pytest.raises(AssessmentBoundaryError, match="response-byte-limit"):
            await diagnose_ftp_directory_listing(network=network)
    finally:
        await network.close()

    assert stream.iterated is False
    assert stream.closed is True
    assert network.evidence == []
    assert network.failures == {"response-byte-limit": 1}


@pytest.mark.asyncio
async def test_ftp_rejects_an_already_consumed_gzip_response() -> None:
    plan = juice_shop_plan("http://127.0.0.1:3000")

    def respond(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/ftp/"
        return httpx.Response(
            200,
            headers={
                "content-encoding": "gzip",
                "content-type": "text/html; charset=utf-8",
            },
            content=gzip.compress(b"<html>preloaded</html>"),
        )

    network = AssessmentNetwork(plan, transport=httpx.MockTransport(respond))
    try:
        with pytest.raises(
            AssessmentBoundaryError,
            match="encoded-response-already-consumed",
        ):
            await diagnose_ftp_directory_listing(network=network)
    finally:
        await network.close()

    assert network.evidence == []
    assert network.failures == {"encoded-response-already-consumed": 1}


@pytest.mark.asyncio
async def test_ftp_directory_listing_distinguishes_absence_from_failed_control() -> None:
    plan = juice_shop_plan("http://127.0.0.1:3000")

    def listing_disabled(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/ftp/":
            return httpx.Response(403, headers={"content-type": "text/plain"}, content=b"denied")
        return _html_response(404, b"<html>missing</html>")

    disabled_network = AssessmentNetwork(
        plan,
        transport=httpx.MockTransport(listing_disabled),
    )
    try:
        disabled = await diagnose_ftp_directory_listing(network=disabled_network)
    finally:
        await disabled_network.close()

    assert disabled.status == "not-observed"
    assert all(not trial.reproduced and trial.controls_passed for trial in disabled.trials)

    listing_body = b"<html><title>Index of /ftp/</title><a href='/ftp/item'>item</a></html>"

    def ambiguous_missing_control(_: httpx.Request) -> httpx.Response:
        return _html_response(200, listing_body)

    ambiguous_network = AssessmentNetwork(
        plan,
        transport=httpx.MockTransport(ambiguous_missing_control),
    )
    try:
        ambiguous = await diagnose_ftp_directory_listing(network=ambiguous_network)
    finally:
        await ambiguous_network.close()

    assert ambiguous.status == "inconclusive"
    assert all(trial.reproduced and not trial.controls_passed for trial in ambiguous.trials)
    assert "inconclusive" in ambiguous.title.lower()


@pytest.mark.asyncio
async def test_ftp_redirect_controls_are_not_followed_or_promoted() -> None:
    plan = juice_shop_plan("http://127.0.0.1:3000")
    external_location = "https://observer.invalid/ftp-listing"
    seen: list[str] = []

    def respond(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        return httpx.Response(302, headers={"location": external_location})

    network = AssessmentNetwork(plan, transport=httpx.MockTransport(respond))
    try:
        result = await diagnose_ftp_directory_listing(network=network)
    finally:
        await network.close()

    assert result.status == "inconclusive"
    assert seen == [
        plan.origin + "/ftp/",
        plan.origin + "/ftp/pajin-web004-control-missing-v1.md",
        plan.origin + "/ftp/",
        plan.origin + "/ftp/pajin-web004-control-missing-v1.md",
    ]
    serialized = json.dumps(result.model_dump(mode="json"))
    assert external_location not in serialized
    assert "observer.invalid" not in serialized
