"""OpenTelemetry tracing bootstrap."""

import importlib.util
from unittest.mock import MagicMock, patch

import pytest

from skill.observability import tracing as tracing_mod


def _has_module(module_path: str) -> bool:
    try:
        return importlib.util.find_spec(module_path) is not None
    except (ModuleNotFoundError, ValueError):
        return False


@pytest.fixture(autouse=True)
def reset_tracing():
    tracing_mod._tracing_initialized = False
    yield
    tracing_mod._tracing_initialized = False


def test_init_tracing_skips_without_endpoint():
    with patch.dict("os.environ", {"OTEL_EXPORTER_OTLP_ENDPOINT": ""}):
        tracing_mod.init_tracing(None)
    assert tracing_mod._tracing_initialized is True


def test_get_tracer_returns_object():
    tracer = tracing_mod.get_tracer("test.service")
    assert tracer is not None


def test_init_tracing_with_endpoint_patches_exporter():
    if _has_module("opentelemetry.exporter.otlp.proto.http.trace_exporter"):
        exporter_target = (
            "opentelemetry.exporter.otlp.proto.http.trace_exporter.OTLPSpanExporter"
        )
    elif _has_module("opentelemetry.exporter.otlp.proto.grpc.trace_exporter"):
        exporter_target = (
            "opentelemetry.exporter.otlp.proto.grpc.trace_exporter.OTLPSpanExporter"
        )
    else:
        tracing_mod._tracing_initialized = False
        tracing_mod.init_tracing(None)
        assert tracing_mod._tracing_initialized is True
        return

    with patch.dict(
        "os.environ",
        {"OTEL_EXPORTER_OTLP_ENDPOINT": "http://localhost:4318/v1/traces"},
    ):
        with patch(exporter_target, MagicMock()):
            tracing_mod._tracing_initialized = False
            tracing_mod.init_tracing(None)
