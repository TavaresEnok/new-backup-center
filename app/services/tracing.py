import os
from contextlib import contextmanager
from typing import Dict, Optional

_TRACER = None
_TRACING_READY = False


def _truthy_env(name: str, default: str = "0") -> bool:
    return str(os.getenv(name, default) or "").strip().lower() in {"1", "true", "on", "yes"}


def _init_tracing():
    global _TRACER, _TRACING_READY
    if _TRACING_READY:
        return _TRACER

    _TRACING_READY = True
    if not _truthy_env("BACKUP_OTEL_ENABLED", "0"):
        return None

    try:
        from opentelemetry import trace
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
    except Exception:
        return None

    service_name = str(os.getenv("BACKUP_OTEL_SERVICE_NAME", "backup-center")).strip() or "backup-center"
    endpoint = str(os.getenv("BACKUP_OTEL_EXPORTER_OTLP_ENDPOINT", "") or "").strip()
    if not endpoint:
        return None

    try:
        provider = TracerProvider(resource=Resource.create({"service.name": service_name}))
        exporter = OTLPSpanExporter(endpoint=endpoint, timeout=5)
        provider.add_span_processor(BatchSpanProcessor(exporter))
        trace.set_tracer_provider(provider)
        _TRACER = trace.get_tracer(service_name)
    except Exception:
        _TRACER = None
    return _TRACER


def get_tracer():
    return _init_tracing()


@contextmanager
def traced_span(name: str, attributes: Optional[Dict[str, object]] = None):
    tracer = get_tracer()
    if not tracer:
        yield None
        return

    with tracer.start_as_current_span(str(name or "backup.span")) as span:
        for key, value in (attributes or {}).items():
            if value is None:
                continue
            try:
                span.set_attribute(str(key), value)
            except Exception:
                continue
        yield span
