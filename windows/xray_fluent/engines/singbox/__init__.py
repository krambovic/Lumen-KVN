"""sing-box engine helpers."""

from .config_builder import build_singbox_outbound
from .manager import SingBoxManager, get_singbox_version
from .operations import restart_runtime, start_proxy, start_runtime, start_tun, try_hot_switch_selector
from .runtime_planner import (
    ParsedSingboxDocument,
    SingboxDocumentState,
    SingboxRuntimePlan,
    SingboxXraySidecarPlan,
    classify_node_for_singbox,
    inspect_singbox_document_text,
    parse_singbox_document,
    plan_singbox_runtime,
    prime_endpoint_resolution,
    singbox_node_tag,
    singbox_node_source_signature,
)

__all__ = [
    "build_singbox_outbound",
    "SingBoxManager",
    "get_singbox_version",
    "restart_runtime",
    "start_tun",
    "start_proxy",
    "start_runtime",
    "try_hot_switch_selector",
    "ParsedSingboxDocument",
    "SingboxDocumentState",
    "SingboxRuntimePlan",
    "SingboxXraySidecarPlan",
    "classify_node_for_singbox",
    "inspect_singbox_document_text",
    "parse_singbox_document",
    "plan_singbox_runtime",
    "prime_endpoint_resolution",
    "singbox_node_tag",
    "singbox_node_source_signature",
]
