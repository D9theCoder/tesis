"""Foundation layer — session management, recon, HTTP client, payloads, verification."""

from foundation.http_client import HTTPClient, RequestResult, TransportError, RequestTimeoutError
from foundation.session_manager import DVWASession
from foundation.recon import recon, parse_forms, extract_nav_links, infer_module_name, detect_security_level_from_html, fingerprint_server, EndpointRecord, InputVectorRecord
from foundation.payload_library import PayloadLibrary, PayloadSet
from foundation.verifier import Verifier, VerificationResult

__all__ = [
    "HTTPClient",
    "RequestResult",
    "TransportError",
    "RequestTimeoutError",
    "DVWASession",
    "recon",
    "parse_forms",
    "extract_nav_links",
    "infer_module_name",
    "detect_security_level_from_html",
    "fingerprint_server",
    "EndpointRecord",
    "InputVectorRecord",
    "PayloadLibrary",
    "PayloadSet",
    "Verifier",
    "VerificationResult",
]
