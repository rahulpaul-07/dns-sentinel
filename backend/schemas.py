"""Pydantic request schemas for the DNSentinel API."""
import ipaddress
import re
from typing import Optional

from pydantic import BaseModel, field_validator

from config import settings

# Printable ASCII with no whitespace. Real DNS names (including punycode IDNs and
# base32/hex tunnel payloads) fit; newlines and control characters -- which
# would otherwise reach log files, PDFs and the SOAR hosts-file writer -- do not.
_QUERY_RE = re.compile(r"^[\x21-\x7e]+$")


class DNSLog(BaseModel):
    timestamp: Optional[float] = None
    query: str
    source_ip: str = "0.0.0.0"
    qtype: str = "A"

    @field_validator("query")
    @classmethod
    def _validate_query(cls, v):
        v = (v or "").strip().rstrip(".")
        if not v:
            raise ValueError("query must not be empty")
        if len(v) > settings.MAX_QUERY_LENGTH:
            raise ValueError(
                f"query exceeds max length of {settings.MAX_QUERY_LENGTH} characters"
            )
        if not _QUERY_RE.match(v):
            raise ValueError("query must be printable ASCII with no whitespace")
        return v.lower()

    @field_validator("source_ip")
    @classmethod
    def _validate_source_ip(cls, v):
        v = (v or "0.0.0.0").strip()
        try:
            return str(ipaddress.ip_address(v))
        except ValueError:
            raise ValueError("source_ip must be a valid IPv4 or IPv6 address")

    @field_validator("qtype")
    @classmethod
    def _validate_qtype(cls, v):
        v = (v or "A").strip().upper()[:10]
        return v if v.isalnum() else "A"
