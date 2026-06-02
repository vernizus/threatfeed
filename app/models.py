import ipaddress
import re
from typing import Literal, Optional

from pydantic import BaseModel, Field, model_validator

_DOMAIN_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)

_MAX_ELEMENT_LEN = 253
_MAX_DURATION_SECONDS = 31_536_000
_MAX_SOURCE_LEN = 64
_MAX_COMMENT_LEN = 512


class FeedCreate(BaseModel):
    element: str = Field(..., max_length=_MAX_ELEMENT_LEN)
    data_type: Literal["ip", "cidr", "domain"]
    entry_type: Literal["permanent", "temporary"]
    duration_seconds: Optional[int] = Field(None, ge=1, le=_MAX_DURATION_SECONDS)
    source: str = Field("manual", max_length=_MAX_SOURCE_LEN)
    comment: Optional[str] = Field(None, max_length=_MAX_COMMENT_LEN)

    @model_validator(mode="after")
    def _validate(self) -> "FeedCreate":
        self.element = self.element.strip()

        if self.entry_type == "temporary" and self.duration_seconds is None:
            raise ValueError("duration_seconds is required for temporary entries")

        el = self.element
        if self.data_type == "ip":
            try:
                ipaddress.ip_address(el)
            except ValueError:
                raise ValueError(f"Invalid IP address: {el!r}")
        elif self.data_type == "cidr":
            try:
                ipaddress.ip_network(el, strict=False)
            except ValueError:
                raise ValueError(f"Invalid CIDR notation: {el!r}")
        elif self.data_type == "domain":
            if not _DOMAIN_RE.match(el):
                raise ValueError(f"Invalid domain format: {el!r}")

        return self


class FeedDelete(BaseModel):
    element: str = Field(..., max_length=_MAX_ELEMENT_LEN)


# ── Feed responses ────────────────────────────────────────────────────────────

class FeedResponse(BaseModel):
    element: str
    data_type: str
    entry_type: str
    source: str
    comment: Optional[str]
    occurrences_count: int
    promoted_to_permanent: bool
    message: Optional[str] = None


class FeedDetailItem(BaseModel):
    element: str
    data_type: str
    entry_type: str
    source: str
    comment: Optional[str]
    expires_at: Optional[str]


# ── Bulk ──────────────────────────────────────────────────────────────────────

class FeedBulkCreate(BaseModel):
    items: list[FeedCreate]

    @model_validator(mode="after")
    def _check_size(self) -> "FeedBulkCreate":
        if not self.items:
            raise ValueError("items list cannot be empty")
        if len(self.items) > 500:
            raise ValueError("bulk limit is 500 items per request")
        return self


class BulkFeedResult(BaseModel):
    element: str
    data_type: str
    entry_type: str
    source: str
    occurrences_count: int
    promoted_to_permanent: bool
    error: Optional[str] = None


class BulkFeedResponse(BaseModel):
    processed: int
    failed: int
    results: list[BulkFeedResult]


# ── History ───────────────────────────────────────────────────────────────────

class HistoryItem(BaseModel):
    element: str
    data_type: str
    occurrences_count: int
    last_seen: str


class HistoryResponse(BaseModel):
    total: int
    items: list[HistoryItem]


# ── Lookup ────────────────────────────────────────────────────────────────────

class LookupFeedInfo(BaseModel):
    data_type: str
    entry_type: str
    source: str
    comment: Optional[str]
    expires_at: Optional[str]
    created_at: str
    active: bool


class LookupHistoryInfo(BaseModel):
    occurrences_count: int
    last_seen: str


class LookupResponse(BaseModel):
    element: str
    found: bool
    feed: Optional[LookupFeedInfo] = None
    history: Optional[LookupHistoryInfo] = None


# ── Import from URL ───────────────────────────────────────────────────────────

class ImportFromUrl(BaseModel):
    url: str = Field(..., max_length=2048)
    data_type: Literal["ip", "domain"]
    entry_type: Literal["permanent", "temporary"] = "permanent"
    duration_seconds: Optional[int] = Field(None, ge=1, le=_MAX_DURATION_SECONDS)
    source: str = Field(..., max_length=_MAX_SOURCE_LEN)
    comment: Optional[str] = Field(None, max_length=_MAX_COMMENT_LEN)

    @model_validator(mode="after")
    def _check_duration(self) -> "ImportFromUrl":
        if self.entry_type == "temporary" and self.duration_seconds is None:
            raise ValueError("duration_seconds required for temporary imports")
        return self


class ImportResponse(BaseModel):
    url: str
    source: str
    inserted: int
    skipped_duplicate: int
    skipped_invalid: int
    total_parsed: int


# ── Stats ─────────────────────────────────────────────────────────────────────

class FeedTypeStats(BaseModel):
    permanent: int
    temporary_active: int
    temporary_expired: int


class StatsResponse(BaseModel):
    feed: dict[str, FeedTypeStats]
    history: dict[str, int]
    config: dict[str, object]
