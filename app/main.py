import hmac
import os
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request, status
from fastapi.responses import JSONResponse, PlainTextResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from .database import (
    delete_feed,
    get_active_feed,
    get_active_feed_detail,
    get_history,
    get_permanent_feed,
    get_permanent_feed_detail,
    get_stats,
    get_temporary_feed,
    get_temporary_feed_detail,
    import_from_url,
    init_db,
    is_blocked,
    lookup_element,
    process_feed_entry,
    seed_from_file,
)
from .models import (
    BulkFeedResponse,
    BulkFeedResult,
    FeedBulkCreate,
    FeedCreate,
    FeedDelete,
    FeedDetailItem,
    FeedResponse,
    HistoryResponse,
    ImportFromUrl,
    ImportResponse,
    LookupResponse,
    StatsResponse,
)

_API_KEY: str = os.getenv("API_KEY", "changeme")
_THRESHOLD: int = int(os.getenv("THRESHOLD_PROMOTION", "5"))
_PROMOTION_ENABLED: bool = os.getenv("PROMOTION_ENABLED", "true").strip().lower() == "true"
_DEBUG: bool = os.getenv("DEBUG", "false").strip().lower() == "true"
_SEED_ENABLED: bool = os.getenv("SEED_ENABLED", "true").strip().lower() == "true"
_SEED_IPS_FILE: str = os.getenv("SEED_IPS_FILE", "/app/seeds/ips.txt")
_SEED_DOMAINS_FILE: str = os.getenv("SEED_DOMAINS_FILE", "/app/seeds/domains.txt")

limiter = Limiter(key_func=get_remote_address)


@asynccontextmanager
async def lifespan(_: FastAPI):
    init_db()
    if _SEED_ENABLED:
        for path, label in ((_SEED_IPS_FILE, "IPs/CIDRs"), (_SEED_DOMAINS_FILE, "domains")):
            ins, skip = seed_from_file(path)
            if ins or skip:
                print(f"[seed] {label}: {ins} inserted, {skip} already present")
    yield


app = FastAPI(
    title="Threat Feed Service",
    version="2.2.0",
    description=(
        "IP/CIDR/Domain threat feed with reputation history, automatic permanence promotion, "
        "source tracking, and plain-text output compatible with any firewall "
        "(firewall, Cisco, MikroTik, pfSense, Squid…)."
    ),
    lifespan=lifespan,
    docs_url="/docs" if _DEBUG else None,
    redoc_url="/redoc" if _DEBUG else None,
    openapi_url="/openapi.json" if _DEBUG else None,
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _check_key(key: Optional[str]) -> bool:
    if not key:
        return False
    return hmac.compare_digest(key.encode("utf-8"), _API_KEY.encode("utf-8"))


def _require_api_key(x_api_key: str = Header(..., alias="X-API-Key")) -> None:
    if not _check_key(x_api_key):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")


def _build_expires_at(duration_seconds: int) -> str:
    return (
        datetime.now(timezone.utc) + timedelta(seconds=duration_seconds)
    ).strftime("%Y-%m-%dT%H:%M:%SZ")


def _process(payload: FeedCreate) -> FeedResponse:
    expires_at = (
        _build_expires_at(payload.duration_seconds)
        if payload.entry_type == "temporary"
        else None
    )
    result = process_feed_entry(
        element=payload.element,
        data_type=payload.data_type,
        entry_type=payload.entry_type,
        expires_at=expires_at,
        threshold=_THRESHOLD,
        promotion_enabled=_PROMOTION_ENABLED,
        source=payload.source,
        comment=payload.comment,
    )
    effective_type = (
        "permanent"
        if (result["promoted"] or payload.entry_type == "permanent")
        else "temporary"
    )
    return FeedResponse(
        element=payload.element,
        data_type=payload.data_type,
        entry_type=effective_type,
        source=payload.source,
        comment=payload.comment,
        occurrences_count=result["occurrences_count"],
        promoted_to_permanent=result["promoted"],
        message=(
            f"Auto-promoted to permanent (threshold={_THRESHOLD} occurrences reached)."
            if result["promoted"]
            else None
        ),
    )


def _feed_response(
    plain: list[str],
    detail_rows: list[dict],
    detail: bool,
    x_api_key: Optional[str],
):
    """Return plain text or JSON detail depending on `detail` flag."""
    if detail:
        if not _check_key(x_api_key):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="X-API-Key required for detail mode",
            )
        return JSONResponse(content=detail_rows)
    return PlainTextResponse("\n".join(plain))


# ── Public feed endpoints ─────────────────────────────────────────────────────
# Plain text by default — consumable by ANY firewall (firewall, Cisco ACL,
# MikroTik address-list, pfSense, Squid, nginx geo…).
#
# Add ?detail=true + X-API-Key to get JSON with source/comment (SOC tools).

@app.get("/feed/ip/active", response_class=PlainTextResponse, tags=["feed"],
         summary="Active IPs/CIDRs — permanent + non-expired temporary")
@limiter.limit("120/minute")
def feed_ip_active(
    request: Request,
    detail: bool = Query(False, description="Return JSON with source/comment (requires X-API-Key)"),
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
):
    return _feed_response(
        get_active_feed(["ip", "cidr"]),
        get_active_feed_detail(["ip", "cidr"]),
        detail, x_api_key,
    )


@app.get("/feed/ip/permanent", response_class=PlainTextResponse, tags=["feed"])
@limiter.limit("120/minute")
def feed_ip_permanent(
    request: Request,
    detail: bool = Query(False),
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
):
    return _feed_response(
        get_permanent_feed(["ip", "cidr"]),
        get_permanent_feed_detail(["ip", "cidr"]),
        detail, x_api_key,
    )


@app.get("/feed/ip/temporary", response_class=PlainTextResponse, tags=["feed"])
@limiter.limit("120/minute")
def feed_ip_temporary(
    request: Request,
    detail: bool = Query(False),
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
):
    return _feed_response(
        get_temporary_feed(["ip", "cidr"]),
        get_temporary_feed_detail(["ip", "cidr"]),
        detail, x_api_key,
    )


@app.get("/feed/domain/active", response_class=PlainTextResponse, tags=["feed"],
         summary="Active domains — permanent + non-expired temporary")
@limiter.limit("120/minute")
def feed_domain_active(
    request: Request,
    detail: bool = Query(False),
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
):
    return _feed_response(
        get_active_feed(["domain"]),
        get_active_feed_detail(["domain"]),
        detail, x_api_key,
    )


@app.get("/feed/domain/permanent", response_class=PlainTextResponse, tags=["feed"])
@limiter.limit("120/minute")
def feed_domain_permanent(
    request: Request,
    detail: bool = Query(False),
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
):
    return _feed_response(
        get_permanent_feed(["domain"]),
        get_permanent_feed_detail(["domain"]),
        detail, x_api_key,
    )


@app.get("/feed/domain/temporary", response_class=PlainTextResponse, tags=["feed"])
@limiter.limit("120/minute")
def feed_domain_temporary(
    request: Request,
    detail: bool = Query(False),
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
):
    return _feed_response(
        get_temporary_feed(["domain"]),
        get_temporary_feed_detail(["domain"]),
        detail, x_api_key,
    )


# ── Protected — history, stats, lookup ───────────────────────────────────────

@app.get("/feed/history", response_model=HistoryResponse, tags=["feed"],
         dependencies=[Depends(_require_api_key)])
@limiter.limit("30/minute")
def feed_history(request: Request) -> HistoryResponse:
    items = get_history()
    return HistoryResponse(total=len(items), items=items)


@app.get("/api/stats", response_model=StatsResponse, tags=["api"],
         dependencies=[Depends(_require_api_key)])
@limiter.limit("30/minute")
def api_stats(request: Request) -> StatsResponse:
    data = get_stats()
    return StatsResponse(
        feed=data["feed"],
        history=data["history"],
        config={
            "threshold_promotion": _THRESHOLD,
            "promotion_enabled": _PROMOTION_ENABLED,
        },
    )


@app.get(
    "/api/feed/lookup",
    tags=["api"],
    summary="Look up a single element. Without API key: returns {blocked: bool} only.",
)
@limiter.limit("120/minute")
def api_lookup(
    request: Request,
    element: str = Query(..., max_length=253, description="IP, CIDR or domain to look up"),
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
):
    if not _check_key(x_api_key):
        # Public mode — minimal response, no internal details
        return JSONResponse(content={"element": element, "blocked": is_blocked(element)})
    return LookupResponse(**lookup_element(element))


# ── Protected — management ────────────────────────────────────────────────────

@app.post("/api/feed", response_model=FeedResponse, tags=["api"],
          dependencies=[Depends(_require_api_key)])
@limiter.limit("60/minute")
def api_add(request: Request, payload: FeedCreate) -> FeedResponse:
    return _process(payload)


@app.post("/api/feed/bulk", response_model=BulkFeedResponse, tags=["api"],
          dependencies=[Depends(_require_api_key)],
          summary="Bulk import up to 500 elements")
@limiter.limit("10/minute")
def api_bulk_add(request: Request, payload: FeedBulkCreate) -> BulkFeedResponse:
    results: list[BulkFeedResult] = []
    failed = 0
    for item in payload.items:
        try:
            r = _process(item)
            results.append(BulkFeedResult(
                element=r.element, data_type=r.data_type, entry_type=r.entry_type,
                source=r.source, occurrences_count=r.occurrences_count,
                promoted_to_permanent=r.promoted_to_permanent,
            ))
        except Exception as exc:
            failed += 1
            results.append(BulkFeedResult(
                element=item.element, data_type=item.data_type, entry_type=item.entry_type,
                source=item.source, occurrences_count=0,
                promoted_to_permanent=False, error=str(exc),
            ))
    return BulkFeedResponse(processed=len(results) - failed, failed=failed, results=results)


@app.post("/api/feed/import", response_model=ImportResponse, tags=["api"],
          dependencies=[Depends(_require_api_key)],
          summary="Download a remote threat feed URL and import it")
@limiter.limit("5/minute")
def api_import(request: Request, payload: ImportFromUrl) -> ImportResponse:
    expires_at = (
        _build_expires_at(payload.duration_seconds)
        if payload.entry_type == "temporary"
        else None
    )
    try:
        stats = import_from_url(
            url=payload.url,
            data_type=payload.data_type,
            entry_type=payload.entry_type,
            expires_at=expires_at,
            source=payload.source,
            comment=payload.comment,
        )
    except RuntimeError as exc:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=str(exc))

    return ImportResponse(url=payload.url, source=payload.source, **stats)


@app.delete("/api/feed", tags=["api"], dependencies=[Depends(_require_api_key)])
@limiter.limit("60/minute")
def api_delete(request: Request, payload: FeedDelete) -> dict:
    if not delete_feed(payload.element):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Element not found")
    return {"deleted": payload.element}


# ── Health ────────────────────────────────────────────────────────────────────

@app.get("/health", tags=["ops"])
@limiter.limit("60/minute")
def health(request: Request) -> dict:
    return {"status": "ok"}
