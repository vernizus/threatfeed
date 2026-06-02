import hmac
import os
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone

from fastapi import Depends, FastAPI, Header, HTTPException, Request, status
from fastapi.responses import PlainTextResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from .database import (
    delete_feed,
    get_active_feed,
    get_history,
    get_permanent_feed,
    get_stats,
    get_temporary_feed,
    init_db,
    process_feed_entry,
    seed_from_file,
)
from .models import (
    BulkFeedResponse,
    BulkFeedResult,
    FeedBulkCreate,
    FeedCreate,
    FeedDelete,
    FeedResponse,
    HistoryResponse,
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
    version="2.1.0",
    description=(
        "IP/CIDR/Domain threat feed with reputation history, "
        "automatic permanence promotion, and FortiGate External Block List support."
    ),
    lifespan=lifespan,
    # Swagger/OpenAPI disabled in production — set DEBUG=true to enable
    docs_url="/docs" if _DEBUG else None,
    redoc_url="/redoc" if _DEBUG else None,
    openapi_url="/openapi.json" if _DEBUG else None,
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)


# ── Auth dependency ───────────────────────────────────────────────────────────

def _require_api_key(x_api_key: str = Header(..., alias="X-API-Key")) -> None:
    # Constant-time comparison prevents timing oracle attacks
    if not hmac.compare_digest(x_api_key.encode("utf-8"), _API_KEY.encode("utf-8")):
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
    )
    effective_type = (
        "permanent"
        if (result["promoted"] or payload.entry_type == "permanent")
        else "temporary"
    )
    msg = (
        f"Auto-promoted to permanent (threshold={_THRESHOLD} occurrences reached)."
        if result["promoted"]
        else None
    )
    return FeedResponse(
        element=payload.element,
        data_type=payload.data_type,
        entry_type=effective_type,
        occurrences_count=result["occurrences_count"],
        promoted_to_permanent=result["promoted"],
        message=msg,
    )


# ── Public feed endpoints (plain text — FortiGate / firewall consumable) ─────
# Rate-limited to prevent DoS. FortiGate polls every 5 min → 12 req/hour well
# within the 120/minute allowance.

@app.get("/feed/ip/permanent", response_class=PlainTextResponse, tags=["feed"])
@limiter.limit("120/minute")
def feed_ip_permanent(request: Request) -> str:
    return "\n".join(get_permanent_feed(["ip", "cidr"]))


@app.get("/feed/ip/temporary", response_class=PlainTextResponse, tags=["feed"])
@limiter.limit("120/minute")
def feed_ip_temporary(request: Request) -> str:
    return "\n".join(get_temporary_feed(["ip", "cidr"]))


@app.get("/feed/ip/active", response_class=PlainTextResponse, tags=["feed"])
@limiter.limit("120/minute")
def feed_ip_active(request: Request) -> str:
    """Primary endpoint for FortiGate External Connector — IPv4 block list."""
    return "\n".join(get_active_feed(["ip", "cidr"]))


@app.get("/feed/domain/permanent", response_class=PlainTextResponse, tags=["feed"])
@limiter.limit("120/minute")
def feed_domain_permanent(request: Request) -> str:
    return "\n".join(get_permanent_feed(["domain"]))


@app.get("/feed/domain/temporary", response_class=PlainTextResponse, tags=["feed"])
@limiter.limit("120/minute")
def feed_domain_temporary(request: Request) -> str:
    return "\n".join(get_temporary_feed(["domain"]))


@app.get("/feed/domain/active", response_class=PlainTextResponse, tags=["feed"])
@limiter.limit("120/minute")
def feed_domain_active(request: Request) -> str:
    """Primary endpoint for FortiGate External Connector — domain block list."""
    return "\n".join(get_active_feed(["domain"]))


# ── Protected history & stats ─────────────────────────────────────────────────

@app.get(
    "/feed/history",
    response_model=HistoryResponse,
    tags=["feed"],
    dependencies=[Depends(_require_api_key)],
)
@limiter.limit("30/minute")
def feed_history(request: Request) -> HistoryResponse:
    items = get_history()
    return HistoryResponse(total=len(items), items=items)


@app.get(
    "/api/stats",
    response_model=StatsResponse,
    tags=["api"],
    dependencies=[Depends(_require_api_key)],
)
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


# ── Protected management API ──────────────────────────────────────────────────

@app.post(
    "/api/feed",
    response_model=FeedResponse,
    status_code=status.HTTP_200_OK,
    tags=["api"],
    dependencies=[Depends(_require_api_key)],
)
@limiter.limit("60/minute")
def api_add(request: Request, payload: FeedCreate) -> FeedResponse:
    return _process(payload)


@app.post(
    "/api/feed/bulk",
    response_model=BulkFeedResponse,
    status_code=status.HTTP_200_OK,
    tags=["api"],
    dependencies=[Depends(_require_api_key)],
    summary="Bulk import up to 500 elements in a single request",
)
@limiter.limit("10/minute")
def api_bulk_add(request: Request, payload: FeedBulkCreate) -> BulkFeedResponse:
    results: list[BulkFeedResult] = []
    failed = 0
    for item in payload.items:
        try:
            r = _process(item)
            results.append(
                BulkFeedResult(
                    element=r.element,
                    data_type=r.data_type,
                    entry_type=r.entry_type,
                    occurrences_count=r.occurrences_count,
                    promoted_to_permanent=r.promoted_to_permanent,
                )
            )
        except Exception as exc:
            failed += 1
            results.append(
                BulkFeedResult(
                    element=item.element,
                    data_type=item.data_type,
                    entry_type=item.entry_type,
                    occurrences_count=0,
                    promoted_to_permanent=False,
                    error=str(exc),
                )
            )
    return BulkFeedResponse(
        processed=len(results) - failed,
        failed=failed,
        results=results,
    )


@app.delete(
    "/api/feed",
    tags=["api"],
    dependencies=[Depends(_require_api_key)],
)
@limiter.limit("60/minute")
def api_delete(request: Request, payload: FeedDelete) -> dict:
    if not delete_feed(payload.element):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Element not found",
        )
    return {"deleted": payload.element}


# ── Health ────────────────────────────────────────────────────────────────────

@app.get("/health", tags=["ops"])
@limiter.limit("60/minute")
def health(request: Request) -> dict:
    return {"status": "ok"}
