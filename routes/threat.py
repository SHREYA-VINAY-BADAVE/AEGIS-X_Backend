"""
Security Events REST API (AEGIS-X Module)

Endpoints
─────────
GET    /api/events              — All events (search, filter, paginate)
GET    /api/events/recent       — Latest 20 events
GET    /api/events/statistics   — Aggregated statistics
GET    /api/events/:id          — Single event detail
DELETE /api/events/:id          — Delete event (admin only)
GET    /api/events/export/csv   — Export events as CSV
GET    /api/threat/stats        — Period-based stats (24h, 7d, 30d)
GET    /api/threat/live         — SSE real-time stream

Role-based access:
  Admin   → full access (CRUD + export)
  Analyst → read + filter
  User    → own events only
"""

import asyncio
import csv
import io
import json
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, Query, Response
from fastapi.responses import StreamingResponse
from backend.middleware.auth import get_current_user, get_current_admin
from backend.services.threat_monitor import (
    get_threat_events,
    get_event_by_id,
    delete_event,
    get_threat_stats,
    get_statistics,
    log_security_event,
    EVENT_TYPES,
)

router = APIRouter(tags=["events"])

# ───────── helper ─────────────────────────────────────────────────────
def _user_can_access(user: dict, event: dict) -> bool:
    role = user.get("role", "user")
    if role in ("admin", "analyst"):
        return True
    return event.get("user_id", "") == user.get("_id", "")


# ══════════════════════════════════════════════════════════════════════
#  /api/events  —  paginated, filtered, searchable event list
# ══════════════════════════════════════════════════════════════════════

@router.get("/events")
async def list_events(
    limit: int = Query(20, ge=1, le=200),
    offset: int = Query(0, ge=0),
    severity: str = Query(None),
    event_type: str = Query(None),
    source_module: str = Query(None),
    status: str = Query(None),
    search: str = Query(None),
    hours: int = Query(None),
    current_user: dict = Depends(get_current_user),
):
    """
    List security events with filtering, search, and pagination.
    Regular users see only their own events.
    """
    role = current_user.get("role", "user")
    user_filter = None if role in ("admin", "analyst") else current_user.get("_id")

    events, total = await get_threat_events(
        limit=limit,
        offset=offset,
        severity=severity,
        event_type=event_type,
        source_module=source_module,
        status=status,
        search=search,
        hours=hours,
        user_id=user_filter,
    )
    return {
        "events": events,
        "total": total,
        "limit": limit,
        "offset": offset,
        "has_more": (offset + limit) < total,
    }


# ══════════════════════════════════════════════════════════════════════
#  /api/events/recent  —  latest 20 events
# ══════════════════════════════════════════════════════════════════════

@router.get("/events/recent")
async def recent_events(current_user: dict = Depends(get_current_user)):
    """Return latest 20 events (role-filtered)."""
    role = current_user.get("role", "user")
    user_filter = None if role in ("admin", "analyst") else current_user.get("_id")

    events, _ = await get_threat_events(limit=20, user_id=user_filter)
    return {"events": events}


# ══════════════════════════════════════════════════════════════════════
#  /api/events/statistics  —  aggregated statistics
# ══════════════════════════════════════════════════════════════════════

@router.get("/events/statistics")
async def event_statistics(current_user: dict = Depends(get_current_user)):
    """
    Returns total, critical, high, today, weekly counts + breakdowns.
    """
    stats = await get_statistics()
    return stats


# ══════════════════════════════════════════════════════════════════════
#  /api/events/export/csv  —  CSV export (admin only)
# ══════════════════════════════════════════════════════════════════════

@router.get("/events/export/csv")
async def export_events_csv(
    severity: str = Query(None),
    event_type: str = Query(None),
    hours: int = Query(None),
    current_user: dict = Depends(get_current_user),
):
    """Export events as CSV file. Admin/Analyst only."""
    role = current_user.get("role", "user")
    if role not in ("admin", "analyst"):
        raise HTTPException(status_code=403, detail="Export requires admin or analyst role.")

    events, _ = await get_threat_events(
        limit=2000, severity=severity, event_type=event_type, hours=hours
    )

    # Build CSV
    output = io.StringIO()
    writer = csv.DictWriter(
        output,
        fieldnames=[
            "event_id", "event_type", "severity", "risk_score",
            "description", "source_url", "username", "ip_address",
            "source_module", "status", "timestamp",
        ],
    )
    writer.writeheader()
    for e in events:
        writer.writerow({
            "event_id": e.get("event_id", ""),
            "event_type": e.get("event_type", ""),
            "severity": e.get("severity", ""),
            "risk_score": e.get("risk_score", 0),
            "description": e.get("description", ""),
            "source_url": e.get("source_url", ""),
            "username": e.get("username", ""),
            "ip_address": e.get("ip_address", ""),
            "source_module": e.get("source_module", ""),
            "status": e.get("status", ""),
            "timestamp": e.get("timestamp", ""),
        })

    csv_bytes = output.getvalue().encode("utf-8")

    await log_security_event(
        event_type="report_generated",
        description=f"Events CSV exported by {current_user.get('email', '')}",
        user_id=str(current_user.get("_id", "")),
        username=current_user.get("email", ""),
        source_module="report_engine",
    )

    return Response(
        content=csv_bytes,
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=security_events.csv"},
    )


# ══════════════════════════════════════════════════════════════════════
#  /api/events/:id  —  single event detail
# ══════════════════════════════════════════════════════════════════════

@router.get("/events/{event_id}")
async def get_event(event_id: str, current_user: dict = Depends(get_current_user)):
    """Get a single event by ID."""
    event = await get_event_by_id(event_id)
    if not event:
        raise HTTPException(status_code=404, detail="Event not found.")
    if not _user_can_access(current_user, event):
        raise HTTPException(status_code=403, detail="Access denied.")
    return event


# ══════════════════════════════════════════════════════════════════════
#  DELETE /api/events/:id  —  admin only
# ══════════════════════════════════════════════════════════════════════

@router.delete("/events/{event_id}")
async def remove_event(event_id: str, current_user: dict = Depends(get_current_admin)):
    """Delete a security event. Admin only."""
    deleted = await delete_event(event_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Event not found.")
    return {"message": "Event deleted."}


# ══════════════════════════════════════════════════════════════════════
#  /api/threat/stats  —  period-based statistics (backward-compat)
# ══════════════════════════════════════════════════════════════════════

# Kept under /threat prefix for backward compatibility with previous implementation
threat_router = APIRouter(prefix="/threat", tags=["threat"])


@threat_router.get("/stats")
async def threat_statistics(
    current_user: dict = Depends(get_current_user),
):
    """Period-based threat stats (24h / 7d / 30d)."""
    stats_24h = await get_threat_stats(24)
    stats_7d = await get_threat_stats(168)
    stats_30d = await get_threat_stats(720)
    return {"last_24h": stats_24h, "last_7d": stats_7d, "last_30d": stats_30d}


@threat_router.get("/live")
async def live_threat_feed(current_user: dict = Depends(get_current_user)):
    """SSE endpoint for real-time event streaming."""

    async def event_generator():
        last_check = None
        while True:
            events, _ = await get_threat_events(limit=5, hours=1)
            new_events = []
            for e in events:
                ts = e.get("timestamp", "")
                if last_check is None or ts > last_check:
                    new_events.append(e)

            if new_events:
                last_check = new_events[0].get("timestamp", "")
                for ev in new_events:
                    yield f"data: {json.dumps(ev)}\n\n"
            else:
                yield f"data: {json.dumps({'type': 'heartbeat', 'timestamp': datetime.utcnow().isoformat()})}\n\n"

            await asyncio.sleep(5)

    return StreamingResponse(event_generator(), media_type="text/event-stream")
