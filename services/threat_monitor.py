"""
Security Event Logger Service (AEGIS-X Module)

Production-ready, reusable event logging for the entire platform.
Every backend module calls `log_security_event()` — the single entry point.

Enhanced schema stores: event_type, severity, username, user_id, ip_address,
status, description, metadata, risk_score, source_module, timestamp.
"""

import logging
import uuid
from datetime import datetime, timezone, timedelta
from backend.database.connection import get_database

logger = logging.getLogger("SecurityEventLogger")

# ── Severity classification thresholds ──────────────────────────────────
SEVERITY_THRESHOLDS = {
    "critical": 90,
    "high": 70,
    "medium": 40,
    "low": 0,
}

# ── Canonical event type labels ─────────────────────────────────────────
EVENT_TYPES = {
    "url_scan":           "URL Scan",
    "phishing_detected":  "Phishing Detected",
    "malware_indicator":  "Malware Indicator",
    "network_anomaly":    "Network Anomaly",
    "login_attempt":      "Login Attempt",
    "login_success":      "Login Success",
    "login_failure":      "Login Failure",
    "user_registered":    "User Registered",
    "admin_action":       "Admin Action",
    "incident_created":   "Incident Created",
    "report_generated":   "Report Generated",
    "model_retrained":    "Model Retrained",
}

# ── Map event types → default source module ─────────────────────────────
SOURCE_MODULE_MAP = {
    "url_scan":           "scanner",
    "phishing_detected":  "scanner",
    "malware_indicator":  "malware_engine",
    "network_anomaly":    "network_monitor",
    "login_attempt":      "auth",
    "login_success":      "auth",
    "login_failure":      "auth",
    "user_registered":    "auth",
    "admin_action":       "admin",
    "incident_created":   "incident_response",
    "report_generated":   "report_engine",
    "model_retrained":    "learning_engine",
}


def classify_severity(risk_score: int) -> str:
    """Classify threat severity based on risk score."""
    for severity, threshold in SEVERITY_THRESHOLDS.items():
        if risk_score >= threshold:
            return severity
    return "low"


# ═══════════════════════════════════════════════════════════════════════
#  CORE LOGGER — single entry point for all modules
# ═══════════════════════════════════════════════════════════════════════

async def log_security_event(
    event_type: str,
    description: str,
    severity: str = "low",
    risk_score: int = 0,
    source_url: str = "",
    user_id: str = "",
    username: str = "",
    ip_address: str = "",
    source_module: str = "",
    status: str = "new",
    metadata: dict = None,
) -> dict | None:
    """
    Central security event logger.  Every backend module calls this single
    function to record an event in the ``threat_events`` collection.

    Parameters
    ----------
    event_type : str       One of EVENT_TYPES keys.
    description : str      Human-readable description.
    severity : str         low | medium | high | critical
    risk_score : int       0-100
    source_url : str       URL that triggered the event (if applicable).
    user_id : str          MongoDB user _id.
    username : str         Display name or email.
    ip_address : str       Client IP.
    source_module : str    Origin module (auto-detected if empty).
    status : str           new | acknowledged | resolved | dismissed
    metadata : dict        Arbitrary extra data.
    """
    db = get_database()

    if not source_module:
        source_module = SOURCE_MODULE_MAP.get(event_type, "system")

    event_doc = {
        "event_id":      str(uuid.uuid4()),
        "event_type":    event_type,
        "severity":      severity,
        "risk_score":    risk_score,
        "description":   description,
        "source_url":    source_url,
        "user_id":       user_id,
        "username":      username,
        "ip_address":    ip_address,
        "source_module": source_module,
        "status":        status,
        "metadata":      metadata or {},
        "timestamp":     datetime.now(timezone.utc),
        "acknowledged":  False,
    }

    try:
        result = await db.threat_events.insert_one(event_doc)
        event_doc["_id"] = str(result.inserted_id)
        logger.info(
            f"[{severity.upper()}] {EVENT_TYPES.get(event_type, event_type)} — "
            f"{description}  (user={username or user_id}, ip={ip_address})"
        )
        return event_doc
    except Exception as e:
        logger.error(f"Failed to emit security event: {e}")
        return None


# backward-compatible alias used by scan / incidents modules
emit_threat_event = log_security_event


# ═══════════════════════════════════════════════════════════════════════
#  QUERY HELPERS
# ═══════════════════════════════════════════════════════════════════════

async def get_threat_events(
    limit: int = 50,
    offset: int = 0,
    severity: str = None,
    event_type: str = None,
    source_module: str = None,
    status: str = None,
    search: str = None,
    hours: int = None,
    user_id: str = None,
) -> tuple[list, int]:
    """
    Retrieve threat events with filtering, search, and pagination.
    Returns (events_list, total_matching_count).
    """
    db = get_database()
    query: dict = {}

    if severity:
        query["severity"] = severity
    if event_type:
        query["event_type"] = event_type
    if source_module:
        query["source_module"] = source_module
    if status:
        query["status"] = status
    if user_id:
        query["user_id"] = user_id
    if hours:
        cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
        query["timestamp"] = {"$gte": cutoff}

    # Get ALL matching (up to 2000 for count) then slice for pagination
    cursor = db.threat_events.find(query)
    all_events = await cursor.to_list(2000)

    # Apply text search filter on description / source_url if provided
    if search:
        q = search.lower()
        all_events = [
            e for e in all_events
            if q in e.get("description", "").lower()
            or q in e.get("source_url", "").lower()
            or q in e.get("username", "").lower()
            or q in e.get("event_type", "").lower()
        ]

    total = len(all_events)

    # Sort descending by timestamp
    all_events = sorted(
        all_events, key=lambda x: x.get("timestamp", ""), reverse=True
    )

    # Paginate
    page = all_events[offset : offset + limit]

    # Serialise
    for e in page:
        e["_id"] = str(e["_id"])
        if "timestamp" in e and isinstance(e["timestamp"], datetime):
            e["timestamp"] = e["timestamp"].isoformat()

    return page, total


async def get_event_by_id(event_id: str) -> dict | None:
    """Fetch a single event by its Mongo _id or event_id UUID."""
    db = get_database()
    from bson import ObjectId

    # Try ObjectId first
    event = None
    try:
        event = await db.threat_events.find_one({"_id": ObjectId(event_id)})
    except Exception:
        pass

    if not event:
        event = await db.threat_events.find_one({"event_id": event_id})
    if not event:
        event = await db.threat_events.find_one({"_id": event_id})

    if event:
        event["_id"] = str(event["_id"])
        if "timestamp" in event and isinstance(event["timestamp"], datetime):
            event["timestamp"] = event["timestamp"].isoformat()

    return event


async def delete_event(event_id: str) -> bool:
    """Delete a single event by _id or event_id."""
    db = get_database()
    from bson import ObjectId

    try:
        result = await db.threat_events.delete_one({"_id": ObjectId(event_id)})
        if result.deleted_count:
            return True
    except Exception:
        pass

    result = await db.threat_events.delete_one({"event_id": event_id})
    if result.deleted_count:
        return True

    result = await db.threat_events.delete_one({"_id": event_id})
    return bool(result.deleted_count)


async def get_threat_stats(period_hours: int = 24) -> dict:
    """Aggregate threat statistics for a given period."""
    db = get_database()
    cutoff = datetime.now(timezone.utc) - timedelta(hours=period_hours)

    cursor = db.threat_events.find({"timestamp": {"$gte": cutoff}})
    events = await cursor.to_list(2000)

    total = len(events)
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    type_counts: dict[str, int] = {}
    module_counts: dict[str, int] = {}

    for e in events:
        sev = e.get("severity", "low")
        if sev in severity_counts:
            severity_counts[sev] += 1
        etype = e.get("event_type", "unknown")
        type_counts[etype] = type_counts.get(etype, 0) + 1
        mod = e.get("source_module", "system")
        module_counts[mod] = module_counts.get(mod, 0) + 1

    return {
        "period_hours": period_hours,
        "total_events": total,
        "severity_breakdown": severity_counts,
        "type_breakdown": type_counts,
        "module_breakdown": module_counts,
        "threat_level": (
            "critical" if severity_counts["critical"] > 0
            else "high" if severity_counts["high"] > 2
            else "medium" if severity_counts["medium"] > 5
            else "low"
        ),
    }


async def get_statistics() -> dict:
    """Full statistics payload: total, by severity, today, this week."""
    db = get_database()

    total = await db.threat_events.count_documents({})
    critical = await db.threat_events.count_documents({"severity": "critical"})
    high = await db.threat_events.count_documents({"severity": "high"})
    medium = await db.threat_events.count_documents({"severity": "medium"})
    low = await db.threat_events.count_documents({"severity": "low"})

    now = datetime.now(timezone.utc)
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    week_start = today_start - timedelta(days=today_start.weekday())

    # Get today / weekly counts via list scan (mongomock-compatible)
    cursor_all = db.threat_events.find({})
    all_events = await cursor_all.to_list(5000)

    today_count = 0
    weekly_count = 0
    for e in all_events:
        ts = e.get("timestamp")
        if isinstance(ts, datetime):
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
            if ts >= today_start:
                today_count += 1
            if ts >= week_start:
                weekly_count += 1

    # type breakdown (all time)
    type_breakdown: dict[str, int] = {}
    module_breakdown: dict[str, int] = {}
    for e in all_events:
        et = e.get("event_type", "unknown")
        type_breakdown[et] = type_breakdown.get(et, 0) + 1
        mod = e.get("source_module", "system")
        module_breakdown[mod] = module_breakdown.get(mod, 0) + 1

    return {
        "total_events": total,
        "critical_events": critical,
        "high_events": high,
        "medium_events": medium,
        "low_events": low,
        "today_events": today_count,
        "weekly_events": weekly_count,
        "type_breakdown": type_breakdown,
        "module_breakdown": module_breakdown,
    }
