"""
Automated Incident Response Routes
- GET /api/incidents — List all incidents
- POST /api/incidents — Create an incident manually
- PATCH /api/incidents/{id} — Update incident status
- POST /api/incidents/{id}/resolve — Mark as resolved
"""

from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from bson import ObjectId
from backend.database.connection import get_database
from backend.middleware.auth import get_current_user
from backend.services.threat_monitor import emit_threat_event

router = APIRouter(prefix="/incidents", tags=["incidents"])

# Severity-based recommended actions
RECOMMENDED_ACTIONS = {
    "critical": [
        "Immediately block the URL at firewall/proxy level",
        "Alert all users who accessed this URL",
        "Initiate forensic analysis of any credential submissions",
        "Report to CERT/CSIRT team",
        "Update threat intelligence feeds",
    ],
    "high": [
        "Block the URL in security gateway",
        "Notify affected users to reset credentials",
        "Run additional scans on related domains",
        "Update URL blacklist database",
    ],
    "medium": [
        "Add URL to watchlist for monitoring",
        "Verify SSL certificate validity",
        "Check domain age and registration details",
        "Schedule follow-up scan in 24 hours",
    ],
    "low": [
        "Log for future reference",
        "No immediate action required",
        "Monitor for pattern changes",
    ],
}


def _get_severity(risk_score: int) -> str:
    if risk_score >= 90:
        return "critical"
    elif risk_score >= 70:
        return "high"
    elif risk_score >= 40:
        return "medium"
    return "low"


async def auto_create_incident(scan_doc: dict) -> dict:
    """Automatically create an incident when a high-risk URL is detected."""
    risk_score = scan_doc.get("risk_score", 0)
    if risk_score < 70:
        return None  # Only create incidents for high+ risk

    db = get_database()
    severity = _get_severity(risk_score)

    incident_doc = {
        "scan_id": str(scan_doc.get("_id", "")),
        "url": scan_doc.get("url", ""),
        "prediction": scan_doc.get("prediction", ""),
        "risk_score": risk_score,
        "severity": severity,
        "status": "open",
        "recommended_actions": RECOMMENDED_ACTIONS.get(severity, []),
        "auto_blocked": risk_score >= 90,
        "notes": "",
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
        "created_by": scan_doc.get("user_id", "system"),
        "resolved_by": None,
        "resolved_at": None,
    }

    result = await db.incidents.insert_one(incident_doc)
    incident_doc["_id"] = str(result.inserted_id)

    # Emit threat event for incident creation
    await emit_threat_event(
        event_type="incident_created",
        description=f"Incident auto-created for {scan_doc.get('url', '')} (risk: {risk_score})",
        severity=severity,
        risk_score=risk_score,
        source_url=scan_doc.get("url", ""),
        user_id=scan_doc.get("user_id", ""),
    )

    return incident_doc


@router.get("")
async def list_incidents(
    current_user: dict = Depends(get_current_user)
):
    """List all incidents."""
    db = get_database()
    cursor = db.incidents.find({})
    incidents = await cursor.to_list(200)

    for inc in incidents:
        inc["_id"] = str(inc["_id"])
        for field in ["created_at", "updated_at", "resolved_at"]:
            if field in inc and isinstance(inc[field], datetime):
                inc[field] = inc[field].isoformat()

    incidents = sorted(incidents, key=lambda x: x.get("created_at", ""), reverse=True)
    return {"incidents": incidents, "total": len(incidents)}


class UpdateIncident(BaseModel):
    status: str = None
    notes: str = None


@router.patch("/{incident_id}")
async def update_incident(
    incident_id: str,
    update: UpdateIncident,
    current_user: dict = Depends(get_current_user)
):
    """Update incident status or notes."""
    db = get_database()

    try:
        query = {"_id": ObjectId(incident_id)}
    except Exception:
        query = {"_id": incident_id}

    incident = await db.incidents.find_one(query)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    update_fields = {"updated_at": datetime.now(timezone.utc)}
    if update.status:
        update_fields["status"] = update.status
    if update.notes is not None:
        update_fields["notes"] = update.notes

    await db.incidents.update_one(query, {"$set": update_fields})
    return {"message": "Incident updated", "status": update.status or incident.get("status")}


@router.post("/{incident_id}/resolve")
async def resolve_incident(
    incident_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Mark an incident as resolved."""
    db = get_database()

    try:
        query = {"_id": ObjectId(incident_id)}
    except Exception:
        query = {"_id": incident_id}

    incident = await db.incidents.find_one(query)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    await db.incidents.update_one(query, {"$set": {
        "status": "resolved",
        "resolved_by": current_user.get("email", ""),
        "resolved_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
    }})

    return {"message": "Incident resolved successfully"}
