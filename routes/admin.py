import os
import json
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from backend.database.connection import get_database
from backend.middleware.auth import get_current_admin, get_current_user
from backend.services.risk_engine import predict_threat_trend
from backend.services.behavior_analytics import get_platform_behavior_summary
from backend.services.learning_engine import get_performance_metrics, get_model_versions, record_retrain_event
from backend.services.threat_monitor import log_security_event

router = APIRouter(prefix="/admin", tags=["admin"])


@router.get("/users")
async def get_all_users(current_admin: dict = Depends(get_current_admin)):
    db = get_database()
    users_cursor = db.users.find({})
    users = await users_cursor.to_list(100)
    for u in users:
        u["_id"] = str(u["_id"])
        u.pop("password", None)
        if "created_at" in u and isinstance(u["created_at"], datetime):
            u["created_at"] = u["created_at"].isoformat()
    return users


@router.get("/scans")
async def get_all_scans(current_admin: dict = Depends(get_current_admin)):
    db = get_database()
    scans_cursor = db.scans.find({})
    scans = await scans_cursor.to_list(200)
    
    users_cursor = db.users.find({})
    users_list = await users_cursor.to_list(100)
    user_map = {str(u["_id"]): u.get("name", "Unknown") for u in users_list}
    
    for s in scans:
        s["_id"] = str(s["_id"])
        uid = s.get("user_id", "")
        s["username"] = user_map.get(str(uid), "External Api Client")
        if "scan_time" in s and isinstance(s["scan_time"], datetime):
            s["scan_time"] = s["scan_time"].isoformat()
            
    scans = sorted(scans, key=lambda x: x.get("scan_time", ""), reverse=True)
    return scans


@router.get("/analytics")
async def get_admin_analytics(current_admin: dict = Depends(get_current_admin)):
    db = get_database()
    
    # 1. Total Counts
    total_users = await db.users.count_documents({})
    total_scans = await db.scans.count_documents({})
    
    # 2. Risk Counts
    total_phishing = await db.scans.count_documents({"prediction": "PHISHING"})
    total_benign = await db.scans.count_documents({"prediction": "BENIGN"})
    
    # 3. Incident Counts
    total_incidents = await db.incidents.count_documents({})
    open_incidents = await db.incidents.count_documents({"status": "open"})
    resolved_incidents = await db.incidents.count_documents({"status": "resolved"})

    # 4. Threat Event Counts
    total_threat_events = await db.threat_events.count_documents({})
    critical_events = await db.threat_events.count_documents({"severity": "critical"})

    # 5. Model Performance
    ml_performance = await get_performance_metrics()

    # 6. Model assets info (legacy compatibility)
    assets_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "assets")
    stats_path = os.path.join(assets_dir, "model_stats.json")

    ml_status = {
        "active_model": ml_performance.get("active_model", "Random Forest"),
        "accuracy": ml_performance.get("current_metrics", {}).get("accuracy", 0.95),
        "precision": ml_performance.get("current_metrics", {}).get("precision", 0.94),
        "recall": ml_performance.get("current_metrics", {}).get("recall", 0.96),
        "f1_score": ml_performance.get("current_metrics", {}).get("f1_score", 0.95),
        "all_candidate_metrics": ml_performance.get("all_models", {}),
    }

    if os.path.exists(stats_path):
        try:
            with open(stats_path, "r") as f:
                stats = json.load(f)
                best_name = stats.get("best_model_name", "Random Forest")
                metrics = stats.get("all_models_metrics", {}).get(best_name, {})
                ml_status.update({
                    "active_model": best_name,
                    "accuracy": metrics.get("accuracy", 0.95),
                    "precision": metrics.get("precision", 0.95),
                    "recall": metrics.get("recall", 0.95),
                    "f1_score": metrics.get("f1_score", 0.95),
                    "confusion_matrix": metrics.get("confusion_matrix", [[0, 0], [0, 0]]),
                    "all_candidate_metrics": stats.get("all_models_metrics", {}),
                })
        except Exception:
            pass

    # 7. System health & logs
    system_logs = [
        {"timestamp": datetime.now().isoformat(), "level": "INFO", "message": "Admin requested security metrics summary."},
        {"timestamp": datetime.now().isoformat(), "level": "INFO", "message": f"ML Model Pipeline: {ml_status['active_model']} (Accuracy: {ml_status['accuracy']})."},
        {"timestamp": datetime.now().isoformat(), "level": "INFO", "message": f"Total threat events tracked: {total_threat_events}."},
        {"timestamp": datetime.now().isoformat(), "level": "INFO", "message": f"Active incidents: {open_incidents} open, {resolved_incidents} resolved."},
    ]
    
    return {
        "analytics": {
            "total_users": total_users,
            "total_scans": total_scans,
            "phishing_count": total_phishing,
            "benign_count": total_benign,
            "threat_percentage": round((total_phishing / total_scans * 100), 2) if total_scans > 0 else 0.0,
            "total_incidents": total_incidents,
            "open_incidents": open_incidents,
            "resolved_incidents": resolved_incidents,
            "total_threat_events": total_threat_events,
            "critical_events": critical_events,
        },
        "ml_status": ml_status,
        "system_logs": system_logs,
    }


# --- Role-Based Access Control Endpoints ---

class RoleUpdate(BaseModel):
    role: str  # "user", "analyst", "admin"


@router.patch("/users/{user_id}/role")
async def update_user_role(
    user_id: str,
    update: RoleUpdate,
    current_admin: dict = Depends(get_current_admin)
):
    """Update a user's role (admin only)."""
    if update.role not in ["user", "analyst", "admin"]:
        raise HTTPException(status_code=400, detail="Invalid role. Must be 'user', 'analyst', or 'admin'.")

    db = get_database()
    from bson import ObjectId
    try:
        query = {"_id": ObjectId(user_id)}
    except Exception:
        query = {"_id": user_id}

    user = await db.users.find_one(query)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    await db.users.update_one(query, {"$set": {"role": update.role}})

    await log_security_event(
        event_type="admin_action",
        description=f"Admin {current_admin['email']} changed role of {user.get('email')} to {update.role}",
        user_id=str(current_admin["_id"]),
    )

    return {"message": f"User role updated to '{update.role}'"}


class UserStatusUpdate(BaseModel):
    status: str  # "active", "blocked"


@router.patch("/users/{user_id}/status")
async def update_user_status(
    user_id: str,
    update: UserStatusUpdate,
    current_admin: dict = Depends(get_current_admin)
):
    """Block or unblock a user (admin only)."""
    if update.status not in ["active", "blocked"]:
        raise HTTPException(status_code=400, detail="Invalid status. Must be 'active' or 'blocked'.")

    db = get_database()
    from bson import ObjectId
    try:
        query = {"_id": ObjectId(user_id)}
    except Exception:
        query = {"_id": user_id}

    user = await db.users.find_one(query)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    await db.users.update_one(query, {"$set": {"status": update.status}})

    await log_security_event(
        event_type="admin_action",
        description=f"Admin {current_admin['email']} set status of {user.get('email')} to {update.status}",
        user_id=str(current_admin["_id"]),
    )

    return {"message": f"User status updated to '{update.status}'"}


# --- Learning Engine Endpoints ---

@router.get("/model/versions")
async def get_ml_model_versions(current_admin: dict = Depends(get_current_admin)):
    """Get model version history."""
    versions = await get_model_versions()
    return {"versions": versions}


@router.get("/model/performance")
async def get_ml_performance(current_admin: dict = Depends(get_current_admin)):
    """Get current model performance and drift analysis."""
    metrics = await get_performance_metrics()
    return metrics


@router.post("/model/retrain")
async def trigger_model_retrain(current_admin: dict = Depends(get_current_admin)):
    """Trigger model retraining (records event, actual retraining is separate)."""
    version = await record_retrain_event(
        admin_id=str(current_admin["_id"]),
        notes="Admin-triggered retraining via dashboard"
    )

    await log_security_event(
        event_type="model_retrained",
        description=f"Model retraining triggered by {current_admin['email']} — version {version['version']}",
        user_id=str(current_admin["_id"]),
    )

    return {"message": "Model retraining recorded", "version": version}


# --- Behavioral Analytics Endpoints ---

@router.get("/behavior/summary")
async def get_behavior_summary(current_admin: dict = Depends(get_current_admin)):
    """Get platform-wide behavioral analytics."""
    summary = await get_platform_behavior_summary()
    return summary


@router.get("/threat/prediction")
async def get_threat_prediction(current_admin: dict = Depends(get_current_admin)):
    """Get AI-based threat prediction and trend analysis."""
    trend = await predict_threat_trend(hours=168)
    return trend
