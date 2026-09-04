"""
Behavioral Analytics Service

Tracks user scanning patterns, detects anomalous behavior,
and stores behavioral profiles in user_behavior collection.
"""

import logging
from datetime import datetime, timezone, timedelta
from backend.database.connection import get_database

logger = logging.getLogger("BehaviorAnalytics")


async def record_scan_behavior(user_id: str, url: str, risk_score: int, prediction: str):
    """Record a scan event for behavioral analysis."""
    db = get_database()
    behavior_doc = {
        "user_id": user_id,
        "url": url,
        "risk_score": risk_score,
        "prediction": prediction,
        "timestamp": datetime.now(timezone.utc),
        "hour_of_day": datetime.now(timezone.utc).hour,
        "day_of_week": datetime.now(timezone.utc).weekday(),
    }
    try:
        await db.behavior_logs.insert_one(behavior_doc)
    except Exception as e:
        logger.error(f"Failed to record behavior: {e}")


async def get_user_behavior_profile(user_id: str) -> dict:
    """Build a behavioral profile for a specific user."""
    db = get_database()
    cursor = db.behavior_logs.find({"user_id": user_id})
    logs = await cursor.to_list(500)

    if not logs:
        return {
            "user_id": user_id,
            "total_scans": 0,
            "phishing_detected": 0,
            "phishing_rate": 0,
            "avg_risk_score": 0,
            "scan_by_hour": {},
            "scan_by_day": {},
            "risk_distribution": {"low": 0, "medium": 0, "high": 0, "critical": 0},
            "active_hours": [],
            "anomaly_detected": False,
            "anomaly_reasons": [],
            "profile": "new_user",
        }

    total = len(logs)
    phishing_count = sum(1 for l in logs if l.get("prediction") == "PHISHING")

    # Hour distribution
    hour_dist = {}
    for l in logs:
        h = l.get("hour_of_day", 0)
        hour_dist[h] = hour_dist.get(h, 0) + 1

    # Day distribution
    day_dist = {}
    day_names = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
    for l in logs:
        d = l.get("day_of_week", 0)
        day_name = day_names[d] if d < 7 else "Unknown"
        day_dist[day_name] = day_dist.get(day_name, 0) + 1

    # Risk distribution
    risk_buckets = {"low": 0, "medium": 0, "high": 0, "critical": 0}
    for l in logs:
        rs = l.get("risk_score", 0)
        if rs >= 80:
            risk_buckets["critical"] += 1
        elif rs >= 60:
            risk_buckets["high"] += 1
        elif rs >= 40:
            risk_buckets["medium"] += 1
        else:
            risk_buckets["low"] += 1

    # Most active hours
    sorted_hours = sorted(hour_dist.items(), key=lambda x: x[1], reverse=True)
    active_hours = [h for h, _ in sorted_hours[:5]]

    # Average risk
    avg_risk = sum(l.get("risk_score", 0) for l in logs) / total

    # Anomaly detection: flag if user has unusual spike or high-risk concentration
    anomaly = False
    anomaly_reasons = []

    # Check recent 1-hour spike
    one_hour_ago = datetime.now(timezone.utc) - timedelta(hours=1)
    recent_logs = []
    for l in logs:
        ts = l.get("timestamp")
        if isinstance(ts, datetime):
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
            if ts >= one_hour_ago:
                recent_logs.append(l)
    if len(recent_logs) > 20:
        anomaly = True
        anomaly_reasons.append(f"High scan frequency: {len(recent_logs)} scans in last hour")

    # Check high-risk concentration
    if total > 5 and (phishing_count / total) > 0.7:
        anomaly = True
        anomaly_reasons.append(f"High phishing URL rate: {round(phishing_count/total*100)}%")

    return {
        "user_id": user_id,
        "total_scans": total,
        "phishing_detected": phishing_count,
        "phishing_rate": round((phishing_count / total * 100), 1) if total > 0 else 0,
        "avg_risk_score": round(avg_risk, 1),
        "scan_by_hour": hour_dist,
        "scan_by_day": day_dist,
        "risk_distribution": risk_buckets,
        "active_hours": active_hours,
        "anomaly_detected": anomaly,
        "anomaly_reasons": anomaly_reasons,
        "profile": (
            "power_user" if total > 50
            else "regular" if total > 10
            else "casual" if total > 3
            else "new_user"
        ),
    }


async def get_platform_behavior_summary() -> dict:
    """Get platform-wide behavioral analytics summary."""
    db = get_database()
    cursor = db.behavior_logs.find({})
    logs = await cursor.to_list(1000)

    if not logs:
        return {
            "total_scans_tracked": 0,
            "unique_users": 0,
            "hourly_distribution": {},
            "daily_distribution": {},
            "avg_risk_score": 0,
            "anomalous_users": [],
        }

    total = len(logs)
    unique_users = list(set(l.get("user_id", "") for l in logs))

    # Global hour distribution
    hour_dist = {}
    for l in logs:
        h = l.get("hour_of_day", 0)
        hour_dist[str(h)] = hour_dist.get(str(h), 0) + 1

    # Global day distribution
    day_names = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
    day_dist = {}
    for l in logs:
        d = l.get("day_of_week", 0)
        day_name = day_names[d] if d < 7 else "Unknown"
        day_dist[day_name] = day_dist.get(day_name, 0) + 1

    avg_risk = sum(l.get("risk_score", 0) for l in logs) / total if total > 0 else 0

    # Find anomalous users
    anomalous_users = []
    for uid in unique_users[:20]:  # Check top 20 users
        profile = await get_user_behavior_profile(uid)
        if profile.get("anomaly_detected"):
            anomalous_users.append({
                "user_id": uid,
                "reasons": profile.get("anomaly_reasons", [])
            })

    return {
        "total_scans_tracked": total,
        "unique_users": len(unique_users),
        "hourly_distribution": hour_dist,
        "daily_distribution": day_dist,
        "avg_risk_score": round(avg_risk, 1),
        "anomalous_users": anomalous_users,
    }
