"""
Adaptive Risk Scoring Engine & AI-Based Threat Prediction

- Multi-factor scoring combining ML probability, threat intel, SSL, domain age,
  content analysis, and behavioral patterns.
- Trend analysis to predict if a domain/IP is likely to become malicious.
"""

import math
import logging
from datetime import datetime, timezone, timedelta
from backend.database.connection import get_database

logger = logging.getLogger("RiskEngine")

# Weight factors for composite risk scoring
RISK_WEIGHTS = {
    "ml_probability": 0.30,
    "threat_intel": 0.20,
    "ssl_anomaly": 0.10,
    "domain_age": 0.10,
    "content_suspicion": 0.15,
    "network_anomaly": 0.10,
    "behavioral_pattern": 0.05,
}


def compute_adaptive_risk_score(
    ml_probability: float,
    threat_intel: dict,
    ssl_details: dict,
    whois_info: dict,
    website_analysis: dict,
    dns_records: dict,
    features: dict,
) -> dict:
    """
    Compute a composite risk score (0-100) from multiple signal sources.
    Returns score, confidence, and contributing factor breakdown.
    """
    factors = {}

    # 1. ML Model Probability (0-100)
    ml_score = ml_probability * 100
    factors["ml_probability"] = {"score": round(ml_score, 1), "weight": RISK_WEIGHTS["ml_probability"]}

    # 2. Threat Intelligence Score
    ti_score = 0
    if threat_intel:
        if threat_intel.get("is_blacklisted", False):
            ti_score = 100
        else:
            hits = 0
            checks = 0
            for provider in ["virustotal", "google_safe_browsing", "phishtank", "openphish"]:
                info = threat_intel.get(provider, {})
                if info.get("detected", False):
                    hits += 1
                checks += 1
            ti_score = (hits / max(checks, 1)) * 100
    factors["threat_intel"] = {"score": round(ti_score, 1), "weight": RISK_WEIGHTS["threat_intel"]}

    # 3. SSL Anomaly Score
    ssl_score = 0
    if ssl_details:
        if not ssl_details.get("valid", True):
            ssl_score = 80
        if ssl_details.get("issuer", "") == "Unknown" or ssl_details.get("issuer", "") == "":
            ssl_score = max(ssl_score, 60)
    if features.get("https_status", 1) == 0:
        ssl_score = max(ssl_score, 70)
    factors["ssl_anomaly"] = {"score": round(ssl_score, 1), "weight": RISK_WEIGHTS["ssl_anomaly"]}

    # 4. Domain Age Score (young domains are riskier)
    domain_age_score = 0
    if whois_info:
        age_days = whois_info.get("domain_age_days", 365)
        if age_days < 30:
            domain_age_score = 90
        elif age_days < 90:
            domain_age_score = 70
        elif age_days < 180:
            domain_age_score = 50
        elif age_days < 365:
            domain_age_score = 30
        elif age_days < 1000:
            domain_age_score = 10
        else:
            domain_age_score = 0
    factors["domain_age"] = {"score": round(domain_age_score, 1), "weight": RISK_WEIGHTS["domain_age"]}

    # 5. Content Suspicion Score
    content_score = 0
    if website_analysis:
        suspicion_signals = [
            website_analysis.get("has_login_form", 0) * 25,
            min(website_analysis.get("hidden_inputs_count", 0) * 15, 30),
            min(website_analysis.get("iframe_count", 0) * 20, 40),
            website_analysis.get("is_obfuscated_js_present", 0) * 35,
            min(website_analysis.get("suspicious_html_redirects", 0) * 20, 40),
        ]
        content_score = min(sum(suspicion_signals), 100)
    factors["content_suspicion"] = {"score": round(content_score, 1), "weight": RISK_WEIGHTS["content_suspicion"]}

    # 6. Network Anomaly Score
    network_score = 0
    if features:
        if features.get("has_ip", 0) == 1:
            network_score += 40
        if features.get("num_redirects", 0) > 2:
            network_score += 30
        if features.get("is_shortened", 0) == 1:
            network_score += 20
        if features.get("entropy_score", 0) > 4.0:
            network_score += 10
    network_score = min(network_score, 100)
    factors["network_anomaly"] = {"score": round(network_score, 1), "weight": RISK_WEIGHTS["network_anomaly"]}

    # 7. Behavioral Pattern (placeholder — will be enriched by behavior_analytics)
    behavioral_score = 0
    factors["behavioral_pattern"] = {"score": round(behavioral_score, 1), "weight": RISK_WEIGHTS["behavioral_pattern"]}

    # Compute weighted composite score
    composite = sum(
        factors[k]["score"] * factors[k]["weight"] for k in factors
    )
    composite = min(max(round(composite), 0), 100)

    # Confidence level based on how many sources contributed non-zero
    active_sources = sum(1 for k in factors if factors[k]["score"] > 0)
    total_sources = len(factors)
    confidence = round((active_sources / total_sources) * 100)

    # Risk level classification
    if composite >= 80:
        risk_level = "critical"
    elif composite >= 60:
        risk_level = "high"
    elif composite >= 40:
        risk_level = "medium"
    else:
        risk_level = "low"

    return {
        "composite_score": composite,
        "risk_level": risk_level,
        "confidence": confidence,
        "factors": factors,
    }


def extract_malware_indicators(website_analysis: dict, features: dict) -> dict:
    """
    Extract malware-related indicators from website content analysis.
    """
    indicators = {
        "obfuscated_javascript": bool(website_analysis.get("is_obfuscated_js_present", 0)),
        "suspicious_iframes": website_analysis.get("iframe_count", 0),
        "hidden_form_inputs": website_analysis.get("hidden_inputs_count", 0),
        "external_script_injection": website_analysis.get("external_scripts_count", 0),
        "html_redirects": website_analysis.get("suspicious_html_redirects", 0),
        "has_login_form": bool(website_analysis.get("has_login_form", 0)),
        "drive_by_download_risk": (
            website_analysis.get("is_obfuscated_js_present", 0) == 1
            and website_analysis.get("iframe_count", 0) > 0
        ),
        "credential_harvesting_risk": (
            website_analysis.get("has_login_form", 0) == 1
            and website_analysis.get("hidden_inputs_count", 0) > 0
        ),
    }

    # Threat level for malware
    score = 0
    if indicators["obfuscated_javascript"]:
        score += 35
    if indicators["suspicious_iframes"] > 0:
        score += 20
    if indicators["drive_by_download_risk"]:
        score += 25
    if indicators["credential_harvesting_risk"]:
        score += 20

    indicators["malware_risk_score"] = min(score, 100)
    indicators["malware_risk_level"] = (
        "critical" if score >= 80
        else "high" if score >= 60
        else "medium" if score >= 30
        else "low"
    )

    # Specific malware signature identification based on pattern
    malware_name = "None Detected"
    if indicators["obfuscated_javascript"] and indicators["suspicious_iframes"] > 0:
        malware_name = "Trojan.JS.Downloader.Heur"
    elif indicators["obfuscated_javascript"]:
        malware_name = "Spyware.JS.Obfuscated"
    elif indicators["suspicious_iframes"] > 0:
        malware_name = "Exploit.HTML.Iframe.Injection"
    elif indicators["drive_by_download_risk"]:
        malware_name = "Trojan.HTML.DriveByDownload"
    elif indicators["credential_harvesting_risk"]:
        malware_name = "Phish.HTML.CredentialStealer"
    elif indicators["external_script_injection"] > 0:
        malware_name = "Malware.JS.ExternalScript"
    elif indicators["html_redirects"] > 0:
        malware_name = "Adware.HTML.Redirector"

    indicators["malware_name"] = malware_name

    return indicators


def extract_network_indicators(dns_records: dict, ssl_details: dict, features: dict, whois_info: dict) -> dict:
    """
    Extract network intrusion-related indicators from DNS, SSL, and URL features.
    """
    indicators = {
        "ip_based_hosting": bool(features.get("has_ip", 0)),
        "redirect_chain_length": features.get("num_redirects", 0),
        "url_shortener_used": bool(features.get("is_shortened", 0)),
        "high_entropy_domain": features.get("entropy_score", 0) > 4.0,
        "dns_records_found": bool(dns_records.get("A", [])),
        "mx_records_present": bool(dns_records.get("MX", [])),
        "ssl_valid": ssl_details.get("valid", False) if ssl_details else False,
        "ssl_issuer": ssl_details.get("issuer", "Unknown") if ssl_details else "Unknown",
        "domain_age_days": whois_info.get("domain_age_days", -1) if whois_info else -1,
        "young_domain": (whois_info.get("domain_age_days", 999) < 90) if whois_info else False,
    }

    # Network threat score
    score = 0
    if indicators["ip_based_hosting"]:
        score += 25
    if indicators["redirect_chain_length"] > 2:
        score += 20
    if indicators["url_shortener_used"]:
        score += 15
    if indicators["high_entropy_domain"]:
        score += 15
    if not indicators["ssl_valid"]:
        score += 15
    if indicators["young_domain"]:
        score += 10

    indicators["network_risk_score"] = min(score, 100)
    indicators["network_risk_level"] = (
        "critical" if score >= 80
        else "high" if score >= 60
        else "medium" if score >= 30
        else "low"
    )

    return indicators


async def predict_threat_trend(hours: int = 168) -> dict:
    """
    AI-Based Threat Prediction: Analyze scan history to predict threat trends.
    Looks at the last N hours of scans and projects risk trajectory.
    """
    db = get_database()
    cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)

    cursor = db.scans.find({"scan_time": {"$gte": cutoff}})
    scans = await cursor.to_list(500)

    if not scans:
        return {
            "period_hours": hours,
            "total_scans": 0,
            "trend": "stable",
            "avg_risk": 0,
            "prediction": "Insufficient data for trend analysis.",
            "time_series": [],
        }

    # Build time series (group by 6-hour buckets)
    bucket_size = 6
    buckets = {}
    for scan in scans:
        st = scan.get("scan_time")
        if isinstance(st, str):
            try:
                st = datetime.fromisoformat(st)
            except Exception:
                continue
        if isinstance(st, datetime):
            bucket_key = st.strftime("%Y-%m-%d") + f" {(st.hour // bucket_size) * bucket_size:02d}:00"
            if bucket_key not in buckets:
                buckets[bucket_key] = {"total": 0, "phishing": 0, "risk_sum": 0}
            buckets[bucket_key]["total"] += 1
            if scan.get("prediction") == "PHISHING":
                buckets[bucket_key]["phishing"] += 1
            buckets[bucket_key]["risk_sum"] += scan.get("risk_score", 0)

    time_series = []
    for key in sorted(buckets.keys()):
        b = buckets[key]
        time_series.append({
            "period": key,
            "total_scans": b["total"],
            "phishing_detected": b["phishing"],
            "avg_risk": round(b["risk_sum"] / b["total"], 1) if b["total"] > 0 else 0,
        })

    # Determine trend
    total_scans = len(scans)
    phishing_count = sum(1 for s in scans if s.get("prediction") == "PHISHING")
    avg_risk = sum(s.get("risk_score", 0) for s in scans) / total_scans if total_scans > 0 else 0

    # Compare first half vs second half
    mid = len(time_series) // 2
    if mid > 0 and len(time_series) > 1:
        first_half_risk = sum(t["avg_risk"] for t in time_series[:mid]) / mid
        second_half_risk = sum(t["avg_risk"] for t in time_series[mid:]) / max(len(time_series[mid:]), 1)
        if second_half_risk > first_half_risk * 1.2:
            trend = "increasing"
            prediction = "Threat levels are rising. Recommend increased monitoring and tighter URL policies."
        elif second_half_risk < first_half_risk * 0.8:
            trend = "decreasing"
            prediction = "Threat levels are decreasing. Current security measures appear effective."
        else:
            trend = "stable"
            prediction = "Threat levels remain stable. Continue monitoring for changes."
    else:
        trend = "stable"
        prediction = "Limited data available. Continue collecting scans for better trend analysis."

    return {
        "period_hours": hours,
        "total_scans": total_scans,
        "phishing_detected": phishing_count,
        "phishing_rate": round((phishing_count / total_scans * 100), 1) if total_scans > 0 else 0,
        "avg_risk": round(avg_risk, 1),
        "trend": trend,
        "prediction": prediction,
        "time_series": time_series,
    }
