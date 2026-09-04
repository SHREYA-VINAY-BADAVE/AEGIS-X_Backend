import os
import socket
import pickle
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, status, Response
from pydantic import BaseModel, HttpUrl
from bson import ObjectId
from backend.database.connection import get_database
from backend.middleware.auth import get_current_user
from ml.extractor import extract_features
from backend.services.scanner import (
    clean_hostname,
    get_dns_records,
    get_ssl_details,
    get_whois_info,
    analyze_website_content,
    query_threat_intelligence
)
from backend.utils.pdf_generator import generate_pdf_report
from backend.services.threat_monitor import emit_threat_event, classify_severity
from backend.services.risk_engine import (
    compute_adaptive_risk_score,
    extract_malware_indicators,
    extract_network_indicators,
)
from backend.services.behavior_analytics import record_scan_behavior
from backend.routes.incidents import auto_create_incident

router = APIRouter(prefix="/scan", tags=["scan"])

# Lazy loader for ML assets
_model = None
_explainer = None

def get_ml_assets():
    global _model, _explainer
    if _model is None or _explainer is None:
        import sys
        from ml import models
        sys.modules['models'] = models

        assets_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "assets")
        # Fallback to old absolute path if relative doesn't work
        if not os.path.exists(assets_dir):
            assets_dir = r"C:\Users\abhij\.gemini\antigravity\scratch\phishing-detection-ml\backend\assets"

        model_path = os.path.join(assets_dir, "best_model.pkl")
        explainer_path = os.path.join(assets_dir, "shap_explainer.pkl")
        
        if not os.path.exists(model_path) or not os.path.exists(explainer_path):
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="ML model assets have not been trained or loaded yet."
            )
            
        with open(model_path, "rb") as f:
            _model = pickle.load(f)
        with open(explainer_path, "rb") as f:
            _explainer = pickle.load(f)
            
    return _model, _explainer

class ScanRequest(BaseModel):
    url: str

# Feature list mapping
FEATURES_LIST = [
    "url_length", "domain_length", "https_status", "num_dots", "num_hyphens",
    "num_digits", "num_special_chars", "num_redirects", "has_ip",
    "has_suspicious_keyword", "is_shortened", "entropy_score"
]

@router.post("")
async def scan_url(request: ScanRequest, current_user: dict = Depends(get_current_user)):
    url = request.url.strip()
    
    # Basic URL cleaning
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
        
    # Check if domain exists (real-time presence validation)
    hostname = clean_hostname(url)
    if not hostname:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Invalid URL format or missing hostname."
        )
        
    is_mock = "aegis-x-mock" in hostname or hostname == "localhost" or hostname == "127.0.0.1"
    if not is_mock:
        try:
            socket.gethostbyname(hostname)
        except socket.gaierror:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"The domain '{hostname}' does not exist or is unreachable. Please verify the URL."
            )
            
    db = get_database()
    model, explainer = get_ml_assets()
    
    # 1. Feature extraction
    try:
        features = extract_features(url, check_redirects=True)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Failed to extract features from URL: {e}"
        )
        
    # Convert features to vector
    vector = [features[feat] for feat in FEATURES_LIST]
    
    # 2. Prediction & Risk Score
    try:
        proba = model.predict_proba([vector])[0][1]  # Phishing probability
        pred = 1 if proba >= 0.5 else 0
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Inference failure: {e}"
        )
        
    # 3. SHAP local explainability
    try:
        shap_values = explainer.explain(vector)
        shap_dict = {FEATURES_LIST[i]: float(shap_values[i]) for i in range(len(FEATURES_LIST))}
    except Exception as e:
        shap_dict = {feat: 0.0 for feat in FEATURES_LIST}
        
    # 4. Domain & Website Deep Analysis
    hostname = clean_hostname(url)
    dns_records = get_dns_records(hostname)
    ssl_details = get_ssl_details(hostname)
    whois_info = get_whois_info(hostname)
    website_analysis = analyze_website_content(url)
    threat_intel = query_threat_intelligence(url)
    
    # 5. Adaptive Risk Scoring (NEW)
    adaptive_risk = compute_adaptive_risk_score(
        ml_probability=proba,
        threat_intel=threat_intel,
        ssl_details=ssl_details,
        whois_info=whois_info,
        website_analysis=website_analysis,
        dns_records=dns_records,
        features=features,
    )
    risk_score = adaptive_risk["composite_score"]

    # Ensure legitimate, authenticated, and proper websites get a correct and safe indication
    is_authenticated_and_proper = (
        ssl_details.get("valid", False) is True
        and not threat_intel.get("is_blacklisted", False)
        and whois_info.get("domain_age_days", 0) >= 365
        and website_analysis.get("is_obfuscated_js_present", 0) == 0
    )
    
    if is_authenticated_and_proper:
        pred = 0
        risk_score = min(risk_score, 15)  # Cap risk score at 15% for pre-verified legitimate sites
        adaptive_risk["risk_level"] = "low"
        adaptive_risk["composite_score"] = risk_score

    # 6. Malware Indicators (NEW)
    malware_indicators = extract_malware_indicators(website_analysis, features)

    # 7. Network Indicators (NEW)
    network_indicators = extract_network_indicators(dns_records, ssl_details, features, whois_info)

    # 8. Core Scan Document
    scan_doc = {
        "url": url,
        "prediction": "PHISHING" if pred == 1 else "BENIGN",
        "risk_score": risk_score,
        "risk_level": adaptive_risk["risk_level"],
        "risk_confidence": adaptive_risk["confidence"],
        "risk_factors": adaptive_risk["factors"],
        "features": features,
        "shap_values": shap_dict,
        "dns": dns_records,
        "whois": whois_info,
        "ssl": ssl_details,
        "website_analysis": website_analysis,
        "threat_intel": threat_intel,
        "malware_indicators": malware_indicators,
        "network_indicators": network_indicators,
        "scan_time": datetime.now(timezone.utc),
        "user_id": current_user["_id"]
    }
    
    # Save to MongoDB
    res = await db.scans.insert_one(scan_doc)
    scan_doc["_id"] = str(res.inserted_id)
    
    # 9. Emit Threat Event (NEW)
    severity = classify_severity(risk_score)
    event_type = "phishing_detected" if pred == 1 else "url_scan"
    await emit_threat_event(
        event_type=event_type,
        description=f"URL scanned: {url} — Risk: {risk_score}% ({adaptive_risk['risk_level']})",
        severity=severity,
        risk_score=risk_score,
        source_url=url,
        user_id=current_user["_id"],
        metadata={
            "prediction": scan_doc["prediction"],
            "scan_id": scan_doc["_id"],
        }
    )

    # 10. Emit malware/network events if high risk
    if malware_indicators.get("malware_risk_score", 0) >= 60:
        await emit_threat_event(
            event_type="malware_indicator",
            description=f"Malware Signature '{malware_indicators.get('malware_name', 'Unknown')}' detected on {url} (score: {malware_indicators['malware_risk_score']})",
            severity=malware_indicators["malware_risk_level"],
            risk_score=malware_indicators["malware_risk_score"],
            source_url=url,
            user_id=current_user["_id"],
        )

    if network_indicators.get("network_risk_score", 0) >= 60:
        await emit_threat_event(
            event_type="network_anomaly",
            description=f"Network anomalies detected for {url} (score: {network_indicators['network_risk_score']})",
            severity=network_indicators["network_risk_level"],
            risk_score=network_indicators["network_risk_score"],
            source_url=url,
            user_id=current_user["_id"],
        )

    # 11. Record behavioral data (NEW)
    await record_scan_behavior(
        user_id=current_user["_id"],
        url=url,
        risk_score=risk_score,
        prediction=scan_doc["prediction"],
    )

    # 12. Auto-create incident if high risk (NEW)
    if risk_score >= 70:
        incident = await auto_create_incident(scan_doc)
        if incident:
            scan_doc["incident_id"] = incident.get("_id")

    return scan_doc

@router.get("/history")
async def get_scan_history(current_user: dict = Depends(get_current_user)):
    db = get_database()
    scans_cursor = db.scans.find({"user_id": current_user["_id"]})
    scans = await scans_cursor.to_list(100)
    
    # Format ObjectId for response
    for s in scans:
        s["_id"] = str(s["_id"])
        if "scan_time" in s and isinstance(s["scan_time"], datetime):
            s["scan_time"] = s["scan_time"].isoformat()
            
    # Sort scans list manually by time descending
    scans = sorted(scans, key=lambda x: x.get("scan_time", ""), reverse=True)
    return scans

@router.get("/report/{scan_id}")
async def get_pdf_report(scan_id: str, current_user: dict = Depends(get_current_user)):
    db = get_database()
    try:
        query = {"_id": ObjectId(scan_id)}
    except Exception:
        query = {"_id": scan_id}
        
    scan = await db.scans.find_one(query)
    
    if not scan:
        scan = await db.scans.find_one({"_id": scan_id})
        
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan record not found."
        )
        
    if scan.get("user_id") != current_user["_id"] and current_user.get("role") != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Unauthorized to access this scan report."
        )
        
    pdf_bytes = generate_pdf_report(scan)
    
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f"attachment; filename=aegis_x_assessment_{scan_id}.pdf"
        }
    )

@router.get("/{scan_id}")
async def get_scan_details(scan_id: str, current_user: dict = Depends(get_current_user)):
    db = get_database()
    try:
        query = {"_id": ObjectId(scan_id)}
    except Exception:
        query = {"_id": scan_id}
        
    scan = await db.scans.find_one(query)
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan record not found."
        )
        
    # Format ObjectId for response
    scan["_id"] = str(scan["_id"])
    if "scan_time" in scan and isinstance(scan["scan_time"], datetime):
        scan["scan_time"] = scan["scan_time"].isoformat()
        
    return scan

@router.delete("/{scan_id}")
async def delete_scan(scan_id: str, current_user: dict = Depends(get_current_user)):
    db = get_database()
    try:
        query = {"_id": ObjectId(scan_id)}
    except Exception:
        query = {"_id": scan_id}
        
    scan = await db.scans.find_one(query)
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan record not found."
        )
        
    if scan.get("user_id") != current_user["_id"] and current_user.get("role") != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Unauthorized to delete this scan record."
        )
        
    await db.scans.delete_one(query)
    return {"status": "success", "message": "Scan record deleted successfully."}
