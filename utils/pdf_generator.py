from fpdf import FPDF
import datetime

class PhishingScanPDF(FPDF):
    def header(self):
        # Draw header banner
        self.set_fill_color(22, 28, 45) # Dark cybersecurity theme
        self.rect(0, 0, 210, 40, 'F')
        
        self.set_text_color(255, 255, 255)
        self.set_font('helvetica', 'B', 18)
        self.cell(0, 10, 'AEGIS-X LABS - THREAT ANALYSIS REPORT', ln=True, align='C')
        
        self.set_font('helvetica', 'I', 10)
        self.cell(0, 5, f'Generated on: {datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}', ln=True, align='C')
        self.ln(10)

    def footer(self):
        # Position at 1.5 cm from bottom
        self.set_y(-15)
        self.set_font('helvetica', 'I', 8)
        self.set_text_color(128, 128, 128)
        self.cell(0, 10, f'Page {self.page_no()}/{{nb}} - AEGIS-X Intelligent Security Evaluation', align='C')

def generate_pdf_report(scan_data: dict) -> bytes:
    """
    Generate assessment report PDF byte string for the user.
    """
    pdf = PhishingScanPDF()
    pdf.alias_nb_pages()
    pdf.add_page()
    pdf.set_y(45) # Start below header banner
    
    # 1. URL Under Assessment card
    pdf.set_fill_color(240, 244, 248)
    pdf.rect(10, 45, 190, 20, 'F')
    pdf.set_font('helvetica', 'B', 11)
    pdf.set_text_color(22, 28, 45)
    pdf.set_x(15)
    pdf.cell(0, 10, 'URL Under Assessment:', ln=True)
    pdf.set_font('Courier', '', 10)
    pdf.set_x(15)
    url_str = scan_data.get('url', '')
    if len(url_str) > 75:
        url_str = url_str[:72] + "..."
    pdf.cell(0, 5, url_str, ln=True)
    pdf.ln(10)
    
    # 2. Risk Classification Card
    risk_score = int(scan_data.get('risk_score', 0))
    prediction = scan_data.get('prediction', 'BENIGN')
    
    # Color coding based on threats
    if prediction == 'PHISHING' or risk_score >= 70:
        fill_color = (254, 226, 226) # Red
        text_color = (185, 28, 28)
        label = "DANGER / PHISHING SUSPECTED"
    elif risk_score >= 40:
        fill_color = (254, 243, 199) # Yellow
        text_color = (180, 83, 9)
        label = "WARNING / SUSPICIOUS"
    else:
        fill_color = (220, 252, 231) # Green
        text_color = (21, 128, 61)
        label = "SECURE / BENIGN"
        
    pdf.set_fill_color(*fill_color)
    pdf.rect(10, 75, 190, 25, 'F')
    pdf.set_x(15)
    pdf.ln(2)
    pdf.set_font('helvetica', 'B', 12)
    pdf.set_text_color(*text_color)
    pdf.cell(0, 8, f'VERDICT: {label}', ln=True)
    pdf.set_font('helvetica', '', 11)
    pdf.set_text_color(50, 50, 50)
    risk_index_text = "UNSAFE" if prediction == "PHISHING" else "SAFE"
    pdf.cell(0, 8, f'Security Risk Index: {risk_index_text}  |  Threat Intel reputation: {"Malicious" if scan_data.get("threat_intel", {}).get("is_blacklisted") else "Clean"}', ln=True)
    
    pdf.ln(12)
    pdf.set_font('helvetica', 'B', 13)
    pdf.set_text_color(22, 28, 45)
    pdf.cell(0, 10, 'HEURISTIC FEATURE ANALYSIS SCORECARD', ln=True)
    pdf.line(10, pdf.get_y(), 200, pdf.get_y())
    pdf.ln(4)
    
    # Feature scores table
    pdf.set_font('helvetica', 'B', 9)
    pdf.set_fill_color(230, 235, 245)
    # Header cells
    pdf.cell(60, 7, 'Feature Parameter', 1, 0, 'L', True)
    pdf.cell(40, 7, 'Extracted Value', 1, 0, 'C', True)
    pdf.cell(60, 7, 'Heuristic Indication', 1, 0, 'L', True)
    pdf.cell(30, 7, 'SHAP Impact', 1, 1, 'C', True)
    
    pdf.set_font('helvetica', '', 9)
    features = scan_data.get('features', {})
    shap_vals = scan_data.get('shap_values', {})
    
    features_mapping = [
        ("url_length", "URL Length", lambda v: f"{v} chars", lambda v: "Long URL (>54)" if v > 54 else "Normal length"),
        ("domain_length", "Domain Length", lambda v: f"{v} chars", lambda v: "Long domain (>20)" if v > 20 else "Normal length"),
        ("https_status", "HTTPS Enabled", lambda v: "Yes" if v else "No", lambda v: "SSL protected" if v else "Insecure HTTP connection"),
        ("num_dots", "Number of Dots", lambda v: str(v), lambda v: "High dots count" if v > 3 else "Normal"),
        ("num_hyphens", "Number of Hyphens", lambda v: str(v), lambda v: "Contains hyphens" if v > 0 else "None"),
        ("num_digits", "Number of Digits", lambda v: str(v), lambda v: "Contains digits (>2)" if v > 2 else "None or trace"),
        ("num_special_chars", "Special Characters", lambda v: str(v), lambda v: "Special chars present" if v > 0 else "None"),
        ("num_redirects", "HTTP Redirects", lambda v: str(v), lambda v: "Redirect chain" if v > 0 else "Direct connection"),
        ("has_ip", "IP Address Domain", lambda v: "Yes" if v else "No", lambda v: "Spoofed IP hostname" if v else "Valid standard host"),
        ("has_suspicious_keyword", "Query Keywords", lambda v: "Yes" if v else "No", lambda v: "Contains credentials words" if v else "No trigger words"),
        ("is_shortened", "Shortened Link", lambda v: "Yes" if v else "No", lambda v: "Obfuscated via shortener" if v else "Normal Domain"),
        ("entropy_score", "Character Entropy", lambda v: f"{v:.3f}", lambda v: "High randomness" if v > 4.2 else "Standard distribution"),
    ]
    
    for key, display_name, val_formatter, label_generator in features_mapping:
        val = features.get(key, 0)
        shap_val = shap_vals.get(key, 0.0)
        
        pdf.cell(60, 6, display_name, 1, 0, 'L')
        pdf.cell(40, 6, val_formatter(val), 1, 0, 'C')
        pdf.cell(60, 6, label_generator(val), 1, 0, 'L')
        
        # Color SHAP impacts
        impact_str = f"{shap_val:+.3f}"
        if shap_val > 0.05:
            pdf.set_text_color(185, 28, 28) # Bad (red)
        elif shap_val < -0.05:
            pdf.set_text_color(21, 128, 61) # Good (green)
        else:
            pdf.set_text_color(80, 80, 80)
            
        pdf.cell(30, 6, impact_str, 1, 1, 'C')
        pdf.set_text_color(22, 28, 45) # Reset
        
    pdf.ln(5)
    
    # 3. Domain & SSL Card (If valid)
    whois_info = scan_data.get('whois', {})
    ssl_info = scan_data.get('ssl', {})
    
    pdf.set_font('helvetica', 'B', 13)
    pdf.cell(0, 10, 'DOMAIN WHOIS & SSL SECURITY DETAILS', ln=True)
    pdf.line(10, pdf.get_y(), 200, pdf.get_y())
    pdf.ln(4)
    
    pdf.set_font('helvetica', 'B', 10)
    pdf.cell(95, 6, 'WHOIS Information', 0, 0)
    pdf.cell(95, 6, 'SSL Certificate Details', 0, 1)
    
    pdf.set_font('helvetica', '', 9)
    pdf.cell(40, 5, 'Registrar:', 0, 0)
    pdf.cell(55, 5, whois_info.get('registrar', 'Unknown'), 0, 0)
    pdf.cell(40, 5, 'SSL Valid:', 0, 0)
    pdf.cell(55, 5, 'Yes' if ssl_info.get('valid') else 'No', 0, 1)
    
    pdf.cell(40, 5, 'Domain Age:', 0, 0)
    pdf.cell(55, 5, f"{whois_info.get('domain_age_days', 0)} days", 0, 0)
    pdf.cell(40, 5, 'Issuer Authority:', 0, 0)
    pdf.cell(55, 5, ssl_info.get('issuer', 'None'), 0, 1)
    
    pdf.cell(40, 5, 'Days to Expiry:', 0, 0)
    pdf.cell(55, 5, f"{whois_info.get('days_to_expiry', 0)} days", 0, 0)
    pdf.cell(40, 5, 'SSL Expiry Date:', 0, 0)
    pdf.cell(55, 5, str(ssl_info.get('expiry') or 'N/A'), 0, 1)
    
    pdf.ln(6)
    
    # 4. Security Action Plan
    pdf.set_font('helvetica', 'B', 13)
    pdf.cell(0, 10, 'SECURITY MITIGATION RECOMMENDATIONS', ln=True)
    pdf.line(10, pdf.get_y(), 200, pdf.get_y())
    pdf.ln(4)
    
    pdf.set_font('helvetica', '', 9)
    if prediction == 'PHISHING' or risk_score >= 70:
        recs = [
            "- DO NOT input passwords, bank credentials, or any personal details on this URL.",
            "- Immediately close the browser window or navigation tab displaying this content.",
            "- Report the URL to PhishTank (phishtank.com) and Google Safe Browsing.",
            "- If you entered any credentials, immediately change them on the official, legitimate platform.",
            "- Notify your IT Security team / system administrator about the suspicious link."
        ]
    elif risk_score >= 40:
        recs = [
            "- Proceed with extreme caution. The heuristics indicate warning signs.",
            "- Check the SSL certificate carefully and match the URL spelling with the official business domain.",
            "- Verify via official communication channels before making transactions.",
            "- Avoid downloading any files or software attachments from this website."
        ]
    else:
        recs = [
            "- URL is resolved as benign and safe under current heuristic checks.",
            "- Ensure the SSL padlock icon is always displayed in your browser address bar.",
            "- Remember that benign sites can sometimes be compromised, double check input fields."
        ]
        
    for rec in recs:
        pdf.cell(0, 5, rec, ln=True)
        
    return bytes(pdf.output())


class ReportSummaryPDF(FPDF):
    def header(self):
        self.set_fill_color(22, 28, 45)
        self.rect(0, 0, 210, 40, 'F')
        self.set_text_color(255, 255, 255)
        self.set_font('helvetica', 'B', 18)
        self.cell(0, 10, 'AEGIS-X - AUTOMATED THREAT SUMMARY', ln=True, align='C')
        self.set_font('helvetica', 'I', 10)
        self.cell(0, 5, f'Generated on: {datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}', ln=True, align='C')
        self.ln(10)

    def footer(self):
        self.set_y(-15)
        self.set_font('helvetica', 'I', 8)
        self.set_text_color(128, 128, 128)
        self.cell(0, 10, f'Page {self.page_no()}/{{nb}} - AEGIS-X Automated Report', align='C')


def generate_report_summary_pdf(summary: dict) -> bytes:
    """Generate a PDF summary report for a given period."""
    pdf = ReportSummaryPDF()
    pdf.alias_nb_pages()
    pdf.add_page()
    pdf.set_y(45)

    period = summary.get("period", "daily").capitalize()
    scan_summary = summary.get("scan_summary", {})
    incident_summary = summary.get("incident_summary", {})
    threat_trend = summary.get("threat_trend", {})

    # Period Header
    pdf.set_font('helvetica', 'B', 14)
    pdf.set_text_color(22, 28, 45)
    pdf.cell(0, 10, f'{period} Security Summary Report', ln=True)
    pdf.line(10, pdf.get_y(), 200, pdf.get_y())
    pdf.ln(6)

    # Scan Statistics
    pdf.set_font('helvetica', 'B', 12)
    pdf.cell(0, 8, 'Scan Statistics', ln=True)
    pdf.set_font('helvetica', '', 10)
    pdf.cell(0, 6, f'Total Scans: {scan_summary.get("total_scans", 0)}', ln=True)
    pdf.cell(0, 6, f'Phishing Detected: {scan_summary.get("phishing_detected", 0)}', ln=True)
    pdf.cell(0, 6, f'Benign Detected: {scan_summary.get("benign_detected", 0)}', ln=True)
    pdf.cell(0, 6, f'Detection Rate: {scan_summary.get("detection_rate", 0)}%', ln=True)
    pdf.cell(0, 6, f'Average Risk Score: {scan_summary.get("avg_risk_score", 0)}', ln=True)
    pdf.ln(4)

    # Incident Summary
    pdf.set_font('helvetica', 'B', 12)
    pdf.cell(0, 8, 'Incident Summary', ln=True)
    pdf.set_font('helvetica', '', 10)
    pdf.cell(0, 6, f'Total Incidents: {incident_summary.get("total_incidents", 0)}', ln=True)
    pdf.cell(0, 6, f'Open: {incident_summary.get("open", 0)}', ln=True)
    pdf.cell(0, 6, f'Resolved: {incident_summary.get("resolved", 0)}', ln=True)
    pdf.ln(4)

    # Threat Trend
    pdf.set_font('helvetica', 'B', 12)
    pdf.cell(0, 8, 'Threat Trend Analysis', ln=True)
    pdf.set_font('helvetica', '', 10)
    pdf.cell(0, 6, f'Trend Direction: {threat_trend.get("direction", "stable").capitalize()}', ln=True)
    pdf.cell(0, 6, f'Average Risk: {threat_trend.get("avg_risk", 0)}', ln=True)
    pdf.ln(2)
    prediction_text = threat_trend.get("prediction", "")
    if prediction_text:
        pdf.set_font('helvetica', 'I', 9)
        pdf.multi_cell(0, 5, prediction_text)
    pdf.ln(4)

    # Top Threats Table
    top_threats = summary.get("top_threats", [])
    if top_threats:
        pdf.set_font('helvetica', 'B', 12)
        pdf.cell(0, 8, 'Top Threats', ln=True)

        pdf.set_font('helvetica', 'B', 9)
        pdf.set_fill_color(230, 235, 245)
        pdf.cell(90, 7, 'URL', 1, 0, 'L', True)
        pdf.cell(30, 7, 'Verdict', 1, 0, 'C', True)
        pdf.cell(30, 7, 'Risk Score', 1, 0, 'C', True)
        pdf.cell(40, 7, 'Scan Time', 1, 1, 'C', True)

        pdf.set_font('helvetica', '', 8)
        for t in top_threats[:10]:
            url_str = t.get("url", "")
            if len(url_str) > 45:
                url_str = url_str[:42] + "..."
            pdf.cell(90, 6, url_str, 1, 0, 'L')
            pdf.cell(30, 6, t.get("prediction", ""), 1, 0, 'C')
            pdf.cell(30, 6, str(t.get("risk_score", 0)), 1, 0, 'C')
            scan_time = t.get("scan_time", "")
            if len(scan_time) > 19:
                scan_time = scan_time[:19]
            pdf.cell(40, 6, scan_time, 1, 1, 'C')

    return bytes(pdf.output())
