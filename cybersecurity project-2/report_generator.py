"""
Report Generator
================
Generates structured vulnerability reports from scan results.
"""

from datetime import datetime


def generate_report(scan_results):
    """Generate a comprehensive vulnerability report from scan results."""
    info = scan_results.get("scan_info", {})
    summary = scan_results.get("summary", {})
    services = scan_results.get("services", [])
    vulns = scan_results.get("vulnerabilities", [])
    sev = summary.get("severity_counts", {})

    report = {
        "report_metadata": {
            "generated_at": datetime.now().isoformat(),
            "scanner_version": "1.0.0",
            "report_type": "vulnerability_assessment",
        },
        "executive_summary": {
            "target": info.get("target", "unknown"),
            "resolved_ip": info.get("resolved_ip", "unknown"),
            "scan_duration": f"{info.get('duration_seconds', 0)}s",
            "ports_scanned": info.get("ports_scanned", 0),
            "open_ports_found": summary.get("open_ports", 0),
            "total_findings": summary.get("total_vulnerabilities", 0),
            "risk_score": summary.get("risk_score", 0),
            "risk_level": summary.get("risk_level", "NONE"),
            "critical_count": sev.get("CRITICAL", 0),
            "high_count": sev.get("HIGH", 0),
            "medium_count": sev.get("MEDIUM", 0),
            "low_count": sev.get("LOW", 0),
        },
        "detailed_findings": _categorize_findings(vulns),
        "service_inventory": _build_service_inventory(services),
        "remediation_plan": _build_remediation_plan(vulns),
        "raw_data": scan_results,
    }
    return report


def _categorize_findings(vulns):
    """Group findings by type."""
    categories = {
        "vulnerable_software": [],
        "risky_port": [],
        "missing_header": [],
        "ssl_issue": [],
        "other": [],
    }
    for v in vulns:
        t = v.get("type", "other")
        if t in categories:
            categories[t].append(v)
        else:
            categories["other"].append(v)
    return categories


def _build_service_inventory(services):
    """Build a clean inventory of discovered services."""
    inventory = []
    for svc in services:
        inventory.append({
            "port": svc.get("port"),
            "service": svc.get("service", "unknown"),
            "software": svc.get("software", ""),
            "version": svc.get("version", ""),
            "has_ssl": "ssl_cert" in svc,
        })
    return inventory


def _build_remediation_plan(vulns):
    """Build a prioritized remediation plan."""
    plan = []
    seen = set()
    priority_order = {"CRITICAL": 1, "HIGH": 2, "MEDIUM": 3, "LOW": 4, "INFO": 5}

    for v in vulns:
        rem = v.get("remediation", "")
        if not rem or rem in seen:
            continue
        seen.add(rem)
        plan.append({
            "priority": priority_order.get(v.get("severity", "INFO"), 5),
            "severity": v.get("severity", "INFO"),
            "action": rem,
            "related_port": v.get("port"),
            "related_cve": v.get("cve", ""),
        })

    plan.sort(key=lambda x: x["priority"])
    return plan
