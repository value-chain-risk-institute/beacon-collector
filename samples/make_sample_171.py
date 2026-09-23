#!/usr/bin/env python3
"""Build a SYNTHETIC sealed evidence package for a fictitious small defense supplier, to demonstrate
the 800-171 coverage bundle. Every item is labelled synthetic in its observation. Unsigned (0.2 mode)."""
import json, os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import beaconlib as bl

def obs_item(slot, tool, observation):
    return {"subcriterion": slot, "mode": "scanner" if tool in ("trivy","openscap","wazuh") else "export",
            "epistemic": "observed_scan" if tool in ("trivy","openscap","wazuh") else "observed_export",
            "tool": tool, "verified_by_collector": True, "collected_utc": bl.utcnow(),
            "observation": observation, "synthetic": True}
def att_item(slot, doc, section):
    return {"subcriterion": slot, "mode": "document", "epistemic": "third_party_attestation",
            "tool": "docs.py", "collected_utc": bl.utcnow(),
            "observation": {"attestation": {"present": True, "document": doc, "section": section}}, "synthetic": True}

items = [
  obs_item("technology-v1:1.1a", "trivy", {"package_inventory": {"present": True, "count": 412}, "sbom": {"standalone": True, "format": "CycloneDX 1.6"}, "signed_attestation": {"present": False}}),
  obs_item("technology-v1:1.1b", "openscap", {"checks_evaluated": {"present": True, "passed": 187, "failed": 6, "profile": "CIS Ubuntu 22.04 L1"}}),
  obs_item("technology-v1:4.4a", "trivy", {"vulnerability_findings": {"present": True, "by_severity": {"critical": 0, "high": 3, "medium": 41, "low": 88}, "fix_available": 39}}),
  obs_item("people-v1:mfa", "okta-export", {"mfa": {"present": True, "coverage_fraction": 0.96, "total_users": 48, "enrolled": 46}}),
  obs_item("people-v1:jml", "okta-export", {"jml": {"present": True, "total_records": 61, "disabled_or_suspended_still_present": 0, "last_deprovision_days": 3}}),
  obs_item("people-v1:least-privilege", "okta-export", {"least_privilege": {"present": True, "privileged_fraction": 0.08, "admins": 4, "total": 48}}),
  obs_item("technology-v1:6.6a", "wazuh", {"siem": {"present": True, "agents_reporting": 39, "agents_total": 41, "retention_days": 400}}),
  att_item("technology-v1:2.2a", "SOC 2 Type II, FY2025 (Example Auditors LLP)", "CC6.1"),
  att_item("technology-v1:4.4b", "SOC 2 Type II, FY2025", "CC6.8"),
  att_item("technology-v1:4.4c", "SOC 2 Type II, FY2025", "CC6.6"),
  att_item("data-v1:in-transit", "SOC 2 Type II, FY2025", "CC6.7"),
  att_item("process-v1:change-management", "SOC 2 Type II, FY2025", "CC8.1"),
  att_item("process-v1:incident-response", "SOC 2 Type II, FY2025", "CC7.3, CC7.4"),
  att_item("process-v1:control-effectiveness", "SOC 2 Type II, FY2025", "CC4.1"),
]
subject = {"name": "Example Machining LLC (synthetic)", "scope": "engineering network handling CUI", "sector": "defense sub-tier supplier"}
collector = {"name": "beacon-collector", "version": "sample", "note": "SYNTHETIC package for the 800-171 coverage bundle demo; not a real organisation"}
core = bl.build_package(subject, collector, items)
pkg = bl.seal_and_sign(core, sign=False, home=os.path.expanduser("~/.beacon"))
out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sample-171-package.json")
json.dump(pkg, open(out, "w"), indent=1)
print("wrote", out, "items", len(items))
