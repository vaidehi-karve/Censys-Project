"""
Heuristic summarizer for Censys host data.
Provides deterministic fallback when LLM is unavailable.
"""

import json
from typing import Dict, List, Any, Optional
from collections import Counter


class HeuristicSummarizer:
    """
    Deterministic summarizer that extracts key security insights from Censys host data.
    Provides fallback when LLM services are unavailable.
    """
    
    def __init__(self):
        self.risk_priority = {"critical": 4, "high": 3, "medium": 2, "low": 1, "unknown": 0}
    
    def summarize(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate a structured summary of Censys host data using heuristic rules.
        
        Args:
            data: Censys host dataset with metadata and hosts array
            
        Returns:
            Structured JSON summary following the required schema
        """
        hosts = data.get("hosts", [])
        
        # Generate dataset overview
        dataset_overview = self._generate_dataset_overview(hosts)
        
        # Generate per-host summaries
        host_summaries = []
        for host in hosts:
            host_summary = self._summarize_host(host)
            host_summaries.append(host_summary)
        
        # Sort hosts by risk level (critical -> low -> unknown) then by IP
        host_summaries.sort(key=lambda h: (
            -self.risk_priority.get(h["risk_level"], 0),
            h["ip"]
        ))
        
        return {
            "dataset_overview": dataset_overview,
            "hosts": host_summaries,
            "meta": {
                "generator": "heuristic",
                "notes": "Generated using deterministic heuristic rules"
            }
        }
    
    def _generate_dataset_overview(self, hosts: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate high-level dataset summary."""
        if not hosts:
            return {
                "host_count": 0,
                "geo_distribution": [],
                "top_risks": [],
                "notable_cves": [],
                "malware_families": [],
                "overall_risk": "unknown"
            }
        
        # Count hosts
        host_count = len(hosts)
        
        # Geographic distribution
        countries = []
        for host in hosts:
            location = host.get("location", {})
            country = location.get("country", "Unknown")
            countries.append(country)
        
        geo_distribution = [f"{country} ({count})" for country, count in Counter(countries).items()]
        
        # Collect all CVEs
        all_cves = []
        for host in hosts:
            for service in host.get("services", []):
                for vuln in service.get("vulnerabilities", []):
                    cve_id = vuln.get("cve_id")
                    if cve_id:
                        all_cves.append(cve_id)
        
        # Get top CVEs (most frequent)
        cve_counts = Counter(all_cves)
        notable_cves = [cve for cve, count in cve_counts.most_common(5)]
        
        # Collect malware families
        malware_families = []
        for host in hosts:
            threat_intel = host.get("threat_intelligence", {})
            families = threat_intel.get("malware_families", [])
            malware_families.extend(families)
        
        malware_families = list(set(malware_families))  # Remove duplicates
        
        # Collect risk levels and generate top risks
        risk_levels = []
        top_risks = []
        
        for host in hosts:
            threat_intel = host.get("threat_intelligence", {})
            risk_level = threat_intel.get("risk_level", "unknown")
            risk_levels.append(risk_level)
            
            # Generate risk bullets
            if risk_level in ["critical", "high"]:
                ip = host.get("ip", "Unknown")
                top_risks.append(f"High-risk host {ip} detected")
            
            # Check for specific threats
            for service in host.get("services", []):
                if service.get("malware_detected"):
                    malware = service["malware_detected"]
                    name = malware.get("name", "Unknown malware")
                    top_risks.append(f"Malware detected: {name}")
                
                # Check for critical CVEs
                for vuln in service.get("vulnerabilities", []):
                    if vuln.get("severity") == "critical":
                        cve = vuln.get("cve_id", "Unknown CVE")
                        top_risks.append(f"Critical vulnerability: {cve}")
        
        # Determine overall risk
        if "critical" in risk_levels:
            overall_risk = "critical"
        elif "high" in risk_levels:
            overall_risk = "high"
        elif "medium" in risk_levels:
            overall_risk = "medium"
        elif "low" in risk_levels:
            overall_risk = "low"
        else:
            overall_risk = "unknown"
        
        return {
            "host_count": host_count,
            "geo_distribution": geo_distribution,
            "top_risks": top_risks[:10],  # Limit to top 10
            "notable_cves": notable_cves,
            "malware_families": malware_families,
            "overall_risk": overall_risk
        }
    
    def _summarize_host(self, host: Dict[str, Any]) -> Dict[str, Any]:
        """Generate detailed summary for a single host."""
        ip = host.get("ip", "Unknown")
        
        # Extract ASN
        asn = 0
        autonomous_system = host.get("autonomous_system", {})
        if autonomous_system:
            asn = autonomous_system.get("asn", 0)
        
        # Extract location
        location = host.get("location", {})
        city = location.get("city", "")
        country = location.get("country", "")
        location_str = f"{city}, {country}" if city and country else country or "Unknown"
        
        # Extract risk level
        threat_intel = host.get("threat_intelligence", {})
        risk_level = threat_intel.get("risk_level", "unknown")
        
        # Extract services
        services = []
        for service in host.get("services", []):
            protocol = service.get("protocol", "Unknown")
            port = service.get("port", 0)
            services.append(f"{protocol}:{port}")
        
        # Extract CVEs
        cves = []
        for service in host.get("services", []):
            for vuln in service.get("vulnerabilities", []):
                cve_id = vuln.get("cve_id")
                if cve_id and cve_id not in cves:
                    cves.append(cve_id)
        
        # Generate key findings
        key_findings = self._extract_key_findings(host)
        
        # Generate recommended actions
        recommended_actions = self._generate_recommended_actions(host)
        
        return {
            "ip": ip,
            "asn": asn,
            "location": location_str,
            "risk_level": risk_level,
            "key_findings": key_findings,
            "cves": cves,
            "services": services,
            "recommended_actions": recommended_actions
        }
    
    def _extract_key_findings(self, host: Dict[str, Any]) -> List[str]:
        """Extract key security findings from host data."""
        findings = []
        
        # DNS hostname
        dns = host.get("dns", {})
        if dns.get("hostname"):
            findings.append(f"DNS hostname: {dns['hostname']}")
        
        # Malware detection
        for service in host.get("services", []):
            malware = service.get("malware_detected")
            if malware:
                name = malware.get("name", "Unknown")
                confidence = malware.get("confidence", 0)
                findings.append(f"Malware detected: {name} (confidence: {confidence})")
                
                # Threat actors
                actors = malware.get("threat_actors", [])
                if actors:
                    findings.append(f"Associated threat actors: {', '.join(actors)}")
        
        # TLS certificates
        for service in host.get("services", []):
            cert = service.get("certificate")
            if cert:
                if cert.get("self_signed"):
                    findings.append("Self-signed TLS certificate detected")
                
                issuer = cert.get("issuer", "")
                if "BT-PANEL" in issuer or "宝塔面板" in issuer:
                    findings.append("Suspicious certificate issuer detected")
        
        # Authentication requirements
        for service in host.get("services", []):
            if service.get("authentication_required"):
                protocol = service.get("protocol", "Unknown")
                port = service.get("port", 0)
                findings.append(f"Authentication required on {protocol}:{port}")
        
        # Access restrictions
        for service in host.get("services", []):
            if service.get("access_restricted"):
                protocol = service.get("protocol", "Unknown")
                findings.append(f"Restricted access on {protocol}")
        
        # Operating system
        os_info = host.get("operating_system", {})
        if os_info:
            vendor = os_info.get("vendor", "")
            product = os_info.get("product", "")
            if vendor and product:
                findings.append(f"OS: {vendor} {product}")
        
        # Security labels
        threat_intel = host.get("threat_intelligence", {})
        labels = threat_intel.get("security_labels", [])
        if labels:
            findings.append(f"Security labels: {', '.join(labels)}")
        
        return findings
    
    def _generate_recommended_actions(self, host: Dict[str, Any]) -> List[str]:
        """Generate concrete remediation recommendations."""
        actions = []
        
        # CVE-based actions
        critical_cves = []
        high_cves = []
        
        for service in host.get("services", []):
            for vuln in service.get("vulnerabilities", []):
                severity = vuln.get("severity", "")
                cve_id = vuln.get("cve_id", "")
                
                if severity == "critical":
                    critical_cves.append(cve_id)
                elif severity == "high":
                    high_cves.append(cve_id)
        
        # Patch recommendations
        if critical_cves:
            actions.append(f"URGENT: Patch critical vulnerabilities: {', '.join(critical_cves)}")
        
        if high_cves:
            actions.append(f"Patch high-severity vulnerabilities: {', '.join(high_cves)}")
        
        # Service-specific recommendations
        for service in host.get("services", []):
            protocol = service.get("protocol", "")
            port = service.get("port", 0)
            
            # SSH recommendations
            if protocol == "SSH":
                actions.append("Update OpenSSH to latest version addressing known CVEs")
                actions.append("Implement SSH key-based authentication")
                actions.append("Disable root login and weak ciphers")
            
            # FTP recommendations
            elif protocol == "FTP":
                if not service.get("tls_enabled"):
                    actions.append("URGENT: Disable FTP or enforce FTPS with strong authentication")
                else:
                    actions.append("Review FTP TLS configuration and access controls")
            
            # HTTP recommendations
            elif protocol == "HTTP":
                if service.get("authentication_required"):
                    actions.append(f"Review authentication on HTTP:{port} - ensure strong credentials")
                else:
                    actions.append(f"Implement authentication on HTTP:{port}")
            
            # MySQL recommendations
            elif protocol == "MYSQL":
                if service.get("access_restricted"):
                    actions.append("Review MySQL access controls and network restrictions")
                else:
                    actions.append("Implement MySQL access controls and network restrictions")
        
        # Malware-specific actions
        for service in host.get("services", []):
            malware = service.get("malware_detected")
            if malware:
                actions.append("URGENT: Isolate host and run incident response playbook")
                actions.append("Conduct forensic analysis for malware persistence")
                actions.append("Review network traffic for C2 communications")
        
        # Certificate recommendations
        for service in host.get("services", []):
            cert = service.get("certificate")
            if cert and cert.get("self_signed"):
                actions.append("Replace self-signed certificates with trusted CA certificates")
                actions.append("Review certificate trust chain and validation")
        
        # General security recommendations
        threat_intel = host.get("threat_intelligence", {})
        risk_level = threat_intel.get("risk_level", "unknown")
        
        if risk_level in ["critical", "high"]:
            actions.append("Implement network segmentation and monitoring")
            actions.append("Conduct comprehensive security assessment")
        
        return actions
