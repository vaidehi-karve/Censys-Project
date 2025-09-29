"""
Test suite for Censys Data Summarization Agent.
Tests both heuristic and LLM summarizers.
"""

import json
import pytest
import os
from pathlib import Path
from typing import Dict, Any

# Import our modules
from agent.summarizer_rules import HeuristicSummarizer
from agent.summarizer_llm import LLMSummarizer


class TestHeuristicSummarizer:
    """Test heuristic summarizer functionality."""
    
    @pytest.fixture
    def sample_data(self):
        """Load sample Censys dataset for testing."""
        data_path = Path("data/hosts_dataset.json")
        if data_path.exists():
            with open(data_path, 'r') as f:
                return json.load(f)
        else:
            # Fallback test data
            return {
                "metadata": {"hosts_count": 2},
                "hosts": [
                    {
                        "ip": "192.168.1.1",
                        "location": {"city": "Test City", "country": "Test Country"},
                        "autonomous_system": {"asn": 12345, "name": "Test AS"},
                        "services": [
                            {
                                "port": 22,
                                "protocol": "SSH",
                                "vulnerabilities": [
                                    {"cve_id": "CVE-2023-1234", "severity": "critical", "cvss_score": 9.8}
                                ]
                            }
                        ],
                        "threat_intelligence": {"risk_level": "high"}
                    },
                    {
                        "ip": "192.168.1.2", 
                        "location": {"city": "Test City 2", "country": "Test Country 2"},
                        "autonomous_system": {"asn": 67890, "name": "Test AS 2"},
                        "services": [
                            {
                                "port": 80,
                                "protocol": "HTTP"
                            }
                        ],
                        "threat_intelligence": {"risk_level": "low"}
                    }
                ]
            }
    
    @pytest.fixture
    def summarizer(self):
        """Create heuristic summarizer instance."""
        return HeuristicSummarizer()
    
    def test_summarize_basic_structure(self, summarizer, sample_data):
        """Test that summary has required top-level structure."""
        summary = summarizer.summarize(sample_data)
        
        # Check required top-level keys
        assert "dataset_overview" in summary
        assert "hosts" in summary
        assert "meta" in summary
        
        # Check meta structure
        assert "generator" in summary["meta"]
        assert summary["meta"]["generator"] == "heuristic"
    
    def test_dataset_overview_structure(self, summarizer, sample_data):
        """Test dataset overview has required fields."""
        summary = summarizer.summarize(sample_data)
        overview = summary["dataset_overview"]
        
        required_keys = ["host_count", "geo_distribution", "top_risks", 
                         "notable_cves", "malware_families", "overall_risk"]
        
        for key in required_keys:
            assert key in overview, f"Missing key: {key}"
        
        # Check data types
        assert isinstance(overview["host_count"], int)
        assert isinstance(overview["geo_distribution"], list)
        assert isinstance(overview["top_risks"], list)
        assert isinstance(overview["notable_cves"], list)
        assert isinstance(overview["malware_families"], list)
        assert isinstance(overview["overall_risk"], str)
    
    def test_host_count_matches(self, summarizer, sample_data):
        """Test that host count matches input data."""
        summary = summarizer.summarize(sample_data)
        expected_count = len(sample_data.get("hosts", []))
        assert summary["dataset_overview"]["host_count"] == expected_count
    
    def test_host_summary_structure(self, summarizer, sample_data):
        """Test individual host summaries have required fields."""
        summary = summarizer.summarize(sample_data)
        
        for host in summary["hosts"]:
            required_keys = ["ip", "asn", "location", "risk_level", 
                           "key_findings", "cves", "services", "recommended_actions"]
            
            for key in required_keys:
                assert key in host, f"Missing host key: {key}"
            
            # Check data types
            assert isinstance(host["ip"], str)
            assert isinstance(host["asn"], int)
            assert isinstance(host["location"], str)
            assert isinstance(host["risk_level"], str)
            assert isinstance(host["key_findings"], list)
            assert isinstance(host["cves"], list)
            assert isinstance(host["services"], list)
            assert isinstance(host["recommended_actions"], list)
    
    def test_risk_levels_valid(self, summarizer, sample_data):
        """Test that risk levels are valid values."""
        summary = summarizer.summarize(sample_data)
        
        valid_risk_levels = ["unknown", "low", "medium", "high", "critical"]
        
        # Check overall risk
        assert summary["dataset_overview"]["overall_risk"] in valid_risk_levels
        
        # Check host risk levels
        for host in summary["hosts"]:
            assert host["risk_level"] in valid_risk_levels
    
    def test_empty_data(self, summarizer):
        """Test handling of empty dataset."""
        empty_data = {"hosts": []}
        summary = summarizer.summarize(empty_data)
        
        assert summary["dataset_overview"]["host_count"] == 0
        assert summary["dataset_overview"]["overall_risk"] == "unknown"
        assert len(summary["hosts"]) == 0
    
    def test_cve_extraction(self, summarizer, sample_data):
        """Test that CVEs are properly extracted."""
        summary = summarizer.summarize(sample_data)
        
        # Check that CVEs from input appear in summary
        all_cves = []
        for host in sample_data.get("hosts", []):
            for service in host.get("services", []):
                for vuln in service.get("vulnerabilities", []):
                    cve_id = vuln.get("cve_id")
                    if cve_id:
                        all_cves.append(cve_id)
        
        summary_cves = summary["dataset_overview"]["notable_cves"]
        for cve in all_cves:
            assert cve in summary_cves, f"CVE {cve} not found in summary"
    
    def test_geographic_distribution(self, summarizer, sample_data):
        """Test geographic distribution calculation."""
        summary = summarizer.summarize(sample_data)
        geo_dist = summary["dataset_overview"]["geo_distribution"]
        
        # Should have entries for each unique country
        countries = []
        for host in sample_data.get("hosts", []):
            country = host.get("location", {}).get("country", "Unknown")
            countries.append(country)
        
        unique_countries = set(countries)
        assert len(geo_dist) == len(unique_countries)
        
        # Each entry should be in format "Country (count)"
        for entry in geo_dist:
            assert "(" in entry and ")" in entry


class TestLLMSummarizer:
    """Test LLM summarizer functionality."""
    
    @pytest.fixture
    def sample_data(self):
        """Load sample Censys dataset for testing."""
        data_path = Path("data/hosts_dataset.json")
        if data_path.exists():
            with open(data_path, 'r') as f:
                return json.load(f)
        else:
            return {"hosts": []}
    
    def test_llm_initialization_no_key(self):
        """Test LLM summarizer initialization without API key."""
        summarizer = LLMSummarizer(api_key=None)
        assert not summarizer.llm_available
    
    def test_llm_initialization_with_key(self):
        """Test LLM summarizer initialization with API key."""
        # Mock API key for testing
        summarizer = LLMSummarizer(api_key="test-key")
        # Should still not be available without actual OpenAI client
        assert not summarizer.llm_available
    
    def test_fallback_to_heuristic(self, sample_data):
        """Test that LLM summarizer falls back to heuristic when LLM unavailable."""
        summarizer = LLMSummarizer(api_key=None)  # No API key
        summary = summarizer.summarize(sample_data)
        
        # Should use heuristic fallback
        assert summary["meta"]["generator"] == "heuristic"
        assert "LLM unavailable" in summary["meta"]["notes"]
    
    def test_data_trimming(self, sample_data):
        """Test that data is properly trimmed for LLM."""
        summarizer = LLMSummarizer(api_key=None)
        trimmed = summarizer._trim_data_for_llm(sample_data)
        
        # Should have same structure but trimmed content
        assert "hosts" in trimmed
        assert "metadata" in trimmed
        
        for host in trimmed["hosts"]:
            # Should have essential fields
            assert "ip" in host
            assert "location" in host
            assert "services" in host
            assert "threat_intelligence" in host
    
    def test_schema_validation(self):
        """Test schema validation function."""
        summarizer = LLMSummarizer(api_key=None)
        
        # Valid schema
        valid_summary = {
            "dataset_overview": {
                "host_count": 1,
                "geo_distribution": ["US (1)"],
                "top_risks": ["Test risk"],
                "notable_cves": ["CVE-2023-1234"],
                "malware_families": [],
                "overall_risk": "high"
            },
            "hosts": [{
                "ip": "192.168.1.1",
                "asn": 12345,
                "location": "Test City, US",
                "risk_level": "high",
                "key_findings": ["Test finding"],
                "cves": ["CVE-2023-1234"],
                "services": ["SSH:22"],
                "recommended_actions": ["Test action"]
            }],
            "meta": {
                "generator": "heuristic",
                "notes": "Test"
            }
        }
        
        assert summarizer._validate_schema(valid_summary)
        
        # Invalid schema - missing required field
        invalid_summary = {
            "dataset_overview": {"host_count": 1},
            "hosts": [],
            "meta": {"generator": "heuristic"}
        }
        
        assert not summarizer._validate_schema(invalid_summary)


def test_integration():
    """Integration test with real dataset."""
    data_path = Path("data/hosts_dataset.json")
    if not data_path.exists():
        pytest.skip("Sample dataset not found")
    
    with open(data_path, 'r') as f:
        data = json.load(f)
    
    # Test heuristic summarizer
    heuristic_summarizer = HeuristicSummarizer()
    summary = heuristic_summarizer.summarize(data)
    
    # Basic validation
    assert "dataset_overview" in summary
    assert "hosts" in summary
    assert "meta" in summary
    
    # Should have 3 hosts
    assert summary["dataset_overview"]["host_count"] == 3
    assert len(summary["hosts"]) == 3
    
    # Test LLM summarizer fallback
    llm_summarizer = LLMSummarizer(api_key=None)
    llm_summary = llm_summarizer.summarize(data)
    
    # Should fallback to heuristic
    assert llm_summary["meta"]["generator"] == "heuristic"


if __name__ == "__main__":
    # Run tests
    pytest.main([__file__, "-v"])
