"""
LLM-based summarizer for Censys host data.
Uses OpenAI API with intelligent prompting and fallback to heuristic rules.
"""

import json
import os
import logging
from typing import Dict, List, Any, Optional
from agent.summarizer_rules import HeuristicSummarizer

try:
    import openai
    OPENAI_AVAILABLE = True
except ImportError:
    OPENAI_AVAILABLE = False
    openai = None

try:
    import google.generativeai as genai
    GEMINI_AVAILABLE = True
except ImportError:
    GEMINI_AVAILABLE = False
    genai = None


class LLMSummarizer:
    """
    AI-powered summarizer using OpenAI GPT models.
    Falls back to heuristic summarizer when API is unavailable.
    """
    
    def __init__(self, api_key: Optional[str] = None, model: str = "gpt-3.5-turbo", temperature: float = 0.3, provider: str = "openai"):
        """
        Initialize LLM summarizer.
        
        Args:
            api_key: API key (if None, will try to read from environment variables)
            model: Model to use (OpenAI or Gemini)
            temperature: Sampling temperature (0.0 to 1.0)
            provider: LLM provider ("openai" or "gemini")
        """
        self.provider = provider.lower()
        self.model = model
        self.temperature = temperature
        self.heuristic_fallback = HeuristicSummarizer()
        
        # Initialize API key and client
        if self.provider == "openai":
            self.api_key = api_key or os.getenv("OPENAI_API_KEY")
            self.llm_available = self._init_openai()
        elif self.provider == "gemini":
            self.api_key = api_key or os.getenv("GOOGLE_API_KEY")
            self.llm_available = self._init_gemini()
        else:
            self.llm_available = False
            logging.warning(f"Unknown provider: {provider}")
    
    def _init_openai(self) -> bool:
        """Initialize OpenAI client."""
        if not OPENAI_AVAILABLE or not self.api_key:
            return False
        
        try:
            openai.api_key = self.api_key
            self.client = openai
            return True
        except Exception as e:
            logging.warning(f"Failed to initialize OpenAI client: {e}")
            return False
    
    def _init_gemini(self) -> bool:
        """Initialize Gemini client."""
        if not GEMINI_AVAILABLE or not self.api_key:
            return False
        
        try:
            genai.configure(api_key=self.api_key)
            self.client = genai
            return True
        except Exception as e:
            logging.warning(f"Failed to initialize Gemini client: {e}")
            return False
    
    def summarize(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate AI-powered summary of Censys host data.
        
        Args:
            data: Censys host dataset with metadata and hosts array
            
        Returns:
            Structured JSON summary following the required schema
        """
        if not self.llm_available:
            logging.info("LLM not available, using heuristic fallback")
            return self._fallback_to_heuristic(data, "No API key or OpenAI unavailable")
        
        try:
            # Prepare trimmed input for LLM
            trimmed_data = self._trim_data_for_llm(data)
            
            # Generate LLM summary based on provider
            if self.provider == "openai":
                llm_response = self._call_openai(trimmed_data)
            elif self.provider == "gemini":
                llm_response = self._call_gemini(trimmed_data)
            else:
                raise Exception(f"Unknown provider: {self.provider}")
            
            # Parse and validate response
            summary = self._parse_llm_response(llm_response)
            
            # Validate against schema
            if self._validate_schema(summary):
                summary["meta"]["generator"] = "llm"
                summary["meta"]["provider"] = self.provider
                return summary
            else:
                logging.warning("LLM response failed schema validation, using heuristic fallback")
                return self._fallback_to_heuristic(data, "LLM response invalid")
                
        except Exception as e:
            logging.error(f"LLM summarization failed: {e}")
            return self._fallback_to_heuristic(data, f"LLM error: {str(e)}")
    
    def _trim_data_for_llm(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Trim host data to essential fields for LLM processing."""
        trimmed_hosts = []
        
        for host in data.get("hosts", []):
            trimmed_host = {
                "ip": host.get("ip"),
                "location": host.get("location", {}),
                "autonomous_system": host.get("autonomous_system", {}),
                "dns": host.get("dns", {}),
                "operating_system": host.get("operating_system", {}),
                "services": [],
                "threat_intelligence": host.get("threat_intelligence", {})
            }
            
            # Trim services to essential fields
            for service in host.get("services", []):
                trimmed_service = {
                    "port": service.get("port"),
                    "protocol": service.get("protocol"),
                    "banner": service.get("banner"),
                    "software": service.get("software", []),
                    "vulnerabilities": service.get("vulnerabilities", []),
                    "malware_detected": service.get("malware_detected"),
                    "authentication_required": service.get("authentication_required"),
                    "access_restricted": service.get("access_restricted"),
                    "tls_enabled": service.get("tls_enabled"),
                    "certificate": service.get("certificate")
                }
                # Remove None values
                trimmed_service = {k: v for k, v in trimmed_service.items() if v is not None}
                trimmed_host["services"].append(trimmed_service)
            
            trimmed_hosts.append(trimmed_host)
        
        return {
            "metadata": data.get("metadata", {}),
            "hosts": trimmed_hosts
        }
    
    def _call_openai(self, data: Dict[str, Any]) -> str:
        """Call OpenAI API with structured prompt."""
        
        system_prompt = """You are a security analyst AI that summarizes Censys host scan data for SecOps teams. 

Your task is to analyze the provided host data and generate a structured JSON summary that follows this exact schema:

{
  "dataset_overview": {
    "host_count": 0,
    "geo_distribution": ["<Country> (<count>)"],
    "top_risks": ["<short bullet>"],
    "notable_cves": ["CVE-..."],
    "malware_families": ["<family>"],
    "overall_risk": "low|medium|high|critical"
  },
  "hosts": [
    {
      "ip": "<string>",
      "asn": 0,
      "location": "<City, Country or Country>",
      "risk_level": "unknown|low|medium|high|critical",
      "key_findings": ["<bullet>", "..."],
      "cves": ["CVE-..."],
      "services": ["<PROTOCOL:PORT>"],
      "recommended_actions": ["<action>", "..."]
    }
  ],
  "meta": {
    "generator": "llm",
    "notes": "<optional message>"
  }
}

Guidelines:
- Write concise, factual, action-oriented summaries in security analyst tone
- Keep bullets concise and actionable
- No speculation beyond the provided data
- Recommended actions should be concrete (e.g., "Patch OpenSSH to address CVE-2023-38408")
- Sort hosts by risk_level (critical→high→medium→low→unknown) then by IP
- Return ONLY valid JSON, no markdown formatting or code fences
- Focus on security implications and remediation steps"""

        user_prompt = f"""Analyze this Censys host data and provide a security summary:

{json.dumps(data, indent=2)}

Generate a JSON summary following the exact schema above. Focus on:
1. Security risks and vulnerabilities
2. Geographic and infrastructure patterns  
3. Concrete remediation recommendations
4. Threat intelligence insights

Return only the JSON object, no additional text."""

        try:
            response = self.client.ChatCompletion.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ],
                temperature=self.temperature,
                max_tokens=4000
            )
            
            return response.choices[0].message.content.strip()
            
        except Exception as e:
            raise Exception(f"OpenAI API call failed: {e}")
    
    def _call_gemini(self, data: Dict[str, Any]) -> str:
        """Call Gemini API with structured prompt."""
        
        system_prompt = """You are a security analyst AI that summarizes Censys host scan data for SecOps teams. 

Your task is to analyze the provided host data and generate a structured JSON summary that follows this exact schema:

{
  "dataset_overview": {
    "host_count": 0,
    "geo_distribution": ["<Country> (<count>)"],
    "top_risks": ["<short bullet>"],
    "notable_cves": ["CVE-..."],
    "malware_families": ["<family>"],
    "overall_risk": "low|medium|high|critical"
  },
  "hosts": [
    {
      "ip": "<string>",
      "asn": 0,
      "location": "<City, Country or Country>",
      "risk_level": "unknown|low|medium|high|critical",
      "key_findings": ["<bullet>", "..."],
      "cves": ["CVE-..."],
      "services": ["<PROTOCOL:PORT>"],
      "recommended_actions": ["<action>", "..."]
    }
  ],
  "meta": {
    "generator": "llm",
    "notes": "<optional message>"
  }
}

Guidelines:
- Write concise, factual, action-oriented summaries in security analyst tone
- Keep bullets concise and actionable
- No speculation beyond the provided data
- Recommended actions should be concrete (e.g., "Patch OpenSSH to address CVE-2023-38408")
- Sort hosts by risk_level (critical→high→medium→low→unknown) then by IP
- Return ONLY valid JSON, no markdown formatting or code fences
- Focus on security implications and remediation steps"""

        user_prompt = f"""Analyze this Censys host data and provide a security summary:

{json.dumps(data, indent=2)}

Generate a JSON summary following the exact schema above. Focus on:
1. Security risks and vulnerabilities
2. Geographic and infrastructure patterns  
3. Concrete remediation recommendations
4. Threat intelligence insights

Return only the JSON object, no additional text."""

        try:
            # Configure Gemini model
            model = self.client.GenerativeModel(self.model)
            
            # Combine system and user prompts for Gemini
            full_prompt = f"{system_prompt}\n\n{user_prompt}"
            
            # Generate content
            response = model.generate_content(
                full_prompt,
                generation_config=self.client.types.GenerationConfig(
                    temperature=self.temperature,
                    max_output_tokens=4000
                )
            )
            
            return response.text.strip()
            
        except Exception as e:
            raise Exception(f"Gemini API call failed: {e}")
    
    def _parse_llm_response(self, response: str) -> Dict[str, Any]:
        """Parse and clean LLM response."""
        # Remove code fences if present
        if response.startswith("```json"):
            response = response[7:]
        if response.startswith("```"):
            response = response[3:]
        if response.endswith("```"):
            response = response[:-3]
        
        response = response.strip()
        
        try:
            return json.loads(response)
        except json.JSONDecodeError as e:
            # Try to fix common JSON issues
            try:
                # Remove any trailing text after the JSON
                json_end = response.rfind("}")
                if json_end > 0:
                    response = response[:json_end + 1]
                return json.loads(response)
            except:
                raise Exception(f"Failed to parse JSON response: {e}")
    
    def _validate_schema(self, summary: Dict[str, Any]) -> bool:
        """Validate that summary follows required schema."""
        try:
            # Check top-level structure
            required_keys = ["dataset_overview", "hosts", "meta"]
            if not all(key in summary for key in required_keys):
                return False
            
            # Check dataset_overview structure
            overview = summary["dataset_overview"]
            overview_keys = ["host_count", "geo_distribution", "top_risks", "notable_cves", "malware_families", "overall_risk"]
            if not all(key in overview for key in overview_keys):
                return False
            
            # Check hosts structure
            for host in summary["hosts"]:
                host_keys = ["ip", "asn", "location", "risk_level", "key_findings", "cves", "services", "recommended_actions"]
                if not all(key in host for key in host_keys):
                    return False
                
                # Validate risk_level values
                if host["risk_level"] not in ["unknown", "low", "medium", "high", "critical"]:
                    return False
            
            # Validate overall_risk
            if overview["overall_risk"] not in ["low", "medium", "high", "critical"]:
                return False
            
            return True
            
        except Exception:
            return False
    
    def _fallback_to_heuristic(self, data: Dict[str, Any], reason: str) -> Dict[str, Any]:
        """Fall back to heuristic summarizer with reason note."""
        summary = self.heuristic_fallback.summarize(data)
        summary["meta"]["notes"] = f"LLM unavailable: {reason}"
        return summary
