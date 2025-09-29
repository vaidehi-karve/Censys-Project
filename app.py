"""
Censys Data Summarization Agent - Streamlit UI

A full-stack Python application for summarizing Censys host data using AI techniques.
Supports both LLM-based and heuristic summarization with automatic fallback.
"""

import streamlit as st
import json
import os
import logging
import platform
from typing import Dict, Any, Optional
from pathlib import Path

# Import our agent modules
from agent.summarizer_llm import LLMSummarizer
from agent.summarizer_rules import HeuristicSummarizer
from config import get_global_config, validate_api_keys, setup_secure_config

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Suppress Google AI library warnings
import warnings
warnings.filterwarnings("ignore", category=UserWarning, module="google")
warnings.filterwarnings("ignore", message=".*ALTS creds ignored.*")

# Page configuration
st.set_page_config(
    page_title="Censys Data Summarization Agent",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Initialize session state for theme
if 'theme' not in st.session_state:
    st.session_state.theme = 'system'  # Default to system preference

def get_effective_theme(theme):
    """Get the effective theme based on system preference."""
    if theme == 'system':
        # Try to detect system preference
        import os
        
        # Check environment variables first (simplest approach)
        if os.getenv('STREAMLIT_THEME') == 'dark':
            return 'dark'
        elif os.getenv('STREAMLIT_THEME') == 'light':
            return 'light'
        
        # Try to detect system preference
        try:
            import platform
            
            if platform.system() == "Darwin":  # macOS
                try:
                    import subprocess
                    result = subprocess.run(['defaults', 'read', '-g', 'AppleInterfaceStyle'], 
                                          capture_output=True, text=True, timeout=2)
                    return 'dark' if 'Dark' in result.stdout else 'light'
                except:
                    return 'light'
            elif platform.system() == "Windows":
                try:
                    import subprocess
                    result = subprocess.run(['reg', 'query', 'HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize', 
                                           '/v', 'AppsUseLightTheme'], capture_output=True, text=True, timeout=2)
                    return 'dark' if '0x0' in result.stdout else 'light'
                except:
                    return 'light'
            else:
                # Linux or other systems - default to light
                return 'light'
        except:
            # Fallback to light mode if detection fails
            return 'light'
    
    return theme

def get_theme_css(theme):
    """Generate CSS based on selected theme."""
    effective_theme = get_effective_theme(theme)
    
    if effective_theme == 'dark':
        return """
        <style>
            /* Dark theme styles */
            .main-header {
                font-size: 2.5rem;
                font-weight: bold;
                color: #4fc3f7;
                text-align: center;
                margin-bottom: 2rem;
            }
            
            /* Dark theme overrides */
            .stApp {
                background-color: #0e1117 !important;
                color: #fafafa !important;
            }
            
            .stSidebar {
                background-color: #262730 !important;
            }
            
            /* Force dark theme on all elements */
            div[data-testid="stApp"] {
                background-color: #0e1117 !important;
                color: #fafafa !important;
            }
            
            /* Fix dropdown visibility in dark mode - comprehensive approach */
            .stSelectbox > div > div {
                background-color: #262730 !important;
                color: #fafafa !important;
                border: 1px solid #616161 !important;
            }
            
            /* Fix sidebar dropdowns specifically */
            .stSidebar .stSelectbox > div > div {
                background-color: #262730 !important;
                color: #fafafa !important;
                border: 1px solid #616161 !important;
            }
            
            /* Fix dropdown options visibility - more specific selectors */
            .stSelectbox > div > div > div {
                background-color: #262730 !important;
                color: #fafafa !important;
            }
            
            /* Fix sidebar dropdown options */
            .stSidebar .stSelectbox > div > div > div {
                background-color: #262730 !important;
                color: #fafafa !important;
            }
            
            /* Fix dropdown menu items with higher specificity */
            .stSelectbox [role="listbox"] {
                background-color: #262730 !important;
                color: #fafafa !important;
                border: 1px solid #616161 !important;
            }
            
            .stSelectbox [role="option"] {
                background-color: #262730 !important;
                color: #fafafa !important;
            }
            
            .stSelectbox [role="option"]:hover {
                background-color: #424242 !important;
                color: #fafafa !important;
            }
            
            /* Force dropdown options to be visible */
            .stSelectbox div[data-baseweb="select"] {
                background-color: #262730 !important;
                color: #fafafa !important;
            }
            
            .stSelectbox div[data-baseweb="select"] > div {
                background-color: #262730 !important;
                color: #fafafa !important;
            }
            
            /* Fix sidebar dropdown baseweb */
            .stSidebar .stSelectbox div[data-baseweb="select"] {
                background-color: #262730 !important;
                color: #fafafa !important;
            }
            
            .stSidebar .stSelectbox div[data-baseweb="select"] > div {
                background-color: #262730 !important;
                color: #fafafa !important;
            }
            
            /* Fix dropdown popup */
            .stSelectbox div[role="listbox"] {
                background-color: #262730 !important;
                color: #fafafa !important;
                border: 1px solid #616161 !important;
            }
            
            .stSelectbox div[role="listbox"] > div {
                background-color: #262730 !important;
                color: #fafafa !important;
            }
            
            .stSelectbox div[role="listbox"] > div:hover {
                background-color: #424242 !important;
                color: #fafafa !important;
            }
            
            /* Fix sidebar dropdown popup */
            .stSidebar .stSelectbox div[role="listbox"] {
                background-color: #262730 !important;
                color: #fafafa !important;
                border: 1px solid #616161 !important;
            }
            
            .stSidebar .stSelectbox div[role="listbox"] > div {
                background-color: #262730 !important;
                color: #fafafa !important;
            }
            
            .stSidebar .stSelectbox div[role="listbox"] > div:hover {
                background-color: #424242 !important;
                color: #fafafa !important;
            }
            
            /* Fix top bar background and elements */
            .stToolbar {
                background-color: #262730 !important;
                color: #fafafa !important;
            }
            
            /* Fix entire top bar background */
            div[data-testid="stHeader"] {
                background-color: #262730 !important;
                color: #fafafa !important;
            }
            
            /* Fix top bar container */
            div[data-testid="stHeader"] > div {
                background-color: #262730 !important;
                color: #fafafa !important;
            }
            
            /* Fix the main top bar area */
            header[data-testid="stHeader"] {
                background-color: #262730 !important;
                color: #fafafa !important;
            }
            
            /* Fix any remaining top bar elements */
            .stApp > header {
                background-color: #262730 !important;
                color: #fafafa !important;
            }
            
            /* Fix the top bar navigation */
            .stApp > div:first-child {
                background-color: #262730 !important;
                color: #fafafa !important;
            }
            
            /* Fix any white backgrounds in the top area */
            div[data-testid="stHeader"] * {
                background-color: #262730 !important;
                color: #fafafa !important;
            }
            
            /* Force the entire top bar to be dark */
            .stApp > div:first-child,
            .stApp > header,
            .stApp > div[data-testid="stHeader"],
            .stApp > div[data-testid="stHeader"] > div,
            .stApp > div[data-testid="stHeader"] > div > div {
                background-color: #262730 !important;
                color: #fafafa !important;
            }
            
            /* Fix the main navigation bar */
            nav[data-testid="stHeader"] {
                background-color: #262730 !important;
                color: #fafafa !important;
            }
            
            /* Fix any remaining top bar elements */
            .stApp > div:first-child * {
                background-color: #262730 !important;
                color: #fafafa !important;
            }
            
            /* Force all top-level containers to be dark */
            .stApp > div:first-child,
            .stApp > div:first-child > div,
            .stApp > div:first-child > div > div {
                background-color: #262730 !important;
                color: #fafafa !important;
            }
            
            /* Fix deploy button and menu */
            .stDeployButton {
                background-color: #262730 !important;
                color: #fafafa !important;
                border: 1px solid #616161 !important;
            }
            
            .stDeployButton:hover {
                background-color: #424242 !important;
            }
            
            /* Fix three dots menu */
            .stToolbar button {
                background-color: #262730 !important;
                color: #fafafa !important;
                border: 1px solid #616161 !important;
            }
            
            .stToolbar button:hover {
                background-color: #424242 !important;
            }
            
            /* Fix top bar text and buttons with higher specificity */
            div[data-testid="stToolbar"] {
                background-color: #262730 !important;
                color: #fafafa !important;
            }
            
            div[data-testid="stToolbar"] button {
                background-color: #262730 !important;
                color: #fafafa !important;
                border: 1px solid #616161 !important;
            }
            
            div[data-testid="stToolbar"] button:hover {
                background-color: #424242 !important;
                color: #fafafa !important;
            }
            
            /* Fix deploy button specifically */
            div[data-testid="stDeployButton"] {
                background-color: #262730 !important;
                color: #fafafa !important;
            }
            
            div[data-testid="stDeployButton"] button {
                background-color: #262730 !important;
                color: #fafafa !important;
                border: 1px solid #616161 !important;
            }
            
            div[data-testid="stDeployButton"] button:hover {
                background-color: #424242 !important;
                color: #fafafa !important;
            }
            
            /* Fix deploy button dropdown */
            div[data-testid="stDeployButton"] [role="menu"] {
                background-color: #262730 !important;
                color: #fafafa !important;
                border: 1px solid #616161 !important;
            }
            
            div[data-testid="stDeployButton"] [role="menuitem"] {
                background-color: #262730 !important;
                color: #fafafa !important;
            }
            
            div[data-testid="stDeployButton"] [role="menuitem"]:hover {
                background-color: #424242 !important;
                color: #fafafa !important;
            }
            
            /* Fix menu button (three dots) */
            div[data-testid="stMenuButton"] {
                background-color: #262730 !important;
                color: #fafafa !important;
            }
            
            div[data-testid="stMenuButton"] button {
                background-color: #262730 !important;
                color: #fafafa !important;
                border: 1px solid #616161 !important;
            }
            
            div[data-testid="stMenuButton"] button:hover {
                background-color: #424242 !important;
                color: #fafafa !important;
            }
            
            /* Fix menu button dropdown */
            div[data-testid="stMenuButton"] [role="menu"] {
                background-color: #262730 !important;
                color: #fafafa !important;
                border: 1px solid #616161 !important;
            }
            
            div[data-testid="stMenuButton"] [role="menuitem"] {
                background-color: #262730 !important;
                color: #fafafa !important;
            }
            
            div[data-testid="stMenuButton"] [role="menuitem"]:hover {
                background-color: #424242 !important;
                color: #fafafa !important;
            }
            
            /* Fix all buttons */
            .stButton > button {
                background-color: #262730 !important;
                color: #fafafa !important;
                border: 1px solid #616161 !important;
            }
            
            .stButton > button:hover {
                background-color: #424242 !important;
            }
            
            /* Fix text inputs */
            .stTextInput > div > div > input {
                background-color: #262730 !important;
                color: #fafafa !important;
                border: 1px solid #616161 !important;
            }
            
            .stTextArea > div > div > textarea {
                background-color: #262730 !important;
                color: #fafafa !important;
                border: 1px solid #616161 !important;
            }
            
            /* Fix expanders */
            .stExpander > div {
                background-color: #262730 !important;
                color: #fafafa !important;
                border: 1px solid #616161 !important;
            }
            
            /* Fix metrics */
            .stMetric > div {
                background-color: #262730 !important;
                color: #fafafa !important;
            }
            
            /* Override Streamlit's default text colors */
            .stMarkdown {
                color: #fafafa !important;
            }
            
            .stText {
                color: #fafafa !important;
            }
            
            /* Force dark theme on all text elements - more selective */
            .stMarkdown p, .stMarkdown div, .stMarkdown span, 
            .stMarkdown h1, .stMarkdown h2, .stMarkdown h3, 
            .stMarkdown h4, .stMarkdown h5, .stMarkdown h6 {
                color: #fafafa !important;
            }
            
            /* Override any remaining light elements */
            .element-container {
                background-color: #0e1117 !important;
                color: #fafafa !important;
            }
            
            /* Fix slider components */
            .stSlider > div > div > div {
                background-color: #262730 !important;
            }
            
            /* Fix checkbox components */
            .stCheckbox > div > div {
                background-color: #262730 !important;
                color: #fafafa !important;
            }
            
            /* Fix file uploader */
            .stFileUploader > div {
                background-color: #262730 !important;
                color: #fafafa !important;
                border: 1px solid #616161 !important;
            }
            
            .status-success {
                background-color: #1b5e20;
                color: #a5d6a7;
                padding: 0.75rem;
                border-radius: 0.375rem;
                border: 1px solid #2e7d32;
            }
            .status-warning {
                background-color: #e65100;
                color: #ffcc02;
                padding: 0.75rem;
                border-radius: 0.375rem;
                border: 1px solid #ff9800;
            }
            .status-error {
                background-color: #b71c1c;
                color: #ffcdd2;
                padding: 0.75rem;
                border-radius: 0.375rem;
                border: 1px solid #d32f2f;
            }
            .risk-critical {
                background-color: #d32f2f;
                color: white;
                padding: 0.25rem 0.5rem;
                border-radius: 0.25rem;
                font-weight: bold;
            }
            .risk-high {
                background-color: #f57c00;
                color: white;
                padding: 0.25rem 0.5rem;
                border-radius: 0.25rem;
                font-weight: bold;
            }
            .risk-medium {
                background-color: #fbc02d;
                color: black;
                padding: 0.25rem 0.5rem;
                border-radius: 0.25rem;
                font-weight: bold;
            }
            .risk-low {
                background-color: #388e3c;
                color: white;
                padding: 0.25rem 0.5rem;
                border-radius: 0.25rem;
                font-weight: bold;
            }
            .risk-unknown {
                background-color: #616161;
                color: white;
                padding: 0.25rem 0.5rem;
                border-radius: 0.25rem;
                font-weight: bold;
            }
            .theme-toggle {
                background-color: #424242;
                color: #ffffff;
                border: 1px solid #616161;
                border-radius: 0.25rem;
                padding: 0.5rem 1rem;
                cursor: pointer;
                transition: all 0.3s ease;
            }
            .theme-toggle:hover {
                background-color: #616161;
            }
        </style>
        """
    else:  # Light theme
        return """
        <style>
            /* Light theme styles - override Streamlit defaults */
            .main-header {
                font-size: 2.5rem !important;
                font-weight: bold !important;
                color: #1f77b4 !important;
                text-align: center !important;
                margin-bottom: 2rem !important;
            }
            
            /* Light theme overrides - more subtle approach */
            .stApp {
                background-color: #ffffff;
            }
            
            .stSidebar {
                background-color: #f8f9fa;
            }
            
            .status-success {
                background-color: #d4edda;
                color: #155724;
                padding: 0.75rem;
                border-radius: 0.375rem;
                border: 1px solid #c3e6cb;
            }
            .status-warning {
                background-color: #fff3cd;
                color: #856404;
                padding: 0.75rem;
                border-radius: 0.375rem;
                border: 1px solid #ffeaa7;
            }
            .status-error {
                background-color: #f8d7da;
                color: #721c24;
                padding: 0.75rem;
                border-radius: 0.375rem;
                border: 1px solid #f5c6cb;
            }
            .risk-critical {
                background-color: #dc3545;
                color: white;
                padding: 0.25rem 0.5rem;
                border-radius: 0.25rem;
                font-weight: bold;
            }
            .risk-high {
                background-color: #fd7e14;
                color: white;
                padding: 0.25rem 0.5rem;
                border-radius: 0.25rem;
                font-weight: bold;
            }
            .risk-medium {
                background-color: #ffc107;
                color: black;
                padding: 0.25rem 0.5rem;
                border-radius: 0.25rem;
                font-weight: bold;
            }
            .risk-low {
                background-color: #28a745;
                color: white;
                padding: 0.25rem 0.5rem;
                border-radius: 0.25rem;
                font-weight: bold;
            }
            .risk-unknown {
                background-color: #6c757d;
                color: white;
                padding: 0.25rem 0.5rem;
                border-radius: 0.25rem;
                font-weight: bold;
            }
            .theme-toggle {
                background-color: #ffffff;
                color: #333333;
                border: 1px solid #cccccc;
                border-radius: 0.25rem;
                padding: 0.5rem 1rem;
                cursor: pointer;
                transition: all 0.3s ease;
            }
            .theme-toggle:hover {
                background-color: #f5f5f5;
            }
        </style>
        """

# Apply theme CSS - this needs to be called after session state is set
# We'll move this to the main function


def load_default_dataset() -> Dict[str, Any]:
    """Load the default Censys dataset."""
    try:
        dataset_path = Path("data/hosts_dataset.json")
        if dataset_path.exists():
            with open(dataset_path, 'r') as f:
                return json.load(f)
        else:
            st.error("Default dataset not found. Please upload a JSON file.")
            return {}
    except Exception as e:
        st.error(f"Error loading default dataset: {e}")
        return {}


def validate_json_schema(data: Dict[str, Any]) -> bool:
    """Validate that the JSON follows Censys host data schema."""
    try:
        # Check for required top-level keys
        if "hosts" not in data:
            return False
        
        # Check that hosts is a list
        if not isinstance(data["hosts"], list):
            return False
        
        # Check each host has required fields
        for host in data["hosts"]:
            if not isinstance(host, dict):
                return False
            if "ip" not in host:
                return False
        
        return True
    except Exception:
        return False


def get_risk_badge_class(risk_level: str) -> str:
    """Get CSS class for risk level badge."""
    risk_classes = {
        "critical": "risk-critical",
        "high": "risk-high", 
        "medium": "risk-medium",
        "low": "risk-low",
        "unknown": "risk-unknown"
    }
    return risk_classes.get(risk_level, "risk-unknown")


def display_dataset_overview(overview: Dict[str, Any]):
    """Display dataset overview in a card format."""
    st.subheader("📊 Dataset Overview")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.metric("Host Count", overview.get("host_count", 0))
    
    with col2:
        risk_level = overview.get("overall_risk", "unknown")
        risk_class = get_risk_badge_class(risk_level)
        st.markdown(f"**Overall Risk:** <span class='{risk_class}'>{risk_level.upper()}</span>", 
                   unsafe_allow_html=True)
    
    with col3:
        cve_count = len(overview.get("notable_cves", []))
        st.metric("Notable CVEs", cve_count)
    
    # Geographic distribution
    if overview.get("geo_distribution"):
        st.write("**Geographic Distribution:**")
        for geo in overview["geo_distribution"]:
            st.write(f"• {geo}")
    
    # Top risks
    if overview.get("top_risks"):
        st.write("**Top Security Risks:**")
        for risk in overview["top_risks"][:5]:  # Show top 5
            st.write(f"• {risk}")
    
    # Notable CVEs
    if overview.get("notable_cves"):
        st.write("**Notable CVEs:**")
        for cve in overview["notable_cves"][:5]:  # Show top 5
            st.write(f"• {cve}")
    
    # Malware families
    if overview.get("malware_families"):
        st.write("**Malware Families Detected:**")
        for family in overview["malware_families"]:
            st.write(f"• {family}")


def display_host_summary(host: Dict[str, Any]):
    """Display individual host summary."""
    with st.expander(f"🖥️ {host['ip']} - {host['location']}", expanded=False):
        col1, col2, col3 = st.columns(3)
        
        with col1:
            risk_level = host.get("risk_level", "unknown")
            risk_class = get_risk_badge_class(risk_level)
            st.markdown(f"**Risk Level:** <span class='{risk_class}'>{risk_level.upper()}</span>", 
                       unsafe_allow_html=True)
        
        with col2:
            st.write(f"**ASN:** {host.get('asn', 'N/A')}")
        
        with col3:
            st.write(f"**Services:** {len(host.get('services', []))}")
        
        # Key findings
        if host.get("key_findings"):
            st.write("**Key Findings:**")
            for finding in host["key_findings"]:
                st.write(f"• {finding}")
        
        # CVEs
        if host.get("cves"):
            st.write("**Vulnerabilities:**")
            for cve in host["cves"]:
                st.write(f"• {cve}")
        
        # Services
        if host.get("services"):
            st.write("**Services:**")
            for service in host["services"]:
                st.write(f"• {service}")
        
        # Recommended actions
        if host.get("recommended_actions"):
            st.write("**Recommended Actions:**")
            for action in host["recommended_actions"]:
                st.write(f"• {action}")


def main():
    """Main Streamlit application."""
    
    # Apply theme CSS
    st.markdown(get_theme_css(st.session_state.theme), unsafe_allow_html=True)
    
    # Theme selector will be added to top bar later
    current_theme = st.session_state.theme
    effective_theme = get_effective_theme(current_theme)
    
    
    # Clean header
    st.markdown('<h1 class="main-header">🔍 Censys Data Summarization Agent</h1>', 
                unsafe_allow_html=True)
    
    st.markdown("AI-powered security analysis of Censys host data with intelligent summarization and actionable insights.")
    
    # Clean sidebar
    with st.sidebar:
        st.header("⚙️ Settings")
        
        # Theme selector
        st.subheader("🎨 Theme")
        theme_options = {
            "🖥️ System": "system",
            "🌞 Light": "light", 
            "🌙 Dark": "dark"
        }
        
        # Get current selection index
        theme_keys = list(theme_options.keys())
        current_index = 0
        for i, (key, value) in enumerate(theme_options.items()):
            if value == current_theme:
                current_index = i
                break
        
        # Theme selector
        selected_theme = st.selectbox(
            "",
            options=theme_keys,
            index=current_index,
            key="theme_selector_sidebar"
        )
        
        # Update theme if changed
        new_theme = theme_options[selected_theme]
        if new_theme != current_theme:
            st.session_state.theme = new_theme
            st.rerun()
        
        # Dataset selection
        st.subheader("📁 Data")
        use_default = st.checkbox("Use default dataset", value=True)
        
        if not use_default:
            uploaded_file = st.file_uploader("Upload JSON file", type=['json'])
            custom_json = st.text_area("Or paste JSON data:", height=200)
        else:
            uploaded_file = None
            custom_json = None
        
        # AI Settings
        st.subheader("🤖 AI")
        
        # Initialize configuration
        config = get_global_config()
        setup_secure_config()
        
        # Provider selection
        available_providers = config.get_available_providers()
        if not available_providers:
            st.caption("⚠️ No API keys - using heuristic")
            provider = "heuristic"
        else:
            provider = st.selectbox(
                "Provider",
                available_providers + ["heuristic"],
                index=0
            )
        
        # Model selection
        if provider != "heuristic":
            available_models = config.get_models(provider)
            model_name = st.selectbox("Model", available_models, index=0)
        else:
            model_name = "heuristic"
        
        temperature = st.slider("Temperature", 0.0, 1.0, config.get_default_temperature(), 0.1)
        
        # API status
        api_status = validate_api_keys()
        if any(api_status.values()):
            st.success("✅ API configured")
        else:
            st.warning("⚠️ No API keys")
    
    # Main content area
    col1, col2 = st.columns([1, 2])
    
    with col1:
        st.header("📊 Data Input")
        
        # Load dataset
        data = {}
        if use_default:
            data = load_default_dataset()
        elif uploaded_file:
            try:
                data = json.load(uploaded_file)
                if not validate_json_schema(data):
                    st.error("Invalid JSON schema. Please upload a valid Censys host dataset.")
                    data = {}
            except Exception as e:
                st.error(f"Error parsing JSON: {e}")
                data = {}
        elif custom_json:
            try:
                data = json.loads(custom_json)
                if not validate_json_schema(data):
                    st.error("Invalid JSON schema. Please provide valid Censys host data.")
                    data = {}
            except Exception as e:
                st.error(f"Error parsing JSON: {e}")
                data = {}
        
        if data:
            st.success(f"✅ Loaded dataset with {len(data.get('hosts', []))} hosts")
            
            # Show dataset preview
            with st.expander("📋 Dataset Preview", expanded=False):
                st.json(data)
        
        # Summarize button
        if st.button("🔍 Generate Summary", type="primary", disabled=not data):
            with st.spinner("Analyzing data..."):
                try:
                    # Initialize summarizer based on provider
                    if provider == "heuristic":
                        summarizer = HeuristicSummarizer()
                        summary = summarizer.summarize(data)
                    else:
                        # Get API key for selected provider
                        api_key = config.get_api_key(provider)
                        summarizer = LLMSummarizer(
                            api_key=api_key,
                            model=model_name,
                            temperature=temperature,
                            provider=provider
                        )
                        summary = summarizer.summarize(data)
                    
                    # Store in session state
                    st.session_state['summary'] = summary
                    st.session_state['raw_data'] = data
                    
                    st.success("✅ Summary generated successfully!")
                    
                except Exception as e:
                    st.error(f"Error generating summary: {e}")
                    logger.error(f"Summarization error: {e}")
    
    with col2:
        st.header("📈 Analysis Results")
        
        if 'summary' in st.session_state:
            summary = st.session_state['summary']
            
            # Status indicator
            generator = summary.get("meta", {}).get("generator", "unknown")
            if generator == "llm":
                st.markdown('<div class="status-success">✅ Using AI-powered analysis</div>', 
                           unsafe_allow_html=True)
            else:
                st.markdown('<div class="status-warning">⚠️ Using heuristic analysis (LLM unavailable)</div>', 
                           unsafe_allow_html=True)
            
            # Dataset overview
            if "dataset_overview" in summary:
                display_dataset_overview(summary["dataset_overview"])
            
            # Host summaries
            if "hosts" in summary:
                st.subheader("🖥️ Host Analysis")
                for host in summary["hosts"]:
                    display_host_summary(host)
            
            # Raw JSON output
            with st.expander("📄 Raw JSON Output", expanded=False):
                st.json(summary)
                
                # Download button
                json_str = json.dumps(summary, indent=2)
                st.download_button(
                    label="💾 Download JSON",
                    data=json_str,
                    file_name="censys_summary.json",
                    mime="application/json"
                )
        
        else:
            st.info("👆 Load a dataset and click 'Generate Summary' to see results")
    
    # Footer
    st.markdown("---")
    st.markdown(
        "**Censys Data Summarization Agent** | "
        "Built with Streamlit & OpenAI | "
        "Supports both AI and heuristic analysis"
    )


if __name__ == "__main__":
    main()
