# 🔍 Censys Data Summarization Agent

A full-stack Python application that uses AI techniques to analyze and summarize Censys host data for security teams. The agent provides intelligent insights, vulnerability assessments, and actionable remediation recommendations.

## 🚀 Features

- **AI-Powered Analysis**: Uses OpenAI GPT or Google Gemini models for intelligent security analysis
- **Heuristic Fallback**: Deterministic rule-based analysis when AI is unavailable
- **Interactive UI**: Clean Streamlit interface with light/dark mode support
- **Comprehensive Summaries**: Dataset overview, per-host analysis, and risk assessment
- **Actionable Insights**: Concrete remediation recommendations for security teams
- **Flexible Input**: Support for default dataset or custom JSON upload
- **Export Capabilities**: Download analysis results as JSON
- **Theme Support**: Light, dark, and system default modes with automatic detection

## 🏗️ Architecture

The application follows a modular architecture with clear separation of concerns:

```
censys-agent/
├── app.py                 # Streamlit UI and main application
├── agent/
│   ├── summarizer_llm.py  # AI-powered summarization with OpenAI
│   └── summarizer_rules.py # Heuristic fallback summarization
├── data/
│   └── hosts_dataset.json # Sample Censys dataset
├── tests/
│   └── test_summarizer.py # Comprehensive test suite
├── requirements.txt       # Python dependencies
└── README.md             # This file
```

## 🛠️ Setup

### Prerequisites

- Python 3.8 or higher
- pip package manager

### Installation

1. **Clone the repository:**
   ```bash
   git clone <repository-url>
   cd censys-agent
   ```

2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Set up API keys (optional):**
   
   **Option A: Environment Variables (Recommended)**
   ```bash
   # For OpenAI GPT models
   export OPENAI_API_KEY="your-openai-api-key-here"
   
   # For Google Gemini models
   export GOOGLE_API_KEY="your-google-api-key-here"
   ```
   
   **Option B: Config File**
   ```bash
   # Copy the example config
   cp config.json.example config.json
   
   # Edit config.json with your API keys
   # The file is automatically ignored by git for security
   ```
   
   **Option C: Interactive Setup**
   ```bash
   python setup_config.py
   ```
   
   *Note: The application works without API keys using heuristic analysis.*

### Running the Application

```bash
streamlit run app.py
```

The application will be available at `http://localhost:8501`

## 🧪 Testing

Run the comprehensive test suite:

```bash
# Run all tests
pytest -v

# Run with coverage
pytest --cov=agent tests/

# Run specific test file
pytest tests/test_summarizer.py -v
```

## 📊 Usage

### Basic Workflow

1. **Load Data**: Use the default Censys dataset or upload your own JSON
2. **Configure AI**: Select model and temperature settings (if API key available)
3. **Generate Summary**: Click "Generate Summary" to analyze the data
4. **Review Results**: Explore dataset overview, host analysis, and recommendations
5. **Export**: Download the complete analysis as JSON

### Input Data Format

The application expects Censys host data in the following JSON structure:

```json
{
  "metadata": {
    "description": "Censys host data",
    "hosts_count": 3
  },
  "hosts": [
    {
      "ip": "192.168.1.1",
      "location": {
        "city": "New York",
        "country": "United States"
      },
      "autonomous_system": {
        "asn": 12345,
        "name": "Example AS"
      },
      "services": [
        {
          "port": 22,
          "protocol": "SSH",
          "vulnerabilities": [
            {
              "cve_id": "CVE-2023-1234",
              "severity": "critical",
              "cvss_score": 9.8
            }
          ]
        }
      ],
      "threat_intelligence": {
        "risk_level": "high"
      }
    }
  ]
}
```

### Output Schema

The application generates structured JSON summaries following this schema:

```json
{
  "dataset_overview": {
    "host_count": 3,
    "geo_distribution": ["United States (2)", "China (1)"],
    "top_risks": ["Critical vulnerability: CVE-2023-38408"],
    "notable_cves": ["CVE-2023-38408", "CVE-2024-6387"],
    "malware_families": ["Cobalt Strike"],
    "overall_risk": "critical"
  },
  "hosts": [
    {
      "ip": "192.168.1.1",
      "asn": 12345,
      "location": "New York, United States",
      "risk_level": "high",
      "key_findings": ["SSH service detected", "Critical vulnerability present"],
      "cves": ["CVE-2023-38408"],
      "services": ["SSH:22"],
      "recommended_actions": ["Patch OpenSSH to address CVE-2023-38408"]
    }
  ],
  "meta": {
    "generator": "llm",
    "notes": "Generated using AI analysis"
  }
}
```

## 🤖 AI Techniques

### LLM Integration

- **Models**: OpenAI GPT-3.5/4 or Google Gemini Pro
- **Multi-Provider**: Support for both OpenAI and Google AI APIs
- **Prompting**: Structured system prompts for security analysis
- **Schema Validation**: Ensures consistent JSON output format
- **Error Handling**: Graceful fallback to heuristic analysis
- **Secure Configuration**: Protected API key management

### Heuristic Analysis

- **Rule-Based Logic**: Deterministic analysis using security best practices
- **Risk Assessment**: Automated risk level calculation
- **CVE Extraction**: Systematic vulnerability identification
- **Geographic Analysis**: Country and region distribution
- **Threat Intelligence**: Malware family and security label analysis

### Key Features

- **Multi-Provider AI**: OpenAI GPT and Google Gemini support
- **Dual-Mode Operation**: AI-powered with heuristic fallback
- **Schema Compliance**: Strict JSON output validation
- **Security Focus**: Specialized for cybersecurity analysis
- **Actionable Output**: Concrete remediation recommendations
- **Secure Configuration**: Protected API key management

## 🔧 Development Assumptions

- **Data Source**: Censys platform datasets (https://docs.censys.com/docs/platform-datasets)
- **Security Context**: Analysis focused on threat detection and vulnerability assessment
- **Fallback Strategy**: Heuristic analysis when AI services unavailable
- **Schema Compliance**: Strict adherence to defined JSON output format
- **Error Handling**: Graceful degradation with user feedback

## 🚀 Future Enhancements

### Short-term Improvements

- **Enhanced Visualization**: Interactive charts for geographic distribution and risk trends
- **CVE Enrichment**: Integration with NVD database for detailed vulnerability information
- **Confidence Scoring**: AI confidence levels for analysis recommendations
- **Batch Processing**: Support for multiple dataset analysis

### Advanced Features

- **Real-time Monitoring**: Live data feed integration
- **Custom Rules**: User-defined analysis rules and thresholds
- **API Integration**: RESTful API for programmatic access
- **Authentication**: User management and access control
- **Persistence**: Database storage for analysis history

### AI Enhancements

- **Multi-Model Support**: Integration with additional LLM providers
- **Fine-tuned Models**: Custom models trained on security data
- **Streaming Responses**: Real-time analysis updates
- **Context Awareness**: Historical analysis and trend detection

## 📝 License

This project is developed as part of the Censys 2026 Summer Internship Take-Home Exercise.

## 🤝 Contributing

This is a take-home project for internship evaluation. For questions or issues, please refer to the project requirements and evaluation criteria.

## 📞 Support

For technical questions about the Censys platform datasets, refer to:
- [Censys Platform Datasets Documentation](https://docs.censys.com/docs/platform-datasets)
- [Censys API Documentation](https://docs.censys.com/)

---

**Built with ❤️ using Streamlit, OpenAI, and Python**