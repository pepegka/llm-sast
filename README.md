# LLM-Powered SAST Scanner

A comprehensive Static Application Security Testing (SAST) tool that leverages Large Language Models to identify and help remediate security vulnerabilities in source code. This tool provides intelligent code analysis with detailed vulnerability reports and automatic patch generation.

## 🚀 Features

- **Multi-format Reporting**: Generate comprehensive reports in multiple formats (JSON, SARIF, HTML, Markdown)
- **Intelligent Vulnerability Detection**: Advanced LLM-based analysis with CWE and OWASP classification
- **Automatic Patch Generation**: AI-suggested fixes for identified vulnerabilities (optional)
- **Multi-language Support**: Detects vulnerabilities in various programming languages
- **Configurable Scanning**: Customize scanning behavior through configuration files and CLI
- **Performance Optimized**: Asynchronous processing with configurable concurrency
- **Detailed Logging**: Comprehensive logging for debugging and auditing
- **Extensible Architecture**: Easy to add new analyzers, reporters, and LLM providers

## 🏗️ Project Structure

```
llm-sast/
├── src/                       # Source code
│   ├── core/                  # Core scanning functionality
│   │   └── scanner.py         # Main scanner implementation
│   │
│   ├── services/              # Service layer
│   │   ├── llm_service.py     # LLM integration and analysis
│   │   └── file_service.py    # File operations and utilities
│   │
│   ├── models/                # Data models and configurations
│   │   ├── config.py         # Scanner configuration
│   │   └── vulnerability.py  # Vulnerability data models
│   │
│   ├── reporters/             # Report generation
│   │   ├── base_reporter.py   # Base reporter class
│   │   ├── json_reporter.py   # JSON report generator
│   │   ├── sarif_reporter.py  # SARIF report generator
│   │   ├── html_reporter.py   # HTML report generator
│   │   └── markdown_reporter.py # Markdown report generator
│   │
│   ├── config/               # Configuration
│   │   └── file_extensions.py # Supported file extensions
│   │
│   └── utils/                # Utilities
│       ├── config_loader.py  # Configuration management
│       ├── logger.py         # Logging configuration
│       └── exceptions.py     # Custom exceptions
│
├── benchmarks/               # Performance benchmarking
├── tests/                    # Test suite
├── main.py                  # CLI entry point
├── requirements.txt         # Python dependencies
└── README.md               # This file
```

## 🛠️ Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/pepegka/llm-sast.git
   cd llm-sast
   ```

2. **Set up a virtual environment**:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

4. **Configure your environment**:
   Create a `.env` file in the project root with your configuration:
   ```env
   # Required: Your LLM provider API key
   OPENAI_API_KEY=your_api_key_here
   
   # Optional: LLM provider (default: 'openai')
   LLM_PROVIDER=openai
   
   # Optional: Logging configuration
   LOG_LEVEL=INFO
   LOG_FILE=llm_sast.log
   
   # Optional: Performance tuning
   MAX_CONCURRENT_REQUESTS=5
   REQUEST_TIMEOUT=60
   ```

## 🚀 Usage

### Basic Scan
```bash
python main.py --target-dir /path/to/code --output-dir reports
```

### Advanced Usage
```bash
python main.py \
  --target-dir /path/to/code \
  --output-dir reports \
  --config custom_config.yaml \
  --log-level DEBUG \
  --no-patches  # Disable patch generation to save LLM requests
```

### Command Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `-t, --target-dir` | Directory to scan | **Required** |
| `-o, --output-dir` | Output directory for reports | `reports` |
| `-c, --config` | Path to custom config file | `None` |
| `-e, --env-file` | Path to .env file | `.env` |
| `-l, --log-level` | Logging level | `INFO` |
| `--log-file` | Path to log file | `None` (stdout) |
| `--no-patches` | Disable patch generation | `False` |

## ⚙️ Configuration

The scanner can be configured through multiple methods (in order of precedence):

1. **Command-line arguments** (highest priority)
2. **Environment variables**
3. **Configuration file** (YAML format)
4. **Default values** (lowest priority)

### Example Configuration File (`config.yaml`)

```yaml
# Scanner configuration
concurrency: 5
log_level: "INFO"
timeout: 3600
max_file_size: 1048576  # 1MB
generate_patches: true

# LLM provider settings
llm_provider: "openai"
model: "gpt-4"
temperature: 0.1
max_tokens: 4096

# File patterns to exclude
excluded_patterns:
  - "**/.git/**"
  - "**/node_modules/**"
  - "**/venv/**"
  - "**/__pycache__/**"

# Report settings
report_formats:
  - json
  - html
  - sarif
  - markdown
```

## 📊 Performance Metrics

The scanner has been optimized for accuracy and performance:

- **Recall**: 59.9% (TP=848, FN=567)
- **Precision**: 68.6% (TP=848, FP=388)
- **F1-Score**: 63.98%
- **OWASP Score**: 30.65

## 🤝 Contributing

We welcome contributions! Please follow these steps:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 📚 Resources

- [OWASP Top 10](https://owasp.org/Top10/)
- [CWE Top 25](https://cwe.mitre.org/top25/)
- [SARIF Specification](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)

## 📝 Changelog

### v1.0.0 (Latest)
- Added support for multiple report formats (JSON, SARIF, HTML, Markdown)
- Improved vulnerability detection accuracy
- Added automatic patch generation
- Enhanced performance with async processing
- Added comprehensive configuration options
