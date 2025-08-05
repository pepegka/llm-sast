# LLM-Powered SAST Scanner

A static application security testing (SAST) tool powered by Large Language Models to detect potential security vulnerabilities in source code.

## Features

- Asynchronous file scanning for improved performance
- LLM-based code analysis using OpenAI's GPT models
- Configurable scanning rules and patterns
- Detailed vulnerability reporting in JSON format
- Extensible architecture for adding new analyzers and reporters

## Project Structure

```
llm-sast/
├── src/
│   ├── core/          # Core scanning functionality
│   ├── services/      # Service layer (LLM, File operations)
│   ├── models/        # Data models and configurations
│   ├── utils/         # Utility functions and helpers
│   └── reporters/     # Report generation modules
├── tests/             # Test suite
├── config/            # Configuration files
├── main.py           # Entry point
└── requirements.txt  # Project dependencies
```

## Installation

1. Clone the repository:
```bash
git clone https://github.com/pepegka/llm-sast.git
cd llm-sast
```

2. Create and activate a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Create a `key.env` file with your OpenAI API key:
```
OPENAI_API_KEY=your_api_key_here
```

## Usage

Basic usage:
```bash
python main.py --target-dir /path/to/code --output-dir reports
```

Advanced options:
```bash
python main.py \
  --target-dir /path/to/code \
  --output-dir reports \
  --concurrency 5 \
  --log-level DEBUG
```

## Configuration

The scanner can be configured through command-line arguments:

- `--target-dir`, `-t`: Directory to scan (required)
- `--output-dir`, `-o`: Directory to save reports (default: "reports")
- `--concurrency`, `-c`: Concurrency limit for API calls (default: 5)
- `--log-level`, `-l`: Logging level (DEBUG, INFO, WARNING, ERROR)

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.
