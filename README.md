# Cascade SAST Scanner

A high-speed modular SAST scanner using ChatGPT (GPT-4o) in a cascading multi-stage analysis pipeline.

## Setup

1. Create a virtual environment:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Set your OpenAI API key in `key.env`:
   ```env
   OPENAI_API_KEY=your_key_here
   ```

## Usage

```bash
python main.py -t /path/to/code -o /path/to/output
```

This will scan source files and generate `report.json` and `report.md` in the specified output directory.
