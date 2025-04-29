from abc import ABC, abstractmethod
import asyncio
import json
import re
import logging
import time
from typing import List, Optional, Dict, Any
import openai
import ollama
from ..models.vulnerability import Vulnerability, CodeLocation, Severity
from ..utils.exceptions import LLMServiceError

logger = logging.getLogger(__name__)

class LLMService(ABC):
    """Abstract base class for LLM services."""
    
    @abstractmethod
    async def analyze_code(self, code: str, file_path: str) -> List[Vulnerability]:
        """Analyze code for potential vulnerabilities."""
        pass

    @abstractmethod
    async def enrich_finding(self, vulnerability: Vulnerability) -> Vulnerability:
        """Enrich a vulnerability finding with additional context."""
        pass

class OpenAIService(LLMService):
    """OpenAI implementation of the LLM service."""
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the OpenAI service with configuration.
        
        Args:
            config: Configuration dictionary containing OpenAI settings
        """
        openai_config = config["openai"]
        
        # Initialize OpenAI client with configuration
        client_kwargs = {
            "api_key": openai_config["api_key"],
            "timeout": openai_config.get("timeout", 30)
        }
        
        # Add custom API base URL if provided
        if openai_config.get("api_base_url"):
            client_kwargs["base_url"] = openai_config["api_base_url"]
            
        self.client = openai.OpenAI(**client_kwargs)
        self.model = openai_config.get("model", "gpt-4")
        self.timeout = openai_config.get("timeout", 30)
        self.semaphore = asyncio.Semaphore(openai_config.get("max_concurrent_calls", 5))
        self.last_call = 0
        self.call_interval = 1  # seconds between requests
        self.max_retries = 3
        self.retry_delay = 2  # seconds between retries
        self.logger = logging.getLogger("llm_sast.llm_service")
        
    async def _make_api_call_with_retry(self, messages: List[Dict]) -> Optional[str]:
        """Make an API call with retry logic and rate limiting."""
        for attempt in range(self.max_retries):
            try:
                # Rate limiting
                now = time.time()
                time_since_last_call = now - self.last_call
                if time_since_last_call < self.call_interval:
                    await asyncio.sleep(self.call_interval - time_since_last_call)
                
                async with self.semaphore:
                    self.last_call = time.time()
                    # Use synchronous API call since OpenAI client is not async
                    response = self.client.chat.completions.create(
                        model=self.model,
                        messages=messages,
                        temperature=0.1
                    )
                    
                    if not response.choices:
                        raise LLMServiceError("No response from OpenAI API")
                        
                    return response.choices[0].message.content
                    
            except openai.RateLimitError as e:
                if attempt < self.max_retries - 1:
                    self.logger.warning(f"Rate limit hit, retrying in {self.retry_delay} seconds...")
                    await asyncio.sleep(self.retry_delay)
                    self.retry_delay *= 2  # Exponential backoff
                else:
                    self.logger.error(f"Rate limit error after {self.max_retries} attempts: {str(e)}")
                    raise
                    
            except openai.APIError as e:
                if attempt < self.max_retries - 1:
                    self.logger.warning(f"API error, retrying in {self.retry_delay} seconds...")
                    await asyncio.sleep(self.retry_delay)
                else:
                    self.logger.error(f"API error after {self.max_retries} attempts: {str(e)}")
                    raise
                    
            except Exception as e:
                self.logger.error(f"Unexpected error during API call: {str(e)}")
                raise
                
        return None
        
    def _fix_code_blocks(self, text: str) -> str:
        """Ensure all code blocks are properly opened and closed."""
        # Count backticks sequences
        opens = len(re.findall(r'(?<!`)`{3}(?!`)', text))
        closes = len(re.findall(r'(?<!`)`{3}(?!`)', text))
        
        # If unbalanced, try to fix
        if opens != closes:
            # If we have unclosed blocks, close them at the end
            if opens > closes:
                text = text.rstrip() + "\n```"
            # If we have unopened blocks, add opening at the start
            elif closes > opens:
                text = "```\n" + text.lstrip()
        
        # Ensure each block has a language specifier or empty string
        text = re.sub(r'```\s*\n', '```\n', text)  # Replace ```<whitespace>\n with ```\n
        
        return text
        
    async def analyze_code(self, code: str, file_path: str) -> List[Vulnerability]:
        """Analyze code using OpenAI's API for vulnerabilities."""
        self.logger.debug(f"Analyzing code from {file_path}, length={len(code)}")
        
        # Add line numbers to the code
        lines = code.splitlines()
        numbered_code = "\n".join(f"{i+1:4d} | {line}" for i, line in enumerate(lines))
        total_lines = len(lines)
        
        messages = [
            {"role": "system", "content": (
                "You are a security analyst specialized in static code analysis. "
                "For each vulnerability found, provide the information in the following format:\n"
                "---VULNERABILITY START---\n"
                "TITLE: <clear title>\n"
                "DESCRIPTION: <detailed description>\n"
                "SEVERITY: <CRITICAL|HIGH|MEDIUM|LOW|INFO>\n"
                "CWE: CWE-<number>\n"
                "LOCATION: Lines X-Y in function_name() or class_name or file scope\n"
                "---VULNERABILITY END---\n"
                "\nProvide only real security vulnerabilities with valid CWE IDs.\n"
                "For LOCATION field:\n"
                "- ALWAYS use format 'Lines X-Y in context'\n"
                "- For single line vulnerabilities, use same number: 'Lines 42-42 in...'\n"
                "- For file-level issues use 'Lines 1-N in file scope'\n"
                "- DO NOT include actual code snippets\n"
                "- DO NOT use ranges without context\n"
                "- IMPORTANT: The code is shown with line numbers. Use these exact numbers in your response.\n"
                "- IMPORTANT: The file has {total_lines} total lines. Ensure your line numbers are within this range.\n"
                "- IMPORTANT: Line numbers are shown as '1234 | code'. Use the number before the | symbol.\n"
                "Examples:\n"
                "LOCATION: Lines 45-47 in parse_json_response()\n"
                "LOCATION: Lines 23-23 in class SecurityScanner\n"
                "LOCATION: Lines 1-156 in file scope"
            )},
            {"role": "user", "content": (
                f"Analyze the following code from {file_path} for security vulnerabilities. "
                "For each vulnerability, provide:\n"
                "1. A clear title describing the issue\n"
                "2. A detailed description of the security risk\n"
                "3. Severity level (CRITICAL for RCE/SQLi, HIGH for auth bypass/data exposure, MEDIUM for DoS/info leak, LOW for best practices)\n"
                "4. The most relevant CWE ID (e.g., CWE-79 for XSS)\n"
                "5. Location information in format 'Lines X-Y in function_name()' or 'Lines X-Y in file scope'\n"
                "IMPORTANT: The code is shown with line numbers. Use these exact numbers in your response.\n"
                f"```\n{numbered_code}\n```"
            )}
        ]
        
        try:
            raw_response = await self._make_api_call_with_retry(messages)
            if not raw_response:
                return []
                
            # Parse vulnerabilities from the text response
            vulnerabilities = []
            findings = raw_response.split("---VULNERABILITY START---")
            
            for finding in findings[1:]:  # Skip the first split which is empty
                try:
                    # Extract fields using regex
                    title_match = re.search(r"TITLE:\s*(.+?)(?:\n|$)", finding)
                    desc_match = re.search(r"DESCRIPTION:\s*(.+?)(?:\n(?=SEVERITY:|CWE:|LOCATION:|---|$))", finding, re.DOTALL)
                    sev_match = re.search(r"SEVERITY:\s*(CRITICAL|HIGH|MEDIUM|LOW|INFO)", finding)
                    cwe_match = re.search(r"CWE:\s*CWE-(\d+)", finding)
                    loc_match = re.search(r"LOCATION:\s*(.+?)(?:\n(?=---|$)|$)", finding, re.DOTALL)
                    
                    if not all([title_match, desc_match, sev_match, cwe_match, loc_match]):
                        self.logger.warning(f"Skipping finding with missing fields: {finding}")
                        continue
                    
                    # Parse location information with more robust pattern matching
                    loc_text = loc_match.group(1).strip()
                    
                    # Try different location patterns
                    line_match = None
                    
                    # Pattern 1: Standard format "Lines X-Y in context"
                    if not line_match:
                        line_match = re.search(r"Lines?\s*(\d+)(?:\s*-\s*(\d+))?\s+in\s+(.+)", loc_text, re.IGNORECASE)
                    
                    # Pattern 2: Just line numbers at start "Lines X-Y" or "Line X"
                    if not line_match:
                        line_match = re.search(r"Lines?\s*(\d+)(?:\s*-\s*(\d+))?", loc_text, re.IGNORECASE)
                        if line_match:
                            context = "file scope"  # Default context if none provided
                        else:
                            context = None
                    
                    if not line_match:
                        self.logger.warning(f"Could not parse location format: {loc_text}")
                        continue
                        
                    start_line = int(line_match.group(1))
                    end_line = int(line_match.group(2)) if line_match.group(2) else start_line
                    context = line_match.group(3).strip() if len(line_match.groups()) > 2 and line_match.group(3) else "file scope"
                    
                    # Validate line numbers against file bounds
                    if start_line < 1 or end_line < start_line or end_line > total_lines:
                        self.logger.warning(f"Invalid line numbers in location: {loc_text} (file has {total_lines} lines)")
                        continue
                    
                    # Get the actual code snippet for the location
                    snippet_lines = lines[start_line-1:end_line]
                    snippet = "\n".join(f"{i+start_line:4d} | {line}" for i, line in enumerate(snippet_lines))
                    
                    location = CodeLocation(
                        file_path=file_path,
                        start_line=start_line,
                        end_line=end_line,
                        snippet=snippet
                    )
                    
                    vuln = Vulnerability(
                        title=title_match.group(1).strip(),
                        description=desc_match.group(1).strip(),
                        severity=Severity[sev_match.group(1)],
                        location=location,
                        cwe_id=f"CWE-{cwe_match.group(1)}"
                    )
                    vulnerabilities.append(vuln)
                    
                except Exception as e:
                    self.logger.error(f"Error parsing finding: {e}")
                    continue
            
            return vulnerabilities
            
        except Exception as e:
            self.logger.error(f"Error analyzing code: {str(e)}")
            return []
            
    async def enrich_finding(self, vulnerability: Vulnerability) -> Vulnerability:
        """Enrich a vulnerability finding with additional context for markdown report."""
        self.logger.debug(f"Enriching vulnerability: {vulnerability.title}")
        
        messages = [
            {"role": "system", "content": (
                "You are an expert penetration tester and security engineer. "
                "Provide a detailed markdown-formatted response with proof of concept and fix instructions. "
                "Focus on actionable, practical steps that developers can follow.\n"
                "Format your response as follows:\n"
                "---POC START---\n"
                "<step by step proof of concept>\n"
                "---POC END---\n"
                "---FIX START---\n"
                "<step by step fix instructions>\n"
                "---FIX END---\n"
                "---RECOMMENDATIONS START---\n"
                "<additional security recommendations>\n"
                "---RECOMMENDATIONS END---\n\n"
                "When including code examples, always use proper markdown code blocks with triple backticks."
            )},
            {"role": "user", "content": (
                f"For the vulnerability titled '{vulnerability.title}' ({vulnerability.cwe_id}), "
                f"with description: '{vulnerability.description}'. "
                f"Given the following code snippet demonstrating the issue:\n```\n{vulnerability.location.snippet}\n```\n"
                "Provide:\n"
                "1. A step-by-step proof of concept showing how to exploit this vulnerability\n"
                "2. A step-by-step guide showing how to fix this vulnerability\n"
                "3. Additional security recommendations and best practices\n"
                "\nEnsure each section is clear, practical, and includes code examples where relevant."
            )}
        ]
        
        try:
            response = await self._make_api_call_with_retry(messages)
            if not response:
                return vulnerability
                
            # Fix any broken code blocks in the response
            response = self._fix_code_blocks(response)
                
            # Parse sections using regex
            poc_match = re.search(r"---POC START---\n(.*?)\n---POC END---", response, re.DOTALL)
            fix_match = re.search(r"---FIX START---\n(.*?)\n---FIX END---", response, re.DOTALL)
            rec_match = re.search(r"---RECOMMENDATIONS START---\n(.*?)\n---RECOMMENDATIONS END---", response, re.DOTALL)
            
            # Store the enrichment data, fixing code blocks in each section
            vulnerability.proof_of_concept = self._fix_code_blocks(poc_match.group(1).strip()) if poc_match else ''
            vulnerability.fix = self._fix_code_blocks(fix_match.group(1).strip()) if fix_match else ''
            vulnerability.recommendation = self._fix_code_blocks(rec_match.group(1).strip()) if rec_match else ''
            
            return vulnerability
            
        except Exception as e:
            self.logger.error(f"Error enriching vulnerability: {str(e)}")
            return vulnerability 
# --- Ollama Service Implementation ---
class OllamaService(LLMService):
    """Ollama implementation of the LLM service."""
    
    def __init__(self, config: Dict[str, Any]):
        ollama_config = config["ollama"]
        self.base_url = ollama_config.get("base_url", "http://localhost:11434")
        self.model = ollama_config.get("model", "llama3")
        self.timeout = ollama_config.get("timeout", 30)
        self.semaphore = asyncio.Semaphore(ollama_config.get("max_concurrent_calls", 5))
        self.call_interval = 1
        self.last_call = 0
        self.max_retries = 3
        self.retry_delay = 2
        self.logger = logging.getLogger("llm_sast.ollama_service")
    
    async def _chat(self, messages: List[Dict]) -> str:
        for attempt in range(self.max_retries):
            try:
                now = time.time()
                if now - self.last_call < self.call_interval:
                    await asyncio.sleep(self.call_interval - (now - self.last_call))
                async with self.semaphore:
                    self.last_call = time.time()
                    response = await asyncio.to_thread(
                        ollama.chat,
                        model=self.model,
                        messages=messages
                    )
                    if not response or "message" not in response:
                        raise LLMServiceError("No response from Ollama API")
                    return response["message"]["content"]
            except Exception as e:
                if attempt < self.max_retries - 1:
                    self.logger.warning(f"Ollama call failed ({e}), retrying in {self.retry_delay}s...")
                    await asyncio.sleep(self.retry_delay)
                    self.retry_delay *= 2
                else:
                    self.logger.error(f"Ollama error after {self.max_retries} attempts: {e}")
                    raise
        return ""
    
    async def analyze_code(self, code: str, file_path: str) -> List[Vulnerability]:
        return await OpenAIService._analyze_code(self, code, file_path)  # type: ignore
    
    async def enrich_finding(self, vulnerability: Vulnerability) -> Vulnerability:
        return await OpenAIService._enrich_finding(self, vulnerability)  # type: ignore
