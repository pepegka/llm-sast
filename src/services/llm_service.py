from abc import ABC, abstractmethod
import asyncio
import json
import re
import logging
from typing import List, Optional, Dict, Any
import openai
from ..models.vulnerability import Vulnerability, CodeLocation, Severity

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
        logger.debug(f"Analyzing code from {file_path}, length={len(code)}")
        
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
                f"```\n{code}\n```"
            )}
        ]
        
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
                    logger.warning(f"Skipping finding with missing fields: {finding}")
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
                    logger.warning(f"Could not parse location format: {loc_text}")
                    continue
                    
                start_line = int(line_match.group(1))
                end_line = int(line_match.group(2)) if line_match.group(2) else start_line
                context = line_match.group(3).strip() if len(line_match.groups()) > 2 and line_match.group(3) else "file scope"
                
                # Validate line numbers
                if start_line < 1 or end_line < start_line:
                    logger.warning(f"Invalid line numbers in location: {loc_text}")
                    continue
                
                location = CodeLocation(
                    file_path=file_path,
                    start_line=start_line,
                    end_line=end_line,
                    snippet=f"Lines {start_line}-{end_line} in {context}"
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
                logger.error(f"Error parsing finding: {e}")
                continue
        
        return vulnerabilities
            
    async def enrich_finding(self, vulnerability: Vulnerability) -> Vulnerability:
        """Enrich a vulnerability finding with additional context for markdown report."""
        logger.debug(f"Enriching vulnerability: {vulnerability.title}")
        
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
            
    async def _make_api_call_with_retry(self, messages: List[Dict]) -> Optional[str]:
        """Make an API call to OpenAI with retry logic."""
        async with self.semaphore:
            # Throttle to avoid rate limit
            now = asyncio.get_event_loop().time()
            wait = self.call_interval - (now - self.last_call)
            if wait > 0:
                await asyncio.sleep(wait)
                
            # Retry on rate limits
            for attempt in range(self.max_retries):
                try:
                    response = await asyncio.to_thread(
                        self.client.chat.completions.create,
                        model=self.model,
                        messages=messages,
                        temperature=0.1
                    )
                    self.last_call = asyncio.get_event_loop().time()
                    
                    # Return raw text response
                    return response.choices[0].message.content.strip()
                        
                except Exception as e:
                    status = getattr(e, 'http_status', None) or getattr(e, 'status_code', None)
                    if status == 429 and attempt < self.max_retries - 1:
                        backoff = 2 ** attempt
                        logger.warning(f"Rate limit (429), retrying in {backoff}s (attempt {attempt+1})")
                        await asyncio.sleep(backoff)
                        continue
                    logger.error(f"API call failed: {str(e)}")
                    return None
                    
            logger.error("Max retries reached for API call")
            return None 