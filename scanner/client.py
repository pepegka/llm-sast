import os
import json
import asyncio
import openai
import logging
import re

logger = logging.getLogger(__name__)

class GPTClient:
    def __init__(self, api_key: str, concurrency: int):
        openai.api_key = api_key
        self.semaphore = asyncio.Semaphore(concurrency)
        self.last_call = 0
        self.call_interval = 1  # seconds between requests
        self.max_retries = 3

    async def detect(self, code_chunk: str) -> list:
        """
        Detect security vulnerabilities in a code chunk using GPT-4o.
        Returns a list of vulnerability dicts with keys: vuln_id, title, description.
        """
        logger.debug(f"Detect called: code_chunk length={len(code_chunk)}")
        async with self.semaphore:
            messages = [
                {"role": "system", "content": "You are a security analyst specialized in static code analysis."},
                {"role": "user", "content": (
                    f"Identify all security vulnerabilities in the following code. "
                    "Return a JSON array of objects with keys: 'vuln_id', 'title', 'description', 'locations'. "
                    "Each 'locations' is a list of objects with 'line' (integer) and 'snippet' (string) fields indicating where the issue occurs. "
                    "Use full line numbers relative to the provided code. \n"
                    f"```" + code_chunk + "```"
                )}
            ]
            # throttle to avoid rate limit
            now = asyncio.get_event_loop().time()
            wait = self.call_interval - (now - self.last_call)
            if wait > 0:
                await asyncio.sleep(wait)
            # retry on rate limits
            for attempt in range(self.max_retries):
                try:
                    response = await asyncio.to_thread(
                        openai.chat.completions.create,
                        model="gpt-4o", messages=messages, temperature=0
                    )
                    self.last_call = asyncio.get_event_loop().time()
                    break
                except Exception as e:
                    status = getattr(e, 'http_status', None) or getattr(e, 'status_code', None)
                    if status == 429:
                        backoff = 2 ** attempt
                        logger.warning(f"Detect rate limit (429), retrying in {backoff}s (attempt {attempt+1})")
                        await asyncio.sleep(backoff)
                        continue
                    raise
            else:
                logger.error("Max retries reached for detect")
                return []
            logger.debug(f"Detect raw response: {response}")
            # get raw response
            content = response.choices[0].message.content
            # extract JSON array from fences
            match = re.search(r'```json\s*(\[[\s\S]*?\])\s*```', content)
            if match:
                json_str = match.group(1)
            else:
                start = content.find('[')
                end = content.rfind(']')
                json_str = content[start:end+1] if start != -1 and end != -1 else content
            logger.debug(f"Detect json_str: {json_str}")
            logger.debug(f"Detect content: {content}")
            try:
                data = json.loads(json_str)
                logger.debug(f"Detect parsed vulnerabilities count: {len(data) if isinstance(data, list) else 0}")
                return data if isinstance(data, list) else []
            except json.JSONDecodeError:
                return []

    async def enrich(self, vuln: dict, code_chunk: str) -> dict:
        """
        Enrich a detected vulnerability with POC, remediation, and references.
        """
        logger.debug(f"Enrich called: vuln={vuln.get('title')} code_chunk length={len(code_chunk)}")
        async with self.semaphore:
            messages = [
                {"role": "system", "content": "You are an expert penetration tester."},
                {"role": "user", "content": (
                    f"For the vulnerability titled '{vuln.get('title')}', with description: '{vuln.get('description')}'. "
                    "Given the following code snippet demonstrating the issue:\n```" + code_chunk + "```\n"
                    "Provide a JSON object with keys: 'proof_of_concept', 'remediation', 'references'. "
                    "Ensure 'proof_of_concept' clearly demonstrates how the vulnerability can be exploited. "
                    "Return only valid JSON without any additional text."
                )}
            ]
            # throttle to avoid rate limit
            now = asyncio.get_event_loop().time()
            wait = self.call_interval - (now - self.last_call)
            if wait > 0:
                await asyncio.sleep(wait)
            # retry on rate limits
            for attempt in range(self.max_retries):
                try:
                    response = await asyncio.to_thread(
                        openai.chat.completions.create,
                        model="gpt-4o", messages=messages, temperature=0
                    )
                    self.last_call = asyncio.get_event_loop().time()
                    break
                except Exception as e:
                    status = getattr(e, 'http_status', None) or getattr(e, 'status_code', None)
                    if status == 429:
                        backoff = 2 ** attempt
                        logger.warning(f"Enrich rate limit (429), retrying in {backoff}s (attempt {attempt+1})")
                        await asyncio.sleep(backoff)
                        continue
                    raise
            else:
                logger.error("Max retries reached for enrich")
                return vuln
            logger.debug(f"Enrich raw response: {response}")
            content = response.choices[0].message.content
            # extract JSON object from fences
            match = re.search(r'```json\s*(\{[\s\S]*?\})\s*```', content)
            if match:
                json_str = match.group(1)
            else:
                start = content.find('{')
                end = content.rfind('}')
                json_str = content[start:end+1] if start != -1 and end != -1 else content
            logger.debug(f"Enrich json_str: {json_str}")
            logger.debug(f"Enrich content: {content}")
            try:
                extra = json.loads(json_str)
                logger.debug(f"Enrich parsed extra keys: {list(extra.keys())}")
                return {**vuln, **extra}
            except json.JSONDecodeError:
                return vuln
