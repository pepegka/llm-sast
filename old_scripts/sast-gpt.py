#!/usr/bin/env python3
"""
sast_analyze.py – Static Code Security Analysis using a local LLM (via Ollama).

Usage:
    python sast_analyze.py --directory <project_path> [--model <model_name>]

Requirements:
    - Python 3.8+
    - `pip install ollama` (Ollama Python library) [oai_citation_attribution:12‡datacamp.com](https://www.datacamp.com/tutorial/deepseek-r1-ollama#:~:text=import%20ollama%20response%20%3D%20ollama,content)
    - Ollama daemon running with the specified model available (e.g., run `ollama pull hengwen/DeepSeek-R1-Distill-Qwen-32B:q4_k_m` beforehand).

Outputs:
    - sast_reports.json: Machine-readable JSON report of file-by-file analysis.
    - sast_summary.md: Human-readable Markdown summary of findings.
"""
import os
import argparse
import json
import re
import ast
import time
from pathlib import Path


# Add OpenAI API initialization after imports
import os
from dotenv import load_dotenv
import openai
import concurrent.futures

# Load API key from key.env
load_dotenv(dotenv_path=Path(__file__).parent / 'key.env')
openai.api_key = os.getenv("OPENAI_API_KEY")

# Supported file extensions for analysis
EXTENSIONS = {".py", ".js", ".ts", ".go", ".java", ".cpp", ".c", ".rs", ".php", ".rb"}

def ask_model_with_retries(prompt, model, max_attempts=1, wait_seconds=0):
    """
    Отправляет промпт в LLM через ollama.chat, пытаясь повторно при невалидном JSON.
    Возвращает либо dict (распарсенный JSON), либо None, если всё сломалось.
    """
    for attempt in range(1, max_attempts + 1):
        try:
            print(f"  [LLM] Attempt {attempt}/{max_attempts}...")
            response = openai.chat.completions.create(model=model, messages=[{"role": "user", "content": prompt}])
            content = response.choices[0].message.content
            parsed = parse_json_response(content)
            if parsed is not None:
                return parsed
            else:
                print("  [!] Invalid JSON from model. Retrying...")
        except Exception as e:
            print(f"  [!] Model call failed: {e}. Retrying...")
        # time.sleep(wait_seconds)
    print("  [✖] Failed after multiple attempts.")
    return None

def find_code_files(directory: Path):
    """Recursively find all files in 'directory' with the supported extensions."""
    return [path for path in directory.rglob('*') 
            if path.is_file() and path.suffix.lower() in EXTENSIONS]

def find_non_code_files(directory: Path, code_extensions: set):
    """
    Возвращает список файлов, не относящихся к коду (не входящих в кодовые расширения) 
    и не созданных SAST-скриптом (например, не в папке 'sast_results' и не отчёты в корне).
    
    Например, захватывает: .jks, Dockerfile, .env, .pem, а также файлы без расширения.
    Исключает файлы, созданные самим SAST (например, отчёты).
    """
    all_files = list(directory.rglob('*'))
    non_code = []
    for f in all_files:
        # Обрабатываем только файлы
        if not f.is_file():
            continue

        # Пропускаем файлы, созданные SAST (например, содержатся в папке 'sast_results'
        # или имеют имена 'sast_reports.json' и 'sast_summary.md' в корне проекта)
        if "sast_results" in f.parts or f.name in {"sast_reports.json", "sast_summary.md"}:
            continue

        # Если у файла отсутствует расширение или расширение не входит в перечень кодовых
        if f.suffix == "" or f.suffix.lower() not in code_extensions:
            non_code.append(f)
    return non_code


def filter_non_code_files(non_code_files: list, project_dir: Path, model_name: str):
    """
    Отправляет список не-кодовых файлов в LLM для предварительной фильтрации,
    и возвращает только те файлы, которые модель рекомендует для дальнейшего анализа.
    
    LLM ожидается вернуть JSON с ключом 'files_to_scan', содержащим список относительных путей.
    """
    # Формируем список относительных путей файлов
    file_list = [str(f.relative_to(project_dir)) for f in non_code_files]
    
    # Генерируем текстовый блок для передачи LLM
    list_message = "\n".join(file_list)
    prompt = (
        "You are an assistant that reviews file names to determine if they are likely to contain secrets, misconfigurations, or suspicious content. "
        "Some like Docker files, config files and other things that can be useful for static analysis of the application for security."
        "Below is a list of non-code files from a project. "
        f"{list_message}"
        "Please return a JSON object with a key 'files_to_scan', which is a list containing only the file names (exactly as listed) that you recommend for further analysis. "
        "If none appear relevant, return an empty list. Do not include any explanation.\n\n"
    )
    
    # Отправляем промпт через нашу функцию с повторами
    result = ask_model_with_retries(prompt, model_name)
    if result and "files_to_scan" in result:
        selected_files = result["files_to_scan"]
        # Отбираем из исходного списка только те файлы, чьи относительные пути совпадают с выборкой LLM
        return [f for f in non_code_files if str(f.relative_to(project_dir)) in selected_files]
    else:
        # Если модель не вернула список – можно либо вернуть пустой список,
        # либо анализировать все файлы. Здесь – пустой список.
        return []

def find_dependency_file(project_dir: Path, dep_name: str):
    """
    Попробовать найти файл зависимости по относительному пути или имени, 
    независимо от того, указан он как '/include/x.php', 'x.php', или просто 'config'
    """
    normalized = dep_name.strip("/\\")  # убираем / в начале/конце
    candidates = list(project_dir.rglob('*'))
    
    # 1. Сначала пробуем полное совпадение пути относительно project_dir
    direct_path = project_dir / normalized
    if direct_path.exists():
        return direct_path

    # 2. Потом ищем точное совпадение имени файла
    for path in candidates:
        if path.is_file() and path.name == normalized:
            return path

    # 3. Потом ищем частичное совпадение (без расширения, например 'config' → config.php)
    stem = Path(normalized).stem
    for path in candidates:
        if path.is_file() and stem in path.stem:
            return path

    return None

def parse_json_response(output: str):
    """Parse JSON from LLM output, attempting to fix minor format issues if necessary."""
    # Trim typical markdown or extra text around JSON
    if output is None:
        return None
    text = output.strip()
    # Remove markdown code fences if present
    if text.startswith("```"):
        # remove leading and trailing triple backticks
        text = text.strip('`')
        # Also remove any language label like "json\n"
        if text.startswith("json"):
            text = text[len("json"):].lstrip()
    # Find the JSON object within the text
    start = text.find('{')
    end = text.rfind('}')
    if start != -1 and end != -1:
        json_str = text[start:end+1]
    else:
        # If braces not found properly, use full text
        json_str = text
    # Attempt direct JSON parse first
    try:
        return json.loads(json_str)
    except json.JSONDecodeError:
        # Try to fix common issues
        # 1. Replace single quotes with double quotes for JSON compatibility
        fixed = json_str.replace("'", "\"")
        # 2. Remove trailing commas before closing brackets/braces
        fixed = re.sub(r",\s*([\]}])", r"\1", fixed)
        # 3. Balance braces/brackets if needed
        open_braces = fixed.count('{')
        close_braces = fixed.count('}')
        if open_braces > close_braces:
            fixed += '}' * (open_braces - close_braces)
        # Try JSON parse again
        try:
            return json.loads(fixed)
        except json.JSONDecodeError:
            # 4. As a last resort, use Python literal_eval for lenient parsing
            try:
                data = ast.literal_eval(fixed)
                return data
            except Exception:
                return None

def get_file_with_line_numbers(code_str: str) -> str:
        return "\n".join([f"{i+1}: {line}" for i, line in enumerate(code_str.splitlines())])

def build_vulnerability_context(vuln: dict, rel_path: Path, file_path: Path, code_str: str) -> str:
        vulnerability_info = json.dumps(vuln, indent=2, ensure_ascii=False)
        file_info = (
            f"File name: {rel_path}\n"
            f"File extension: {file_path.suffix}\n"
            f"Full file content with line numbers:\n{get_file_with_line_numbers(code_str)}\n"
        )
        return vulnerability_info + "\n" + file_info

def stage3_validate_vulnerabilities(vulnerabilities, rel_path, file_path, code, model_name):
    pass
    final_vulnerabilities = []
    for vuln in vulnerabilities:
        full_context = build_vulnerability_context(vuln, rel_path, file_path, code)
        print(full_context)

        # 1. Проверка на тест/lib файл
        prompt_test_or_lib = (
            "You are a static analysis assistant. Review the full context below and determine "
            "if the file is a test file (unit tests, mocks, etc.) or a third-party library (e.g., jQuery, vendor code). "
            "If so, any vulnerability detected should be flagged as a false positive. Do not provide any explanation.\n\n"
            f"{full_context}\n\n"
            "Respond with JSON containing only one key: 'is_test_or_library': true or false."
        )
        resp1 = ask_model_with_retries(prompt_test_or_lib, model_name)
        if resp1 and resp1.get("is_test_or_library", False):
            vuln["is_valid"] = False
            vuln["false_positive_reason"] = "File determined to be a test or third-party library based on full context."
            final_vulnerabilities.append(vuln)
            continue

        # 2. Уточнение строки
        if vuln.get('line', 0) != 0:
            prompt_refine_line = (
                "You are a code auditing assistant. Based on the full context provided below, "
                "determine the most accurate line number in the file where the vulnerability described occurs.\n\n"
                "Full vulnerability context:\n"
                f"{full_context}\n\n"
                "Respond with JSON containing one key: 'correct_line': <line_number> (an integer). This might be exacts correct line number where the bug is or 0 if none"
            )
            resp2 = ask_model_with_retries(prompt_refine_line, model_name)
            if resp2 and isinstance(resp2.get("correct_line"), int):
                vuln["correct_line"] = resp2["correct_line"]

        # 3. Проверка валидности
        prompt_validity_check = (
            "You are a security expert. Evaluate the full vulnerability context provided below and determine "
            "whether the reported vulnerability is genuine or a false positive. If the context indicates that the vulnerability"
            "that absolutely clearly affect the actual application logic, mark it as a false positive (false). In every other case, even if not 100% certain, "
            "assume the vulnerability is real and mark it as true.\n\n"
            "TLDR: return false only if you are 100% sure that is false positive and true in any other ways\n\n"
            f"{full_context}\n\n"
            "Respond with JSON containing only one key: 'is_valid': true or false."
        )

        resp3 = ask_model_with_retries(prompt_validity_check, model_name)
        if resp3 and "is_valid" in resp3:
            vuln["is_valid"] = resp3["is_valid"]
            if not resp3["is_valid"]:
                vuln["false_positive_reason"] = "Model identified this as a false positive based on full context."
        else:
            vuln["is_valid"] = True

        final_vulnerabilities.append(vuln)
    return final_vulnerabilities


def analyze_file(file_path, project_dir, model_name, output_dir):
    rel_path = file_path.relative_to(project_dir)  # relative path for nicer output
    print(f"\n[+] Analyzing file: {rel_path}")
    # Read file content (ignore errors to handle any odd encoding gracefully)
    try:
        code = file_path.read_text(encoding="utf-8", errors="ignore")
    except Exception as e:
        print(f"  [!] Could not read file {rel_path}: {e}. Skipping.")
        return

    # Stage 1: Risk rating and dependency detection
    prompt_stage1 = (
        "You are a static code analysis assistant. "
        "Evaluate the security rate of the following code file and identify any dependencies.\n\n"
        f"File: {rel_path}\n```{file_path.suffix.lstrip('.') if file_path.suffix else ''}\n"
        f"{code}\n```\n\n"
        "Provide a JSON output with two keys: 'rating' (an integer 1-10) and 'dependencies' (a list of relative file pathes that this file depends on). Do not use any symbols like *, only one file per one path."
        "Do NOT include any explanation or any text besides the JSON."
    )
    try:
        response1 = openai.chat.completions.create(model=model_name, messages=[{"role": "user", "content": prompt_stage1}])
        output1 = response1.choices[0].message.content  # the text output from model
    except Exception as e:
        print(f"  [!] Model query for Stage 1 failed for {rel_path}: {e}. Skipping file.")
        return

    data1 = ask_model_with_retries(prompt_stage1, model_name)
    if data1 is None or "rating" not in data1:
        print(f"  [!] Failed to parse Stage 1 output for {rel_path}. Skipping this file.")
        return

    rating = data1.get("rating", None)
    dependencies = data1.get("dependencies", [])
    if dependencies is None:
        dependencies = []
    # Ensure dependencies are unique and filter out non-string entries (if any)
    dependencies = [str(dep) for dep in dependencies if isinstance(dep, (str, Path))]
    print(f"  [Stage 1] Security Rating = {rating}, Dependencies = {dependencies}")

    # Stage 2: Vulnerability analysis (with dependencies content)
    dep_contents = ""
    for dep in dependencies:
        dep_path = find_dependency_file(project_dir, dep)
        if dep_path:
            try:
                dep_code = dep_path.read_text(encoding="utf-8", errors="ignore")
            except Exception as e:
                dep_code = ""
            dep_name = dep_path.name
            dep_ext = dep_path.suffix.lstrip('.')
            dep_contents += f"\nDependency: {dep_name}\n```{dep_ext}\n{dep_code}\n```\n"
        else:
            print(f"  [Stage 2] Warning: dependency '{dep}' not found in project directory.")
        if dep_path and dep_path.exists() and dep_path.is_file():
            try:
                dep_code = dep_path.read_text(encoding="utf-8", errors="ignore")
            except Exception as e:
                dep_code = ""
            dep_name = dep_path.name
            dep_ext = dep_path.suffix.lstrip('.')
            dep_contents += f"\nDependency: {dep_name}\n```{dep_ext}\n{dep_code}\n```\n"
        else:
            # If dependency file not found in project, note it (we could also skip including it)
            print(f"  [Stage 2] Warning: dependency '{dep}' not found in project directory.")

    prompt_stage2 = (
        "You are a security auditor AI. Analyze the following code for vulnerabilities.\n\n"
        f"{dep_contents}\n"
        "Analyze the following file for vulnerabilities such as SQL injection, XSS, hardcoded credentials, dangerous eval/exec, and insecure input handling."
        "Identify any security vulnerabilities in the **main file**. "
        f"Main file: {rel_path}\n```{file_path.suffix.lstrip('.')}\n{code}\n```\n"
        "Respond in JSON format with a key 'vulnerabilities' containing a list of objects, each with 'type', 'line' (number or 0 if not), and 'description' keys. "
        "Do not include explanations, only the JSON."
    )
    try:
        response2 = openai.chat.completions.create(model=model_name, messages=[{"role": "user", "content": prompt_stage2}])
        output2 = response2.choices[0].message.content
    except Exception as e:
        print(f"  [!] Model query for Stage 2 failed for {rel_path}: {e}.")
        output2 = ""

    data2 = ask_model_with_retries(prompt_stage2, model_name)
    if data2 is None:
        # If parsing failed, we'll assume no vulnerabilities found or an error occurred.
        vulnerabilities = []
        print(f"  [Stage 2] No valid vulnerability data returned for {rel_path}.")
    else:
        vulnerabilities = data2.get("vulnerabilities", [])
        if vulnerabilities is None:
            vulnerabilities = []

        # Stage 3: Validate vulnerabilities
        vulnerabilities = stage3_validate_vulnerabilities(vulnerabilities, rel_path, file_path, code, model_name)
        # Ensure each vulnerability entry is a dict with expected keys
        vulnerabilities = [v for v in vulnerabilities if isinstance(v, dict)]
        print(f"  [Stage 2] Found {len(vulnerabilities)} potential vulnerabilities in {rel_path}.")

    # Store results for this file
    file_result = {
        "file": str(rel_path),
        "rating": rating,
        "dependencies": dependencies,
        "vulnerabilities": vulnerabilities
    }

    # Опционально делай имя файла безопасным для файловой системы:
    safe_name = str(rel_path).replace("/", "__")
    file_json_path = output_dir / f"{safe_name}.json"
    try:
        with open(file_json_path, "w", encoding="utf-8") as jf:
            json.dump(file_result, jf, indent=2, ensure_ascii=False)
        print(f"  [✓] Saved individual report: {file_json_path}")
    except Exception as e:
        print(f"  [!] Error saving report for {rel_path}: {e}")

def main():
    parser = argparse.ArgumentParser(description="Perform static security analysis on a codebase using a local LLM (Ollama).")
    parser.add_argument("--directory", "-d", required=True, help="Path to the project directory to analyze")
    parser.add_argument("--model", "-m", default="gpt-4o",
                        help="Name of the Ollama model to use (default: gpt-4o)")
    args = parser.parse_args()
    project_dir = Path(args.directory)
    output_dir = project_dir / "sast_results"
    output_dir.mkdir(exist_ok=True)
    model_name = args.model

    if not project_dir.is_dir():
        print(f"Error: Directory {project_dir} does not exist or is not a directory.")
        exit(1)

    print(f"[+] Starting SAST analysis on {project_dir} using model '{model_name}'")
    code_files = find_code_files(project_dir)
    if not code_files:
        print("No code files found to analyze. Exiting.")
        exit(0)
    print(f"[+] Found {len(code_files)} code files to analyze.")

    # Parallel analysis of code files
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        list(executor.map(lambda fp: analyze_file(fp, project_dir, model_name, output_dir), code_files))
    # [ADDED] === Stage 2.5: Анализ «не-кодовых» файлов (jks, Dockerfile, .env, и т.д.) ===
    non_code_files = find_non_code_files(project_dir, EXTENSIONS)
    if non_code_files:
        print(f"\n[+] Found {len(non_code_files)} non-code files (pre-filtering Stage).")
        
        # Передаём список в LLM для фильтрации
        filtered_non_code_files = filter_non_code_files(non_code_files, project_dir, model_name)
        print(f"[+] LLM selected {len(filtered_non_code_files)} files for detailed analysis.")
        
        for file_path in filtered_non_code_files:
            rel_path = file_path.relative_to(project_dir)
            print(f"[+] Analyzing non-code file: {rel_path}")
            # Пытаемся прочитать файл как текст; если это бинарник – может быть пусто
            try:
                file_content = file_path.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                file_content = ""
                print("  [!] Could not read as text (possibly binary). Will proceed anyway.")

            # Англ. промпт, чтобы модель искала что-то вроде секретов, миссконфигов и т.п.
            prompt_stage25 = (
                "You are a security misconfiguration detection AI. "
                "Analyze the following file for secrets, misconfigurations or suspicious content. "
                "If the file is binary or unreadable, just note that. "
                f"File name: {rel_path.name}\n"
                f"File extension: {file_path.suffix}\n"
                "File content:\n"
                f"```{file_path.suffix.lstrip('.')}\n"
                f"{file_content[:5000]}\n"
                "```"
                "Respond in JSON format with a key 'vulnerabilities' containing a list of objects, each with 'type', 'line' (0 if none), and 'description' keys. "
                "Do not include explanations, only the JSON."
            )

            data25 = ask_model_with_retries(prompt_stage25, model_name)
            if data25 is None:
                print(f"  [!] Failed to parse Stage 2.5 output for {rel_path}. Skipping.")
                continue

            issues = data25.get("vulnerabilities", [])
            if not issues:
                issues = []
            print(f"  [Stage 2.5] Found {len(issues)} issues in {rel_path}.")

            # Сохраняем JSON-отчёт для не-кодового файла
            file_result = {
                "file": str(rel_path),
                "issues": issues
            }
            safe_name = str(rel_path).replace("/", "__")
            file_json_path = output_dir / f"{safe_name}.noncode.json"
            try:
                with open(file_json_path, "w", encoding="utf-8") as jf:
                    json.dump(file_result, jf, indent=2, ensure_ascii=False)
                print(f"  [✓] Saved non-code report: {file_json_path}")
            except Exception as e:
                print(f"  [!] Error saving non-code report for {rel_path}: {e}")
    else:
        print("\n[+] No non-code files found for Stage 2.5.")

   
    
    print("\n[+] Combining individual reports into a single sast_reports.json...")
    combined_results = {}
    for json_file in output_dir.glob("*.json"):
        try:
            with open(json_file, "r", encoding="utf-8") as jf:
                data = json.load(jf)
                combined_results[data["file"]] = data
        except Exception as e:
            print(f"  [!] Failed to read {json_file}: {e}")

    # Save combined machine-readable report
    report_path = project_dir / "sast_reports.json"
    try:
        with open(report_path, "w", encoding="utf-8") as rf:
            json.dump(combined_results, rf, indent=2, ensure_ascii=False)
        print(f"[+] Saved combined JSON report to {report_path}")
    except Exception as e:
        print(f"[!] Error saving combined report: {e}")

    # === Generate summary markdown using the LLM ===

    print("[+] Generating summary Markdown report via LLM...")
    summary_prompt = (
        "You are a security analysis report generator. You will be given the results of a security analysis in JSON format. "
        "Produce a comprehensive Markdown report summarizing the security findings in a human-readable form. "
        "Include an introduction and list the vulnerabilities per file with their severity (rating) and details. "
        "Make sure the report is well-structured with appropriate headings and bullet points.\n\n"
        f"Analysis Results JSON:\n```json\n{json.dumps(combined_results, indent=2)}\n```\n\n"
        "Now provide the Markdown summary report below:\n"
    )
    summary_md = ""
    try:
        response3 = openai.chat.completions.create(model=model_name, messages=[{"role": "user", "content": summary_prompt}])
        summary_md = response3.choices[0].message.content
    except Exception as e:
        print(f"[!] Failed to generate summary via model: {e}")
        summary_md = ""

    # Save the summary markdown to file
    summary_path = project_dir / "sast_summary.md"
    try:
        with open(summary_path, "w", encoding="utf-8") as sf:
            sf.write(summary_md)
        print(f"[+] Saved Markdown summary to {summary_path}")
    except Exception as e:
        print(f"[!] Error saving Markdown summary: {e}")

    print("\n[✓] SAST analysis complete.")
    if summary_md:
        print("[✓] Summary of findings (excerpt):")
        print("\n".join(summary_md.splitlines()[:10]), "...\n")
    else:
        print("[!] No summary was generated.")

if __name__ == "__main__":
    main()