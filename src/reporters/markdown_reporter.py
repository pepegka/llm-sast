from ..config.file_extensions import PROGRAMMING_EXTENSIONS
from ..models.vulnerability import Vulnerability, Severity
from collections import defaultdict, Counter
import os
from datetime import datetime
from typing import List, Dict, Set, Tuple
import aiofiles
from .base_reporter import BaseReporter

class MarkdownReporter(BaseReporter):
    """Generate markdown format reports."""
    
    def _ensure_correct_header_level(self, line: str) -> str:
        """Ensure headers are at correct levels:
        - level 3 (###) only for file names
        - level 4 (####) only for vulnerability titles
        - level 5 (#####) for all other sections
        """
        if not line.startswith('#'):
            return line
            
        # Count the level
        level = 0
        for char in line:
            if char == '#':
                level += 1
            else:
                break
                
        # Get the header text without the #s and leading/trailing whitespace
        header_text = line[level:].strip()
        
        # If it's level 3 and not a file name header, downgrade to level 4
        if level == 3 and not any(header_text.endswith(ext) for ext in PROGRAMMING_EXTENSIONS):
            return '#' + line  # Add one # to make it level 4
            
        # If it's level 4 and looks like a section name rather than a vulnerability title,
        # downgrade to level 5
        if level == 4:
            section_keywords = ['Description', 'Affected Locations', 'Step-by-Step', 'Proof of Concept', 'How to Fix', 'Additional Security Recommendations', 'Additional Recommendations', 'Fix Instructions']
            if any(keyword in header_text for keyword in section_keywords):
                return '#' + line  # Add one # to make it level 5
            
        return line

    def _validate_line_numbers(self, file_path: str, locations: Set[Tuple[int, int]]) -> Set[Tuple[int, int]]:
        """Validate that line numbers are within file bounds."""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                total_lines = sum(1 for _ in f)
            
            valid_locations = set()
            for start_line, end_line in locations:
                # Ensure line numbers are positive and within file bounds
                if 0 < start_line <= total_lines and 0 < end_line <= total_lines:
                    valid_locations.add((start_line, end_line))
                else:
                    print(f"Warning: Invalid line numbers in {file_path}: {start_line}-{end_line} (file has {total_lines} lines)")
            
            return valid_locations
        except Exception as e:
            print(f"Error validating line numbers for {file_path}: {e}")
            return locations  # Return original locations if validation fails

    async def report(self, vulnerabilities: List[Vulnerability]) -> None:
        """Generate markdown report."""
        if not vulnerabilities:
            return
            
        output_file = self.config.output_dir / f"sast_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
        
        # Group vulnerabilities by file
        vulns_by_file = self._group_vulnerabilities(vulnerabilities)
        
        # Generate report content
        content = [
            self._ensure_correct_header_level(line)
            for line in [
                self._generate_header(),
                await self.get_summary(vulnerabilities),
                "",
                "## Security Issues",
                "",
                "#### Overview",
                "The following security issues were identified in the codebase:",
                ""
            ]
        ]
        
        # Add findings by file
        for file_path, file_vulns in sorted(vulns_by_file.items()):
            content.extend(
                self._ensure_correct_header_level(line)
                for line in self._format_file_vulnerabilities(file_path, file_vulns)
            )
            content.append("")  # Add spacing between files
        
        # Write report
        async with aiofiles.open(output_file, mode='w', encoding='utf-8') as f:
            await f.write('\n'.join(content))
            
    def _group_vulnerabilities(self, vulnerabilities: List[Vulnerability]) -> Dict[str, List[Tuple[Vulnerability, Set[Tuple[int, int]]]]]:
        """Group vulnerabilities by file and combine duplicates."""
        vulns_by_file = defaultdict(list)
        
        for vuln in vulnerabilities:
            file_path = str(vuln.location.file_path)
            
            # Try to find existing similar vulnerability
            found_match = False
            for existing_vuln, locations in vulns_by_file[file_path]:
                if (existing_vuln.title == vuln.title and 
                    existing_vuln.cwe_id == vuln.cwe_id and 
                    existing_vuln.severity == vuln.severity):
                    # Add new location to existing vulnerability
                    locations.add((vuln.location.start_line, vuln.location.end_line))
                    found_match = True
                    break
            
            if not found_match:
                # Create new entry with initial location set
                vulns_by_file[file_path].append(
                    (vuln, {(vuln.location.start_line, vuln.location.end_line)})
                )
        
        return vulns_by_file
            
    def _format_file_vulnerabilities(self, file_path: str, vulnerabilities: List[Tuple[Vulnerability, Set[Tuple[int, int]]]]) -> List[str]:
        """Format all vulnerabilities for a single file."""
        # Sort by severity level (high to low) and then by title
        sorted_vulns = sorted(vulnerabilities, key=lambda x: (-x[0].severity.level, x[0].title.lower()))
        
        # File header (only level 3 header in the report)
        lines = [
            f"### {os.path.basename(file_path)}",  # This is correct as level 3
            f"**Full path**: `{file_path}`",
            ""
        ]
        
        for vuln, locations in sorted_vulns:
            # Validate line numbers before using them
            valid_locations = self._validate_line_numbers(file_path, locations)
            
            # Vulnerability title at level 4
            lines.extend([
                f"#### {vuln.title}",  # This is correct as level 4
                "",
                f"**Severity**: {vuln.severity.value}",
                f"**CWE**: [{vuln.cwe_id}]({vuln.cwe_url})" if vuln.cwe_id else "",
                "",
                "##### Description",  # All sections at level 5
                vuln.description,
                "",
                "##### Affected Locations",
            ])
            
            # Add all locations where this vulnerability was found
            for start_line, end_line in sorted(valid_locations):
                if start_line == end_line:
                    lines.append(f"- Line {start_line}")
                else:
                    lines.append(f"- Lines {start_line}-{end_line}")
            
            # Add proof of concept if available
            if vuln.proof_of_concept:
                lines.extend([
                    "",
                    "##### Proof of Concept",
                    vuln.proof_of_concept
                ])
                
            # Add fix instructions if available
            if vuln.fix:
                lines.extend([
                    "",
                    "##### How to Fix",
                    vuln.fix
                ])
                
            # Add recommendations if available
            if vuln.recommendation:
                lines.extend([
                    "",
                    "##### Additional Recommendations",
                    vuln.recommendation
                ])
            
            lines.extend(["", "---", ""])
            
        return lines
            
    async def get_summary(self, vulnerabilities: List[Vulnerability]) -> str:
        """Generate summary section of the report."""
        severity_counts = Counter(v.severity for v in vulnerabilities)
        total = len(vulnerabilities)
        
        lines = [
            "## Summary",
            "",
            f"Total vulnerabilities found: **{total}**",
            "",
            "#### Risk Overview",
            ""
        ]
        
        # Add severity breakdown
        for severity in Severity:
            count = severity_counts.get(severity, 0)
            if count > 0:
                lines.append(f"- **{severity.value}**: {count}")
        
        return "\n".join(lines)
            
    def _generate_header(self) -> str:
        """Generate report header."""
        return '\n'.join([
            "# Security Analysis Report",
            "",
            "#### Overview",
            "This report was automatically generated by the SAST scanner.",
            "",
            "#### Findings Summary",
            ""
        ]) 