import json
from pathlib import Path
from typing import List, Dict
import aiofiles
from datetime import datetime

from .base_reporter import BaseReporter
from ..models.vulnerability import Vulnerability, Severity

class HTMLReporter(BaseReporter):
    """Generate an interactive, single-page HTML dashboard with visualisations."""

    async def report(self, vulnerabilities: List[Vulnerability]) -> None:
        """Generate and save the HTML report."""
        if not vulnerabilities:
            return

        output_file = self.config.output_dir / f"sast_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"

        # Prepare data structures -----------------------------------------------------------
        severity_counts: Dict[str, int] = {severity.value: 0 for severity in Severity}
        file_counts: Dict[str, int] = {}
        vuln_json = []

        for vuln in vulnerabilities:
            severity_counts[vuln.severity.value] += 1
            file_path = str(vuln.location.file_path)
            file_counts[file_path] = file_counts.get(file_path, 0) + 1
            vuln_json.append(vuln.to_json_dict())

        # Build JS-serialisable objects
        severity_data = [{"severity": k, "count": v} for k, v in severity_counts.items() if v > 0]
        file_data = [{"file": k, "count": v} for k, v in file_counts.items()]

        # Compose HTML ----------------------------------------------------------------------
        html_content = self._generate_html(
            severity_data=severity_data,
            file_data=file_data,
            vulnerabilities=vuln_json,
        )

        async with aiofiles.open(output_file, mode="w", encoding="utf-8") as f:
            await f.write(html_content)

    async def get_summary(self, vulnerabilities: List[Vulnerability]):
        """Return a short plaintext summary (used by Scanner logging)."""
        total = len(vulnerabilities)
        return f"HTML dashboard generated with {total} findings."

    # -------------------------------------------------------------------------------------
    def _generate_html(self, *, severity_data: List[Dict], file_data: List[Dict], vulnerabilities: List[Dict]) -> str:
        """Return complete HTML page embedding scan results."""
        severity_json = json.dumps(severity_data)
        file_json = json.dumps(file_data)
        vuln_json = json.dumps(vulnerabilities)

        template = """<!DOCTYPE html>
<html lang='en'>
<head>
  <meta charset='utf-8'>
  <meta name='viewport' content='width=device-width,initial-scale=1'>
  <title>SAST Dashboard</title>
  <link href='https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css' rel='stylesheet'>
  <script src='https://d3js.org/d3.v7.min.js'></script>
  <style>body{padding:1rem}</style>
</head>
<body>
<h1>Static Analysis Dashboard</h1>
<div class='row'>
  <div class='col-md-6'>
    <h3>Severity Breakdown</h3>
    <svg id='severityChart' width='400' height='300'></svg>
  </div>
  <div class='col-md-6'>
    <h3>Files Treemap</h3>
    <svg id='fileTreemap' width='400' height='300'></svg>
  </div>
</div>
<hr/>
<h3>Findings</h3>
<table class='table table-sm' id='findingsTable'><thead><tr><th>#</th><th>File</th><th>Line</th><th>Severity</th><th>Title</th></tr></thead><tbody></tbody></table>
<script>
const severityData = __SEVERITY__;
const fileData = __FILE__;
const vulnerabilities = __VULN__;

// Severity Chart
(function(){
  const svg = d3.select('#severityChart');
  const m = {top:20,right:20,bottom:30,left:40};
  const w = +svg.attr('width') - m.left - m.right;
  const h = +svg.attr('height') - m.top - m.bottom;
  const g = svg.append('g').attr('transform',`translate(${m.left},${m.top})`);
  const x = d3.scaleBand().domain(severityData.map(d=>d.severity)).range([0,w]).padding(0.2);
  const y = d3.scaleLinear().domain([0,d3.max(severityData,d=>d.count)]).nice().range([h,0]);
  g.selectAll('rect').data(severityData).enter().append('rect')
    .attr('x',d=>x(d.severity)).attr('y',d=>y(d.count))
    .attr('width',x.bandwidth()).attr('height',d=>h-y(d.count))
    .attr('fill','#4682b4');
  g.append('g').attr('transform',`translate(0,${h})`).call(d3.axisBottom(x));
  g.append('g').call(d3.axisLeft(y));
})();

// File Treemap
(function(){
  const svg = d3.select('#fileTreemap');
  const width = +svg.attr('width');
  const height = +svg.attr('height');
  const root = {name:'files',children:fileData.map(d=>({name:d.file,value:d.count}))};
  const hier = d3.hierarchy(root).sum(d=>d.value).sort((a,b)=>b.value-a.value);
  d3.treemap().size([width,height]).padding(2)(hier);
  const nodes = svg.selectAll('g').data(hier.leaves()).enter().append('g')
    .attr('transform',d=>`translate(${d.x0},${d.y0})`);
  nodes.append('rect').attr('width',d=>d.x1-d.x0).attr('height',d=>d.y1-d.y0).attr('fill','#69b3a2');
  nodes.append('title').text(d=>`${d.data.name}: ${d.value}`);
})();

// Findings Table
(function(){
  const tbody = d3.select('#findingsTable tbody');
  vulnerabilities.forEach((v,i)=>{
    const loc = v.location;
    const tr = tbody.append('tr');
    tr.append('td').text(i+1);
    tr.append('td').text(loc.file_path);
    tr.append('td').text(loc.start_line);
    tr.append('td').text(v.severity);
    tr.append('td').text(v.title);
  });
})();
</script>
</body>
</html>
"""
        html = (template.replace('__SEVERITY__', severity_json)
                         .replace('__FILE__', file_json)
                         .replace('__VULN__', vuln_json))
        return html
        """Return the full HTML page as a string."""
        # Embed data as JSON in <script> tag so that the page is self-contained.
        severity_json = json.dumps(severity_data)
        file_json = json.dumps(file_data)
        vuln_json = json.dumps(vulnerabilities)

        template = """<!DOCTYPE html>
<html lang=\"en\">
<head>
<meta charset=\"utf-8\">
<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"/>
<title>SAST Dashboard</title>
<link href=\"https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css\" rel=\"stylesheet\">
<script src=\"https://d3js.org/d3.v7.min.js\"></script>
<style>body{padding:1rem}</style>
</head>
<body>
<h1>Static Analysis Dashboard</h1>
<div class=\"row\">
  <div class=\"col-md-6\">
    <h3>Severity Breakdown</h3>
    <svg id=\"severityChart\" width=\"400\" height=\"300\"></svg>
  </div>
  <div class=\"col-md-6\">
    <h3>Files Treemap</h3>
    <svg id=\"fileTreemap\" width=\"400\" height=\"300\"></svg>
  </div>
</div>
<hr/>
<h3>Findings</h3>
<table class=\"table table-sm\" id=\"findingsTable\"><thead><tr><th>#</th><th>File</th><th>Line</th><th>Severity</th><th>Title</th></tr></thead><tbody></tbody></table>
<script>
const severityData = __SEVERITY_JSON__;
const fileData = __FILE_JSON__;
const vulnerabilities = __VULN_JSON__;
// Severity chart
(function(){
  const svg=d3.select('#severityChart');
  const m={top:20,right:20,bottom:30,left:40};
  const w=+svg.attr('width')-m.left-m.right;
  const h=+svg.attr('height')-m.top-m.bottom;
  const g=svg.append('g').attr('transform',`translate(${m.left},${m.top})`);
  const x=d3.scaleBand().domain(severityData.map(d=>d.severity)).range([0,w]).padding(0.2);
  const y=d3.scaleLinear().domain([0,d3.max(severityData,d=>d.count)]).nice().range([h,0]);
  g.selectAll('rect').data(severityData).enter().append('rect').attr('x',d=>x(d.severity)).attr('y',d=>y(d.count)).attr('width',x.bandwidth()).attr('height',d=>h-y(d.count)).attr('fill','#4682b4');
  g.append('g').attr('transform',`translate(0,${h})`).call(d3.axisBottom(x));
  g.append('g').call(d3.axisLeft(y));
})();
// File treemap
(function(){
  const svg=d3.select('#fileTreemap');
  const width=+svg.attr('width');
  const height=+svg.attr('height');
  const root={name:'files',children:fileData.map(d=>({name:d.file,value:d.count}))};
  const hier=d3.hierarchy(root).sum(d=>d.value).sort((a,b)=>b.value-a.value);
  d3.treemap().size([width,height]).padding(2)(hier);
  const nodes=svg.selectAll('g').data(hier.leaves()).enter().append('g').attr('transform',d=>`translate(${d.x0},${d.y0})`);
  nodes.append('rect').attr('width',d=>d.x1-d.x0).attr('height',d=>d.y1-d.y0).attr('fill','#69b3a2');
  nodes.append('title').text(d=>`${d.data.name}: ${d.value}`);
})();
// Findings table
(function(){
 const tbody=d3.select('#findingsTable tbody');
 vulnerabilities.forEach((v,i)=>{
   const loc=v.location;
   const tr=tbody.append('tr');
   tr.append('td').text(i+1);
   tr.append('td').text(loc.file_path);
   tr.append('td').text(loc.start_line);
   tr.append('td').text(v.severity);
<style>
body {{ padding: 1rem; }}
#severityChart rect {{ cursor: pointer; }}
</style>
</head>
<body>
<h1 class=\"mb-4\">Static Analysis Dashboard</h1>

<div class=\"row\">
  <div class=\"col-md-6\">
    <h3>Severity Breakdown</h3>
    <svg id=\"severityChart\" width=\"400\" height=\"300\"></svg>
  </div>
  <div class=\"col-md-6\">
    <h3>Files Heat-Map (Treemap)</h3>
    <svg id=\"fileTreemap\" width=\"400\" height=\"300\"></svg>
  </div>
</div>

<hr/>
<h3>Findings Table</h3>
<table class=\"table table-striped\" id=\"findingsTable\">
  <thead><tr><th>#</th><th>File</th><th>Line</th><th>Severity</th><th>Title</th></tr></thead>
  <tbody></tbody>
</table>

<script>
// Embedded data ------------------------------------------------------------
const severityData = __SEVERITY_JSON__;
const fileData = __FILE_JSON__;
const vulnerabilities = __VULN_JSON__;

// Severity Bar Chart -------------------------------------------------------
(function() {{
  const svg = d3.select('#severityChart');
  const margin = {{top: 20, right: 20, bottom: 30, left: 50}};
  const width = +svg.attr('width') - margin.left - margin.right;
  const height = +svg.attr('height') - margin.top - margin.bottom;

  const g = svg.append('g').attr('transform', `translate(${margin.left}},${margin.top})`);

  const x = d3.scaleBand().domain(severityData.map(d => d.severity)).range([0, width]).padding(0.2);
  const y = d3.scaleLinear().domain([0, d3.max(severityData, d => d.count)]).nice().range([height, 0]);

  g.append('g').selectAll('rect')
    .data(severityData)
    .enter().append('rect')
      .attr('x', d => x(d.severity))
      .attr('y', d => y(d.count))
      .attr('width', x.bandwidth())
      .attr('height', d => height - y(d.count))
      .attr('fill', d => severityColor(d.severity));

  g.append('g').attr('transform', `translate(0,${height})`).call(d3.axisBottom(x));
  g.append('g').call(d3.axisLeft(y));

  function severityColor(s) {{
    switch(s) {{
      case 'CRITICAL': return '#d73027';
      case 'HIGH': return '#fc8d59';
      case 'MEDIUM': return '#fee08b';
      case 'LOW': return '#d9ef8b';
      default: return '#91cf60';
    }}
  }}
})();

// File Treemap -------------------------------------------------------------
(function() {
  const svg = d3.select('#fileTreemap');
  const width = +svg.attr('width');
  const height = +svg.attr('height');

  // Convert flat file list into hierarchy with single depth (file nodes)
  const root = {{
    name: 'files',
    children: fileData.map(d => ({{ name: d.file, value: d.count }))
  }};

  const hierarchyData = d3.hierarchy(root).sum(d => d.value).sort((a,b) => b.value - a.value);
  d3.treemap().size([width, height]).padding(1)(hierarchyData);

  const nodes = svg.selectAll('g').data(hierarchyData.leaves()).enter().append('g')
    .attr('transform', d => `translate(${d.x0}},${d.y0})`);

  nodes.append('rect')
    .attr('width', d => ${d.x1 - d.x0})
    .attr('height', d => ${d.y1 - d.y0})
    .attr('fill', '#69b3a2');

  nodes.append('title').text(d => `${d.data.name}}: ${d.value}}`);
})();

// Findings table -----------------------------------------------------------
(function() {{
  const tbody = d3.select('#findingsTable tbody');
  vulnerabilities.forEach((v,i) => {{
    const loc = v.location;
    const tr = tbody.append('tr');
    tr.append('td').text(i+1);
    tr.append('td').text(loc.file_path);
    tr.append('td').text(loc.start_line);
    tr.append('td').text(v.severity);
    tr.append('td').text(v.title);
  });
})();

</script>
</body>
</html>"""
        html = template.replace('__SEVERITY_JSON__', severity_json).replace('__FILE_JSON__', file_json).replace('__VULN_JSON__', vuln_json)
        return html
