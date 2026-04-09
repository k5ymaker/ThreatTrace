"""Report generator — dispatches to JSON or HTML writers."""
from __future__ import annotations

import json
from pathlib import Path

from ..models.report import AnalysisReport


class ReportGenerator:
    def __init__(self, output_path: str, fmt: str = "json") -> None:
        self.output_path = Path(output_path)
        self.fmt = fmt.lower()

    def write(self, report: AnalysisReport) -> Path:
        if self.fmt == "html":
            return self._write_html(report)
        elif self.fmt == "all":
            json_path = self._write_json(report, self.output_path.with_suffix(".json"))
            html_path = self._write_html(report, self.output_path.with_suffix(".html"))
            return html_path
        else:
            return self._write_json(report)

    def _write_json(self, report: AnalysisReport, path: Path | None = None) -> Path:
        if path is None:
            path = self.output_path if self.output_path.suffix == ".json" else self.output_path.with_suffix(".json")
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(report.to_dict(), f, indent=2, default=str)
        return path

    def _write_html(self, report: AnalysisReport, path: Path | None = None) -> Path:
        if path is None:
            path = self.output_path if self.output_path.suffix == ".html" else self.output_path.with_suffix(".html")
        path.parent.mkdir(parents=True, exist_ok=True)

        try:
            from jinja2 import Environment, FileSystemLoader, select_autoescape
            templates_dir = Path(__file__).parent / "templates"
            env = Environment(
                loader=FileSystemLoader(str(templates_dir)),
                autoescape=select_autoescape(["html"]),
            )
            template = env.get_template("report.html.j2")
            html = template.render(report=report)
        except Exception:
            # Fallback: inline HTML generation
            html = self._fallback_html(report)

        with open(path, "w", encoding="utf-8") as f:
            f.write(html)
        return path

    def _fallback_html(self, report: AnalysisReport) -> str:
        """Generate a basic HTML report without Jinja2."""
        from ..models.finding import Severity
        sev_colors = {
            "CRITICAL": "#dc2626",
            "HIGH": "#d97706",
            "MEDIUM": "#f59e0b",
            "LOW": "#0891b2",
            "INFO": "#2563eb",
        }

        rows = []
        for f in report.sorted_findings():
            color = sev_colors.get(f.severity.value, "#666")
            ts = f.timestamp.strftime("%Y-%m-%d %H:%M:%S") if f.timestamp else "N/A"
            mitre = f"{f.mitre_tactic or ''} / {f.mitre_technique or ''}".strip(" /")
            rows.append(f"""
            <tr>
                <td>{ts}</td>
                <td><span style="color:{color};font-weight:bold">{f.severity.value}</span></td>
                <td><span style="font-size:0.75em;color:#888">{f.engine.upper()}</span> {f.rule_name}</td>
                <td>{mitre}</td>
                <td><code style="font-size:0.75em">{f.raw_line[:120].replace('<','&lt;')}</code></td>
            </tr>""")

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>ThreatTrace Report — {report.generated_at.strftime('%Y-%m-%d %H:%M:%S')}</title>
<style>
  body {{ font-family: 'Segoe UI', sans-serif; background: #0f172a; color: #e2e8f0; margin: 0; padding: 20px; }}
  h1 {{ color: #ef4444; }}
  .summary {{ display: flex; gap: 20px; margin: 20px 0; }}
  .card {{ background: #1e293b; border-radius: 8px; padding: 16px; min-width: 100px; text-align: center; }}
  .card .num {{ font-size: 2em; font-weight: bold; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 0.9em; }}
  th {{ background: #1e293b; padding: 10px; text-align: left; }}
  td {{ padding: 8px 10px; border-bottom: 1px solid #1e293b; vertical-align: top; }}
  tr:hover {{ background: #1e293b55; }}
  code {{ background: #0f172a; padding: 2px 4px; border-radius: 3px; }}
</style>
</head>
<body>
<h1>ThreatTrace Analysis Report</h1>
<p>Generated: {report.generated_at.strftime('%Y-%m-%d %H:%M:%S UTC')} | Host: {report.analyst_host} |
   Log source: {report.log_source.value} | Events: {report.total_events:,} | Findings: {len(report.findings)}</p>
<div class="summary">
  <div class="card"><div class="num" style="color:#dc2626">{report.critical_count}</div><div>CRITICAL</div></div>
  <div class="card"><div class="num" style="color:#d97706">{report.high_count}</div><div>HIGH</div></div>
  <div class="card"><div class="num" style="color:#f59e0b">{report.medium_count}</div><div>MEDIUM</div></div>
  <div class="card"><div class="num" style="color:#0891b2">{report.low_count}</div><div>LOW</div></div>
  <div class="card"><div class="num" style="color:#2563eb">{report.info_count}</div><div>INFO</div></div>
</div>
<table>
  <tr><th>Timestamp</th><th>Severity</th><th>Rule</th><th>MITRE</th><th>Matched Content</th></tr>
  {''.join(rows) if rows else '<tr><td colspan="5">No findings.</td></tr>'}
</table>
</body>
</html>"""
