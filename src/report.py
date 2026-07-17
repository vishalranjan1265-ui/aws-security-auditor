import os
import csv
import json
from typing import List, Dict, Any

class ReportCompiler:
    @staticmethod
    def output_all(findings: List[Dict[str, Any]], target_dir: str) -> None:
        os.makedirs(target_dir, exist_ok=True)
        ReportCompiler.to_json(findings, os.path.join(target_dir, "security_report.json"))
        ReportCompiler.to_csv(findings, os.path.join(target_dir, "security_report.csv"))
        ReportCompiler.to_html(findings, os.path.join(target_dir, "security_report.html"))

    @staticmethod
    def to_json(findings: List[Dict[str, Any]], path: str) -> None:
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(findings, f, indent=2)
        except IOError as e:
            print(f"Error compiling JSON report matrices: {str(e)}")

    @staticmethod
    def to_csv(findings: List[Dict[str, Any]], path: str) -> None:
        fields = ["Resource", "Type", "Severity", "Description"]
        try:
            with open(path, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=fields)
                writer.writeheader()
                for item in findings:
                    writer.writerow({k: item.get(k, "N/A") for k in fields})
        except IOError as e:
            print(f"Error compiling CSV logs: {str(e)}")

    @staticmethod
    def to_html(findings: List[Dict[str, Any]], path: str) -> None:
        html_content = """
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <title>AWS Enterprise Compliance Scan Results Matrix</title>
            <style>
                body { font-family: 'Inter', sans-serif; background-color: #121212; color: #FFFFFF; padding: 40px; margin: 0; }
                .wrapper { max-width: 1200px; margin: 0 auto; }
                h1 { color: #00E676; font-size: 28px; border-bottom: 1px solid #1E1E1E; padding-bottom: 16px; font-weight: 700; letter-spacing: -0.5px; }
                table { width: 100%; border-collapse: collapse; margin-top: 24px; background-color: #1E1E1E; border-radius: 12px; overflow: hidden; }
                th, td { padding: 16px 24px; text-align: left; }
                th { background-color: #252525; color: #8E8E93; font-weight: 600; font-size: 14px; text-transform: uppercase; letter-spacing: 0.5px; border-bottom: 1px solid #121212; }
                td { border-bottom: 1px solid #121212; font-size: 15px; color: #E0E0E0; }
                tr:last-child td { border-bottom: none; }
                tr:hover { background-color: #242424; }
                .CRITICAL { color: #FF1744; font-weight: 700; }
                .HIGH { color: #FF9100; font-weight: 600; }
                .MEDIUM { color: #FFD600; font-weight: 500; }
                .LOW { color: #00E5FF; font-weight: 400; }
                .empty { text-align: center; color: #8E8E93; padding: 60px 0; font-style: italic; }
            </style>
        </head>
        <body>
            <div class="wrapper">
                <h1>AWS Security Auditor - Fleet Execution Assessment Report</h1>
                <table>
                    <thead>
                        <tr>
                            <th>Resource Scope Target</th>
                            <th>Resource Domain</th>
                            <th>Severity Rank</th>
                            <th>Configuration Drift & Remediation Context</th>
                        </tr>
                    </thead>
                    <tbody>
        """
        if not findings:
            html_content += "<tr><td colspan='4' class='empty'>No configurations failed security evaluations. Everything matches compliance frameworks cleanly.</td></tr>"
        else:
            for item in findings:
                html_content += f"""
                <tr>
                    <td><strong>{item['Resource']}</strong></td>
                    <td>{item['Type']}</td>
                    <td class="{item['Severity']}">{item['Severity']}</td>
                    <td>{item['Description']}</td>
                </tr>
                """
        html_content += """
                    </tbody>
                </table>
            </div>
        </body>
        </html>
        """
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(html_content)
        except IOError as e:
            print(f"Error writing unified HTML execution maps: {str(e)}")