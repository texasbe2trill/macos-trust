"""HTML report generation with interactive charts."""

from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List
from collections import Counter

# HTML template with embedded CSS and Chart.js
HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>macOS Trust Scanner Report</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
            color: #333;
        }}
        
        .container {{
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            border-radius: 12px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            overflow: hidden;
        }}
        
        header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px;
            text-align: center;
            position: relative;
            overflow: hidden;
        }}
        
        header::before {{
            content: '';
            position: absolute;
            top: -50%;
            left: -50%;
            width: 200%;
            height: 200%;
            background: radial-gradient(circle, rgba(255,255,255,0.1) 0%, transparent 50%);
            animation: pulse 4s ease-in-out infinite;
        }}
        
        @keyframes pulse {{
            0%, 100% {{ transform: scale(1); opacity: 0.5; }}
            50% {{ transform: scale(1.1); opacity: 0.8; }}
        }}
        
        header h1 {{
            font-size: 2.5em;
            margin-bottom: 10px;
            font-weight: 700;
            position: relative;
            z-index: 1;
        }}
        
        header p {{
            font-size: 1.1em;
            opacity: 0.95;
            position: relative;
            z-index: 1;
        }}
        
        .metadata {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            padding: 20px 40px;
            background: #f8f9fa;
            border-bottom: 1px solid #e9ecef;
        }}
        
        .metadata-item {{
            display: flex;
            flex-direction: column;
        }}
        
        .metadata-label {{
            font-size: 0.85em;
            color: #6c757d;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-bottom: 5px;
        }}
        
        .metadata-value {{
            font-size: 1.1em;
            font-weight: 600;
            color: #212529;
        }}
        
        .summary {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 20px;
            padding: 40px;
        }}
        
        .summary-card {{
            background: white;
            border-radius: 8px;
            padding: 25px;
            text-align: center;
            border: 2px solid #e9ecef;
            transition: transform 0.2s, box-shadow 0.2s;
            position: relative;
            overflow: hidden;
        }}
        
        .summary-card::before {{
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 4px;
        }}
        
        .summary-card.high::before {{ background: linear-gradient(90deg, #dc3545, #ff6b6b); }}
        .summary-card.med::before {{ background: linear-gradient(90deg, #ffc107, #ffdd57); }}
        .summary-card.low::before {{ background: linear-gradient(90deg, #28a745, #51cf66); }}
        .summary-card.info::before {{ background: linear-gradient(90deg, #17a2b8, #4ecdc4); }}
        
        .summary-card:hover {{
            transform: translateY(-5px);
            box-shadow: 0 10px 20px rgba(0,0,0,0.1);
        }}
        
        .summary-card.high {{
            border-color: #dc3545;
            background: #fff5f5;
        }}
        
        .summary-card.med {{
            border-color: #ffc107;
            background: #fffbf0;
        }}
        
        .summary-card.low {{
            border-color: #28a745;
            background: #f0fff4;
        }}
        
        .summary-card.info {{
            border-color: #17a2b8;
            background: #f0f9ff;
        }}
        
        .summary-number {{
            font-size: 3em;
            font-weight: 700;
            margin-bottom: 10px;
        }}
        
        .summary-card.high .summary-number {{ color: #dc3545; }}
        .summary-card.med .summary-number {{ color: #ffc107; }}
        .summary-card.low .summary-number {{ color: #28a745; }}
        .summary-card.info .summary-number {{ color: #17a2b8; }}
        
        .summary-label {{
            font-size: 1em;
            color: #6c757d;
            text-transform: uppercase;
            letter-spacing: 1px;
        }}
        
        .charts {{
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 30px;
            padding: 40px;
            background: #f8f9fa;
        }}
        
        .chart-container {{
            background: white;
            border-radius: 8px;
            padding: 25px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        
        .chart-container:has(#vendorChart) {{
            min-height: 350px;
        }}
        
        .chart-wrapper {{
            position: relative;
            height: 280px;
        }}
        
        .chart-title {{
            font-size: 1.3em;
            font-weight: 600;
            margin-bottom: 20px;
            color: #212529;
        }}
        
        .findings {{
            padding: 40px;
        }}
        
        .findings-header {{
            font-size: 1.8em;
            font-weight: 700;
            margin-bottom: 30px;
            color: #212529;
        }}
        
        .finding {{
            background: white;
            border-left: 4px solid #e9ecef;
            border-radius: 8px;
            padding: 25px;
            margin-bottom: 20px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.08);
            transition: transform 0.2s, box-shadow 0.2s;
        }}
        
        .finding:hover {{
            transform: translateX(5px);
            box-shadow: 0 4px 12px rgba(0,0,0,0.15);
        }}
        
        .finding.high {{ border-left-color: #dc3545; }}
        .finding.med {{ border-left-color: #ffc107; }}
        .finding.low {{ border-left-color: #28a745; }}
        .finding.info {{ border-left-color: #17a2b8; }}
        
        .finding-header {{
            display: flex;
            align-items: center;
            margin-bottom: 15px;
        }}
        
        .risk-badge {{
            display: inline-block;
            padding: 6px 14px;
            border-radius: 20px;
            font-size: 0.85em;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-right: 15px;
        }}
        
        .risk-badge.high {{
            background: linear-gradient(135deg, #dc3545, #ff6b6b);
            color: white;
        }}
        
        .risk-badge.med {{
            background: linear-gradient(135deg, #ffc107, #ffdd57);
            color: #212529;
        }}
        
        .risk-badge.low {{
            background: linear-gradient(135deg, #28a745, #51cf66);
            color: white;
        }}
        
        .risk-badge.info {{
            background: linear-gradient(135deg, #17a2b8, #4ecdc4);
            color: white;
        }}
        
        .finding-title {{
            font-size: 1.2em;
            font-weight: 600;
            color: #212529;
            flex: 1;
        }}
        
        .category-badge {{
            background: #e9ecef;
            color: #495057;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.85em;
            font-weight: 500;
        }}
        
        .finding-details {{
            margin-top: 15px;
        }}
        
        .detail-section {{
            margin-bottom: 15px;
        }}
        
        .detail-label {{
            font-weight: 600;
            color: #495057;
            margin-bottom: 5px;
        }}
        
        .detail-value {{
            color: #6c757d;
            line-height: 1.6;
        }}
        
        .code {{
            background: #f8f9fa;
            padding: 2px 6px;
            border-radius: 4px;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
        }}
        
        .evidence-table {{
            margin-top: 10px;
            width: 100%;
            border-collapse: collapse;
        }}
        
        .evidence-table td {{
            padding: 8px;
            border-bottom: 1px solid #e9ecef;
        }}
        
        .evidence-table td:first-child {{
            font-weight: 600;
            color: #495057;
            width: 30%;
        }}
        
        footer {{
            background: #212529;
            color: white;
            padding: 30px;
            text-align: center;
        }}
        
        footer p {{
            opacity: 0.8;
            margin-bottom: 10px;
        }}
        
        footer a {{
            color: #667eea;
            text-decoration: none;
        }}
        
        footer a:hover {{
            text-decoration: underline;
        }}
        
        @media (max-width: 1200px) {{
            .charts {{
                grid-template-columns: repeat(2, 1fr);
            }}
        }}
        
        @media (max-width: 768px) {{
            .charts {{
                grid-template-columns: 1fr;
            }}
            
            .summary {{
                grid-template-columns: repeat(2, 1fr);
            }}
            
            header h1 {{
                font-size: 1.8em;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🔍 macOS Trust Scanner Report</h1>
            <p>Security audit results for your Mac</p>
        </header>
        
        <div class="metadata">
            <div class="metadata-item">
                <span class="metadata-label">Host</span>
                <span class="metadata-value">{hostname}</span>
            </div>
            <div class="metadata-item">
                <span class="metadata-label">OS Version</span>
                <span class="metadata-value">macOS {os_version}</span>
            </div>
            <div class="metadata-item">
                <span class="metadata-label">Architecture</span>
                <span class="metadata-value">{architecture}</span>
            </div>
            <div class="metadata-item">
                <span class="metadata-label">Scan Date</span>
                <span class="metadata-value">{scan_date}</span>
            </div>
        </div>
        
        <div class="summary">
            <div class="summary-card high">
                <div class="summary-number">{high_count}</div>
                <div class="summary-label">High Risk</div>
            </div>
            <div class="summary-card med">
                <div class="summary-number">{med_count}</div>
                <div class="summary-label">Medium Risk</div>
            </div>
            <div class="summary-card low">
                <div class="summary-number">{low_count}</div>
                <div class="summary-label">Low Risk</div>
            </div>
            <div class="summary-card info">
                <div class="summary-number">{info_count}</div>
                <div class="summary-label">Informational</div>
            </div>
        </div>
        
        <div class="charts">
            <div class="chart-container">
                <div class="chart-title">Risk Distribution</div>
                <div class="chart-wrapper">
                    <canvas id="riskChart"></canvas>
                </div>
            </div>
            <div class="chart-container">
                <div class="chart-title">Category Breakdown</div>
                <div class="chart-wrapper">
                    <canvas id="categoryChart"></canvas>
                </div>
            </div>
            <div class="chart-container">
                <div class="chart-title">Top Vendors</div>
                <div class="chart-wrapper">
                    <canvas id="vendorChart"></canvas>
                </div>
            </div>
        </div>
        
        <div class="findings">
            <h2 class="findings-header">Detailed Findings ({total_findings})</h2>
            {findings_html}
        </div>
        
        <footer>
            <p>Generated by <strong>macos-trust</strong> v{tool_version}</p>
            <p><a href="https://github.com/texasbe2trill/macos-trust" target="_blank">GitHub Repository</a></p>
        </footer>
    </div>
    
    <script>
        // Risk Distribution Chart
        const riskCtx = document.getElementById('riskChart').getContext('2d');
        new Chart(riskCtx, {{
            type: 'doughnut',
            data: {{
                labels: ['High Risk', 'Medium Risk', 'Low Risk', 'Informational'],
                datasets: [{{
                    data: [{high_count}, {med_count}, {low_count}, {info_count}],
                    backgroundColor: [
                        '#dc3545',
                        '#ffc107',
                        '#28a745',
                        '#17a2b8'
                    ],
                    borderWidth: 2,
                    borderColor: '#fff'
                }}]
            }},
            options: {{
                responsive: true,
                maintainAspectRatio: false,
                plugins: {{
                    legend: {{
                        position: 'bottom',
                        labels: {{
                            padding: 15,
                            font: {{
                                size: 12
                            }}
                        }}
                    }}
                }}
            }}
        }});
        
        // Category Chart
        const categoryCtx = document.getElementById('categoryChart').getContext('2d');
        new Chart(categoryCtx, {{
            type: 'bar',
            data: {{
                labels: {category_labels},
                datasets: [{{
                    label: 'Findings',
                    data: {category_data},
                    backgroundColor: '#667eea',
                    borderRadius: 6
                }}]
            }},
            options: {{
                responsive: true,
                maintainAspectRatio: false,
                plugins: {{
                    legend: {{
                        display: false
                    }}
                }},
                scales: {{
                    y: {{
                        beginAtZero: true,
                        ticks: {{
                            stepSize: 1
                        }}
                    }}
                }}
            }}
        }});
        
        // Vendor Chart
        const vendorCtx = document.getElementById('vendorChart').getContext('2d');
        new Chart(vendorCtx, {{
            type: 'bar',
            data: {{
                labels: {vendor_labels},
                datasets: [{{
                    label: 'Findings',
                    data: {vendor_data},
                    backgroundColor: '#764ba2',
                    borderRadius: 6
                }}]
            }},
            options: {{
                responsive: true,
                maintainAspectRatio: false,
                indexAxis: 'y',
                plugins: {{
                    legend: {{
                        display: false
                    }}
                }},
                scales: {{
                    x: {{
                        beginAtZero: true,
                        ticks: {{
                            stepSize: 1
                        }}
                    }},
                    y: {{
                        ticks: {{
                            autoSkip: false,
                            font: {{
                                size: 11
                            }}
                        }}
                    }}
                }}
            }}
        }});
    </script>
</body>
</html>
"""


def generate_html_report(findings: List[Dict[str, Any]], metadata: Dict[str, Any], output_path: Path) -> None:
    """
    Generate an HTML report with interactive charts.
    
    Args:
        findings: List of findings from the scan
        metadata: Scan metadata
        output_path: Path to write HTML file
    """
    # Calculate summary statistics
    risk_counts = Counter(f.get("risk", "INFO") for f in findings)
    high_count = risk_counts.get("HIGH", 0)
    med_count = risk_counts.get("MED", 0)
    low_count = risk_counts.get("LOW", 0)
    info_count = risk_counts.get("INFO", 0)
    total_findings = len(findings)
    
    # Category breakdown
    categories = Counter(f.get("category", "unknown") for f in findings)
    category_labels = list(categories.keys())
    category_data = list(categories.values())
    
    # Vendor breakdown (top 5)
    vendors = Counter()
    for f in findings:
        evidence = f.get("evidence", {})
        recommendation = f.get("recommendation", "")
        
        # Try to extract vendor from spctl_source
        vendor = evidence.get("spctl_source", "")
        if "Developer ID" in vendor and ":" in vendor:
            try:
                vendor = vendor.split("Developer ID:")[1].split("(")[0].strip()
            except (IndexError, ValueError):
                vendor = ""
        # Try to extract from recommendation text
        elif "signed by" in recommendation and "(Team ID:" in recommendation:
            try:
                parts = recommendation.split("signed by")[1].split("(Team ID:")[0]
                vendor = parts.strip()
            except (IndexError, ValueError):
                vendor = ""
        # Check if team ID exists (use app name as fallback)
        elif evidence.get("codesign_team_id") or evidence.get("spctl_team_id"):
            # Extract app name from title as fallback
            title = f.get("title", "")
            if ":" in title:
                vendor = title.split(":")[-1].strip()
            else:
                vendor = ""
        else:
            vendor = "Unsigned"
        
        if vendor and vendor not in ["Unknown", "no usable signature", "", "Unsigned"]:
            vendors[vendor] += 1
    
    top_vendors = vendors.most_common(5)
    vendor_labels = [v[0] for v in top_vendors] if top_vendors else ["None"]
    vendor_data = [v[1] for v in top_vendors] if top_vendors else [0]
    
    # Generate findings HTML
    findings_html = ""
    for finding in findings:
        risk = finding.get("risk", "INFO").lower()
        title = finding.get("title", "Unknown Finding")
        category = finding.get("category", "unknown")
        description = finding.get("details", finding.get("description", ""))
        path = finding.get("path", "")
        recommendation = finding.get("recommendation", "")
        evidence = finding.get("evidence", {})
        
        evidence_rows = ""
        for key, value in evidence.items():
            if value:
                evidence_rows += f"<tr><td>{key}</td><td>{value}</td></tr>"
        
        evidence_table = f'<table class="evidence-table">{evidence_rows}</table>' if evidence_rows else ""
        
        findings_html += f"""
        <div class="finding {risk}">
            <div class="finding-header">
                <span class="risk-badge {risk}">{finding.get("risk", "INFO")}</span>
                <span class="finding-title">{title}</span>
                <span class="category-badge">{category}</span>
            </div>
            <div class="finding-details">
                <div class="detail-section">
                    <div class="detail-label">Description</div>
                    <div class="detail-value">{description}</div>
                </div>
                {f'<div class="detail-section"><div class="detail-label">Path</div><div class="detail-value"><span class="code">{path}</span></div></div>' if path else ''}
                {f'<div class="detail-section"><div class="detail-label">Evidence</div>{evidence_table}</div>' if evidence_table else ''}
                {f'<div class="detail-section"><div class="detail-label">Recommendation</div><div class="detail-value">{recommendation}</div></div>' if recommendation else ''}
            </div>
        </div>
        """
    
    if not findings_html:
        findings_html = '<p style="text-align: center; color: #6c757d; padding: 40px;">No findings detected. Your system looks good! ✅</p>'
    
    # Format metadata
    hostname = metadata.get("hostname", "Unknown")
    os_version = metadata.get("os_version", "Unknown")
    architecture = metadata.get("arch", "Unknown")
    scan_date = metadata.get("timestamp", datetime.now().isoformat())
    if "T" in scan_date:
        scan_date = datetime.fromisoformat(scan_date.replace("Z", "+00:00")).strftime("%Y-%m-%d %H:%M:%S")
    tool_version = metadata.get("tool_version", "0.3.0")
    
    # Render template
    html = HTML_TEMPLATE.format(
        hostname=hostname,
        os_version=os_version,
        architecture=architecture,
        scan_date=scan_date,
        high_count=high_count,
        med_count=med_count,
        low_count=low_count,
        info_count=info_count,
        total_findings=total_findings,
        category_labels=json.dumps(category_labels) if category_labels else "[]",
        category_data=json.dumps(category_data) if category_data else "[]",
        vendor_labels=json.dumps(vendor_labels),
        vendor_data=json.dumps(vendor_data),
        findings_html=findings_html,
        tool_version=tool_version
    )
    
    # Write to file
    output_path.write_text(html, encoding="utf-8")


import json
