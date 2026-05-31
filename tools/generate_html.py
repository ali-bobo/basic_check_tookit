#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SysKit Scanner — HTML Report Generator
========================================
將 syskit_report_*.json 轉換成可閱讀的 HTML 報告。
使用方式：
  python tools/generate_html.py reports/syskit_report_20260531_120000.json

輸出：同目錄下的 .html 檔案（inline CSS，無外部依賴）。
"""

import json
import sys
import html
import os
from datetime import datetime, timezone
from pathlib import Path


CSS = """
:root {
  --bg: #0d1117; --surface: #161b22; --border: #30363d;
  --text: #c9d1d9; --muted: #8b949e; --accent: #58a6ff;
  --pass: #3fb950; --fail: #f85149; --skip: #d29922;
  --warn-bg: #2d2208; --crit-bg: #2d1a1a;
}
* { box-sizing: border-box; margin: 0; padding: 0; }
body {
  background: var(--bg); color: var(--text);
  font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
  font-size: 14px; line-height: 1.6; padding: 24px;
}
h1 { color: var(--accent); font-size: 22px; margin-bottom: 4px; }
h2 { color: var(--accent); font-size: 15px; margin: 24px 0 10px; border-bottom: 1px solid var(--border); padding-bottom: 6px; }
.meta { color: var(--muted); font-size: 12px; margin-bottom: 20px; }
.card {
  background: var(--surface); border: 1px solid var(--border);
  border-radius: 8px; padding: 16px; margin-bottom: 16px;
}
.badge {
  display: inline-block; padding: 2px 8px; border-radius: 12px;
  font-size: 12px; font-weight: 600;
}
.badge-pass { background: #1a3a26; color: var(--pass); }
.badge-fail { background: #2d1a1a; color: var(--fail); }
.badge-skip { background: #2d2a18; color: var(--skip); }
.badge-normal { background: #1a3a26; color: var(--pass); }
.badge-warn { background: var(--warn-bg); color: var(--skip); }
.badge-crit { background: var(--crit-bg); color: var(--fail); }
.score-bar-wrap {
  background: var(--border); border-radius: 4px; height: 10px; margin: 8px 0;
}
.score-bar { height: 10px; border-radius: 4px; background: var(--pass); }
table { width: 100%; border-collapse: collapse; }
th { text-align: left; color: var(--muted); font-size: 11px; padding: 6px 8px; border-bottom: 1px solid var(--border); text-transform: uppercase; }
td { padding: 7px 8px; border-bottom: 1px solid var(--border); vertical-align: top; }
tr:last-child td { border-bottom: none; }
.finding { padding: 6px 10px; border-radius: 4px; margin: 4px 0; font-size: 13px; }
.finding-crit { background: var(--crit-bg); border-left: 3px solid var(--fail); }
.finding-warn { background: var(--warn-bg); border-left: 3px solid var(--skip); }
.kv { display: grid; grid-template-columns: 160px 1fr; gap: 4px 12px; }
.kv-key { color: var(--muted); font-size: 12px; }
.footer { color: var(--muted); font-size: 11px; margin-top: 32px; text-align: center; }
"""


def status_badge(status: str) -> str:
    cls_map = {"PASS": "pass", "FAIL": "fail", "SKIPPED": "skip"}
    cls = cls_map.get(status.upper(), "skip")
    icon_map = {"PASS": "✅", "FAIL": "❌", "SKIPPED": "⏭"}
    icon = icon_map.get(status.upper(), "")
    return f'<span class="badge badge-{cls}">{icon} {html.escape(status)}</span>'


def overall_badge(status: str) -> str:
    s = status.lower()
    if "🔴" in status or "需注意" in status:
        cls = "crit"
    elif "🟡" in status or "注意" in status:
        cls = "warn"
    else:
        cls = "normal"
    return f'<span class="badge badge-{cls}">{html.escape(status)}</span>'


def build_html(data: dict) -> str:
    host = html.escape(data.get("host", "unknown"))
    os_name = html.escape(data.get("os", "unknown"))
    ts = html.escape(data.get("timestamp", ""))
    version = html.escape(data.get("scanner_version", "2.0.0"))
    overall = data.get("overall_status", "🟢 正常")
    mem = data.get("mem_free_mb", "N/A")
    disk = data.get("disk_use_percent", "N/A")
    load = html.escape(str(data.get("load_avg", "N/A")))

    net = data.get("network", {})
    private_ip = html.escape(str(net.get("private_ip", "N/A")))
    public_ip = html.escape(str(net.get("public_ip", "N/A")))
    open_ports = net.get("open_ports", [])

    cis = data.get("cis_score", {})
    cis_pass = cis.get("passed", 0)
    cis_fail = cis.get("failed", 0)
    cis_skip = cis.get("skipped", 0)
    cis_total = cis.get("total", 0)
    cis_pct = round(cis_pass / cis_total * 100) if cis_total else 0

    cis_checks = data.get("cis_checks", [])
    critical_findings = data.get("critical_findings", [])
    warn_findings = data.get("warn_findings", [])
    skipped_checks = data.get("skipped_checks", [])

    # Platform-specific security fields
    extra_fields = []
    for field, label in [
        ("selinux", "SELinux"), ("apparmor", "AppArmor"),
        ("sip", "SIP"), ("gatekeeper", "Gatekeeper"),
        ("filevault", "FileVault"), ("firewall", "Application Firewall"),
        ("defender", "Windows Defender"),
    ]:
        if field in data and data[field] not in (None, "N/A", ""):
            extra_fields.append((label, html.escape(str(data[field]))))

    # ── Findings HTML ──────────────────────────────────────────────────────
    findings_html = ""
    if not critical_findings and not warn_findings:
        findings_html = '<p style="color:var(--pass)">無重大發現。</p>'
    for f in critical_findings:
        findings_html += f'<div class="finding finding-crit">{html.escape(f)}</div>\n'
    for f in warn_findings:
        findings_html += f'<div class="finding finding-warn">{html.escape(f)}</div>\n'

    # ── CIS Table ─────────────────────────────────────────────────────────
    cis_rows = ""
    for i, c in enumerate(cis_checks, 1):
        name = html.escape(c.get("name", ""))
        status = c.get("status", "")
        evidence = html.escape(c.get("evidence", ""))
        advice = html.escape(c.get("advice", ""))
        advice_cell = f'<span style="color:var(--muted);font-size:12px">{advice}</span>' if advice else ""
        cis_rows += f"""
        <tr>
          <td style="color:var(--muted);width:30px">{i}</td>
          <td>{name}</td>
          <td>{status_badge(status)}</td>
          <td>{evidence}</td>
          <td>{advice_cell}</td>
        </tr>"""

    # ── Open Ports ────────────────────────────────────────────────────────
    ports_str = ", ".join(str(p) for p in open_ports) if open_ports else "無"

    # ── Extra security fields ─────────────────────────────────────────────
    extra_rows = ""
    for label, value in extra_fields:
        extra_rows += f'<div class="kv-key">{label}</div><div>{value}</div>\n'

    # ── Skipped checks ────────────────────────────────────────────────────
    skipped_html = ""
    if skipped_checks:
        skipped_html = f"""
      <h2>被跳過的檢查（需管理員權限）</h2>
      <div class="card">
        {''.join(f'<div style="color:var(--muted);font-size:12px">• {html.escape(s)}</div>' for s in skipped_checks)}
      </div>"""

    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    return f"""<!DOCTYPE html>
<html lang="zh-TW">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>SysKit Scanner v{version} — {host}</title>
  <style>{CSS}</style>
</head>
<body>
  <h1>🛡️ SysKit Scanner v{version}</h1>
  <p class="meta">掃描主機: <strong>{host}</strong> ({os_name}) &nbsp;|&nbsp; 掃描時間: {ts}</p>

  <h2>整體狀態</h2>
  <div class="card">
    <div style="margin-bottom:10px">{overall_badge(overall)}</div>
    <div class="kv">
      <div class="kv-key">主機</div><div>{host}</div>
      <div class="kv-key">作業系統</div><div>{os_name}</div>
      <div class="kv-key">Load Avg</div><div>{load}</div>
      <div class="kv-key">記憶體空閒</div><div>{mem} MiB</div>
      <div class="kv-key">磁碟使用率 (/)</div><div>{disk}%</div>
      <div class="kv-key">私有 IP</div><div>{private_ip}</div>
      <div class="kv-key">公網 IP</div><div>{public_ip}</div>
      <div class="kv-key">監聽埠</div><div>{html.escape(ports_str)}</div>
      {extra_rows}
    </div>
  </div>

  <h2>警示 (Findings)</h2>
  <div class="card">{findings_html}</div>

  <h2>CIS-like 安全基準 ({cis_pass}/{cis_total} — {cis_pct}%)</h2>
  <div class="card">
    <div style="display:flex;gap:16px;margin-bottom:12px">
      <span class="badge badge-pass">✅ 通過 {cis_pass}</span>
      <span class="badge badge-fail">❌ 未通過 {cis_fail}</span>
      <span class="badge badge-skip">⏭ 跳過 {cis_skip}</span>
    </div>
    <div class="score-bar-wrap">
      <div class="score-bar" style="width:{cis_pct}%;background:{'var(--pass)' if cis_pct >= 80 else ('var(--skip)' if cis_pct >= 50 else 'var(--fail)')}"></div>
    </div>
    <table style="margin-top:12px">
      <thead>
        <tr>
          <th>#</th><th>項目</th><th>狀態</th><th>結果</th><th>建議</th>
        </tr>
      </thead>
      <tbody>{cis_rows}</tbody>
    </table>
  </div>

  {skipped_html}

  <div class="footer">
    SysKit Scanner v{version} — HTML 報告產生於 {generated_at}<br>
    此報告含有系統資訊，請勿公開分享。
  </div>
</body>
</html>
"""


def main() -> int:
    if len(sys.argv) < 2:
        print("Usage: python tools/generate_html.py <path/to/syskit_report_*.json>", file=sys.stderr)
        return 1

    json_path = Path(sys.argv[1])
    if not json_path.is_file():
        print(f"[!] 找不到 JSON 報告: {json_path}", file=sys.stderr)
        return 1

    try:
        with json_path.open("r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        print(f"[!] 無法解析 JSON: {e}", file=sys.stderr)
        return 1

    html_path = json_path.with_suffix(".html")
    try:
        html_content = build_html(data)
        with html_path.open("w", encoding="utf-8") as f:
            f.write(html_content)
        print(f"[+] HTML 報告已產生: {html_path}")
        return 0
    except Exception as e:
        print(f"[!] HTML 產生失敗: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
