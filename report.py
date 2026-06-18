#!/usr/bin/env python3
"""
linux-hardening-toolkit — report.py
Gerador de relatório HTML para resultados de auditoria de segurança
Autor: Professor Max — github.com/MMVonnSeek
"""

import argparse
import sys
from datetime import datetime
from pathlib import Path


def parse_results(results_str: str) -> list[dict]:
    """Converte string de resultados em lista de dicionários."""
    checks = []
    if not results_str:
        return checks

    for line in results_str.strip().split('\n'):
        if not line.strip():
            continue
        parts = line.split('|')
        if len(parts) >= 5:
            checks.append({
                'id': parts[0].strip(),
                'description': parts[1].strip(),
                'status': parts[2].strip(),
                'detail': parts[3].strip(),
                'fix': parts[4].strip(),
            })
    return checks


def score_color(score: int) -> str:
    if score >= 85:
        return '#2d6a2d'
    elif score >= 70:
        return '#7a5c00'
    elif score >= 50:
        return '#b34700'
    else:
        return '#8b0000'


def score_label(score: int) -> str:
    if score >= 95:
        return 'Excelente'
    elif score >= 85:
        return 'Bom'
    elif score >= 70:
        return 'Adequado'
    elif score >= 50:
        return 'Insuficiente'
    else:
        return 'Crítico'


def status_badge(status: str) -> str:
    colors = {
        'PASSED': ('background:#1a4a1a;color:#90ee90;', 'PASSOU'),
        'FAILED': ('background:#4a1a1a;color:#ff9090;', 'FALHOU'),
        'WARN':   ('background:#4a3a00;color:#ffd080;', 'AVISO'),
    }
    style, label = colors.get(status, ('background:#333;color:#fff;', status))
    return (
        f'<span style="padding:3px 10px;border-radius:4px;'
        f'font-size:0.8em;font-weight:bold;{style}">{label}</span>'
    )


def generate_html(host: str, score: int, total: int, passed: int,
                  failed: int, warned: int, checks: list[dict],
                  generated_at: str) -> str:

    sc = score_color(score)
    sl = score_label(score)
    bar_width = score

    rows = ''
    for c in checks:
        fix_html = ''
        if c['fix'] and c['status'] != 'PASSED':
            fix_html = (
                f'<br><code style="font-size:0.8em;color:#aaa;">'
                f'$ {c["fix"]}</code>'
            )
        detail_html = f'<br><small style="color:#aaa;">{c["detail"]}</small>' \
            if c['detail'] else ''

        rows += f"""
        <tr>
          <td style="color:#888;font-size:0.85em;">{c['id']}</td>
          <td>{c['description']}{detail_html}{fix_html}</td>
          <td style="text-align:center;">{status_badge(c['status'])}</td>
        </tr>"""

    return f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Auditoria de Segurança — {host}</title>
  <style>
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      font-family: 'Segoe UI', system-ui, sans-serif;
      background: #0d0d0d;
      color: #e0e0e0;
      padding: 2rem;
      line-height: 1.6;
    }}
    .container {{ max-width: 960px; margin: 0 auto; }}
    header {{
      border-bottom: 2px solid #cc0000;
      padding-bottom: 1rem;
      margin-bottom: 2rem;
    }}
    h1 {{ color: #cc0000; font-size: 1.6rem; }}
    .meta {{ color: #888; font-size: 0.9rem; margin-top: 0.3rem; }}
    .score-card {{
      background: #1a1a1a;
      border: 1px solid #333;
      border-left: 4px solid {sc};
      border-radius: 6px;
      padding: 1.5rem;
      margin-bottom: 2rem;
      display: flex;
      align-items: center;
      gap: 2rem;
    }}
    .score-number {{
      font-size: 3.5rem;
      font-weight: bold;
      color: {sc};
      line-height: 1;
    }}
    .score-label {{ color: {sc}; font-size: 1.1rem; margin-top: 0.3rem; }}
    .score-bar-container {{
      flex: 1;
    }}
    .score-bar-bg {{
      background: #333;
      border-radius: 4px;
      height: 12px;
      margin: 0.5rem 0;
    }}
    .score-bar-fill {{
      background: {sc};
      border-radius: 4px;
      height: 12px;
      width: {bar_width}%;
      transition: width 1s ease;
    }}
    .stats {{
      display: flex;
      gap: 1rem;
      margin-bottom: 2rem;
      flex-wrap: wrap;
    }}
    .stat-card {{
      background: #1a1a1a;
      border: 1px solid #333;
      border-radius: 6px;
      padding: 1rem 1.5rem;
      text-align: center;
      flex: 1;
      min-width: 120px;
    }}
    .stat-number {{ font-size: 2rem; font-weight: bold; }}
    .stat-label {{ color: #888; font-size: 0.85rem; margin-top: 0.2rem; }}
    .passed {{ color: #5cb85c; }}
    .failed {{ color: #d9534f; }}
    .warned {{ color: #f0ad4e; }}
    .total  {{ color: #aaa; }}
    table {{
      width: 100%;
      border-collapse: collapse;
      background: #1a1a1a;
      border-radius: 6px;
      overflow: hidden;
    }}
    th {{
      background: #111;
      color: #cc0000;
      padding: 0.8rem 1rem;
      text-align: left;
      font-size: 0.85rem;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      border-bottom: 1px solid #333;
    }}
    td {{
      padding: 0.8rem 1rem;
      border-bottom: 1px solid #222;
      vertical-align: top;
    }}
    tr:last-child td {{ border-bottom: none; }}
    tr:hover td {{ background: #1f1f1f; }}
    code {{
      background: #111;
      padding: 2px 6px;
      border-radius: 3px;
      font-family: 'Cascadia Code', 'Fira Code', monospace;
    }}
    .section-title {{
      color: #cc0000;
      margin: 2rem 0 1rem;
      font-size: 1rem;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      border-bottom: 1px solid #333;
      padding-bottom: 0.5rem;
    }}
    footer {{
      text-align: center;
      color: #555;
      font-size: 0.8rem;
      margin-top: 3rem;
      padding-top: 1rem;
      border-top: 1px solid #222;
    }}
    footer a {{ color: #cc0000; text-decoration: none; }}
  </style>
</head>
<body>
  <div class="container">
    <header>
      <h1>Relatório de Auditoria de Segurança</h1>
      <div class="meta">
        Host: <strong>{host}</strong> &nbsp;|&nbsp;
        Gerado em: {generated_at}
      </div>
    </header>

    <div class="score-card">
      <div>
        <div class="score-number">{score}</div>
        <div style="color:#888;font-size:0.8rem;">de 100</div>
        <div class="score-label">{sl}</div>
      </div>
      <div class="score-bar-container">
        <div style="color:#aaa;font-size:0.9rem;">Score de segurança</div>
        <div class="score-bar-bg">
          <div class="score-bar-fill"></div>
        </div>
        <div style="color:#666;font-size:0.8rem;">
          0 — Crítico &nbsp;&nbsp; 50 — Insuficiente &nbsp;&nbsp;
          70 — Adequado &nbsp;&nbsp; 85 — Bom &nbsp;&nbsp; 95 — Excelente
        </div>
      </div>
    </div>

    <div class="stats">
      <div class="stat-card">
        <div class="stat-number total">{total}</div>
        <div class="stat-label">Verificações</div>
      </div>
      <div class="stat-card">
        <div class="stat-number passed">{passed}</div>
        <div class="stat-label">Passou</div>
      </div>
      <div class="stat-card">
        <div class="stat-number failed">{failed}</div>
        <div class="stat-label">Falhou</div>
      </div>
      <div class="stat-card">
        <div class="stat-number warned">{warned}</div>
        <div class="stat-label">Aviso</div>
      </div>
    </div>

    <div class="section-title">Resultado por verificação</div>

    <table>
      <thead>
        <tr>
          <th style="width:80px;">ID</th>
          <th>Verificação</th>
          <th style="width:100px;text-align:center;">Status</th>
        </tr>
      </thead>
      <tbody>
        {rows}
      </tbody>
    </table>

    <footer>
      Gerado por
      <a href="https://github.com/MMVonnSeek/linux-hardening-toolkit">
        linux-hardening-toolkit
      </a>
      — Professor Max &nbsp;|&nbsp;
      <a href="https://github.com/sponsors/MMVonnSeek">Apoie o projeto</a>
    </footer>
  </div>
</body>
</html>"""


def main():
    parser = argparse.ArgumentParser(
        description='Gerador de relatório HTML para linux-hardening-toolkit'
    )
    parser.add_argument('--host',    required=True)
    parser.add_argument('--score',   required=True, type=int)
    parser.add_argument('--total',   required=True, type=int)
    parser.add_argument('--passed',  required=True, type=int)
    parser.add_argument('--failed',  required=True, type=int)
    parser.add_argument('--warned',  required=True, type=int)
    parser.add_argument('--results', required=True)
    parser.add_argument('--output',  required=True)
    args = parser.parse_args()

    checks = parse_results(args.results)
    generated_at = datetime.now().strftime('%d/%m/%Y %H:%M:%S')

    html = generate_html(
        host=args.host,
        score=args.score,
        total=args.total,
        passed=args.passed,
        failed=args.failed,
        warned=args.warned,
        checks=checks,
        generated_at=generated_at,
    )

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(html, encoding='utf-8')
    print(f'Relatório salvo em: {output_path}', file=sys.stderr)


if __name__ == '__main__':
    main()
