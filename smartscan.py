import subprocess # для запуска Semgrep из питона
import json # для парсинга JSON-вывода
import yaml # для чтения конфигурационного файла
import sys # для работы с командной строкой
import os
from html import escape


SEVERITY_LEVELS = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'] # Общепринятые уровни опасности по возрастанию

def load_config(path='config.yaml'): # подключение файла конфигурации
    with open(path, 'r') as f:
        return yaml.safe_load(f)

def severity_to_int(sev):
    try:
        return SEVERITY_LEVELS.index(sev.upper()) # перевод в числовой ответ
    except ValueError:
        return 0

def run_semgrep(paths):
    # paths - список директорий или файлов
    if not paths:
        print("No scan paths specified in config!")
        sys.exit(1)

    all_results = {"results": []}
    for p in paths:
        print(f"Running semgrep on: {p}")
        cmd = ['semgrep', '--json', p]
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            print(f"Semgrep failed on {p}: {result.stderr}")
            sys.exit(1)
        data = json.loads(result.stdout)
        all_results["results"].extend(data.get("results", []))
    return all_results

# генерация HTML-отчета
def generate_markdown_report(results, config):
    exclude = set(config.get('exclude_rules', []))
    threshold = config.get('severity_threshold', 'LOW').upper()
    threshold_index = severity_to_int(threshold)

    md = ['# SmartScanWrapper Report\n']

    for res in results.get('results', []):
        rule_id = res.get('check_id')
        severity = res.get('extra', {}).get('severity', 'LOW').upper()
        if rule_id in exclude:
            continue
        if severity_to_int(severity) < threshold_index:
            continue

        # Пометка особо опасных проблем
        highlight = ""
        if severity_to_int(severity) >= severity_to_int('HIGH'):
            highlight = "⚠️ **"

        md.append(f"## {highlight}{rule_id} - Severity: **{severity}**{highlight[::-1] if highlight else ''}")
        md.append(f"- **Message:** {res.get('extra', {}).get('message', '')}")
        md.append(f"- **File:** `{res.get('path')}`")
        md.append(f"- **Line:** {res.get('start', {}).get('line', '?')}")
        md.append('---')

    return '\n'.join(md)

def generate_html_report(results, config):
    exclude = set(config.get('exclude_rules', []))
    threshold = config.get('severity_threshold', 'LOW').upper()
    threshold_index = severity_to_int(threshold)

    # Цвета для уровней
    severity_colors = {
        'LOW': '#2E8B57',      # зеленый
        'MEDIUM': '#FFA500',   # оранжевый
        'HIGH': '#FF4500',     # красный
        'CRITICAL': '#8B0000'  # темно-красный
    }

    html = ['<html><head><title>SmartScanWrapper Report</title>']
    html.append('<style>')
    html.append('body { font-family: Arial, sans-serif; padding: 20px; }')
    html.append('.issue { border: 1px solid #ddd; margin-bottom: 15px; padding: 10px; border-radius: 5px; }')
    html.append('.severity { font-weight: bold; }')
    html.append('</style></head><body>')
    html.append('<h1>SmartScanWrapper Report</h1>')

    for res in results.get('results', []):
        rule_id = res.get('check_id')
        severity = res.get('extra', {}).get('severity', 'LOW').upper()
        if rule_id in exclude:
            continue
        if severity_to_int(severity) < threshold_index:
            continue

        color = severity_colors.get(severity, '#000000')
        message = escape(res.get('extra', {}).get('message', ''))
        path = escape(res.get('path'))
        line = res.get('start', {}).get('line', '?')

        html.append(f'<div class="issue" style="border-left: 5px solid {color};">')
        html.append(f'<h2>{escape(rule_id)} <span class="severity" style="color: {color};">[{severity}]</span></h2>')
        html.append(f'<p><strong>Message:</strong> {message}</p>')
        html.append(f'<p><strong>File:</strong> <code>{path}</code></p>')
        html.append(f'<p><strong>Line:</strong> {line}</p>')
        html.append('</div>')

    html.append('</body></html>')
    return '\n'.join(html)

def main():
    config = load_config()

    paths = config.get('scan_paths', [])
    if len(sys.argv) > 1:
        # Путь(и) из аргументов командной строки имеют приоритет
        paths = sys.argv[1:]
    if not paths:
        print("Error: No scan paths specified either in config or as arguments.")
        sys.exit(1)

    results = run_semgrep(paths)

    md_report = generate_markdown_report(results, config)
    html_report = generate_html_report(results, config)

    # Сохраняем отчёты в файлы
    with open('report.md', 'w', encoding='utf-8') as f:
        f.write(md_report)
    with open('report.html', 'w', encoding='utf-8') as f:
        f.write(html_report)

    print("Reports generated: report.md and report.html")

if __name__ == "__main__":
    main()
