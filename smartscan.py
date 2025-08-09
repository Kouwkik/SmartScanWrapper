import subprocess # для запуска Semgrep из питона
import json # для парсинга JSON-вывода
import yaml # для чтения конфигурационного файла
import sys # для работы с командной строкой

SEVERITY_LEVELS = ['INFO', 'WARNING', 'ERROR', 'CRITICAL'] # список уровней серьезности