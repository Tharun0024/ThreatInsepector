import json
import os

def save_report(report_data, filename='reports/forensic_report.json'):
    os.makedirs(os.path.dirname(filename), exist_ok=True)
    with open(filename, 'w') as f:
        json.dump(report_data, f, indent=2)
