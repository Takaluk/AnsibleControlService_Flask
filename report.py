from flask import Blueprint, render_template
import subprocess
import json
import glob
import os
import re

report_bp = Blueprint('report', __name__, url_prefix='/report')
@report_bp.route('/')
def report():
    # 기존 스캔 결과 삭제
    subprocess.run(['sudo', 'rm', '-rf', '/AnsibleVulnScanner/scan_results/*'], check=True)

    # Ansible playbook 명령어 실행
    command = 'cd /AnsibleVulnScanner/ && sudo -u ubuntu ansible-playbook playbooks/main.yml'
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    if result.returncode != 0:
        return 'Ansible 플레이북 실행 중 오류가 발생했습니다.'

    # JSON 파일 읽기
    scan_results_dir = '/AnsibleVulnScanner/scan_results/'
    json_files = glob.glob(os.path.join(scan_results_dir, '*.json'))
    if not json_files:
        return '스캔 결과 JSON 파일을 찾을 수 없습니다.'

    servers = []
    for file in json_files:
        with open(file) as json_file:
            data = json.load(json_file)
            if data:
                hostname = data['hostname']
                scan_results = data['scan_results']
                servers.append({'hostname': hostname, 'scan_results': scan_results})

    return render_template('report_template.html', servers=servers)
