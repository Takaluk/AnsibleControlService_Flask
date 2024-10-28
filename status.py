from flask import Blueprint, render_template, request, redirect, url_for
import subprocess
import re
import json
import os

status_bp = Blueprint('status', __name__, url_prefix='/status')

@status_bp.route('/')
def status():
    # Ansible playbook 명령어 실행
    command = 'cd /AnsibleVulnScanner/ && sudo -u ubuntu ansible-playbook playbooks/detect_os.yml'
    output = subprocess.getoutput(command)

    servers = []

    # 정규 표현식으로 데이터 파싱
    matches = re.findall(r'ok: \[(.*?)\] => {\s+"msg": "(.*?)"\s+}', output)
    for match in matches:
        host, message = match
        # Parsing the message to extract details
        details = message.split(' | ')
        if len(details) == 5:  # Ensure we have all components
            server_name, ip, connection_status, os_info, version_info = details
            servers.append({
                'name': server_name,
                'ip': ip.split(': ')[1],  # Extract IP from "IP: <value>"
                'status': connection_status.split(': ')[1],  # Extract status from "Status: <value>"
                'os': os_info.split(': ')[1],  # Extract OS from "OS: <value>"
                'version': version_info.split(': ')[1]  # Extract version from "Version: <value>"
            })

    # 서버 정보를 JSON 파일에서 읽기 (sudo 사용)
    sudo_command = 'sudo cat /AnsibleVulnScanner/docs/server_inform.json'
    result = subprocess.run(sudo_command, shell=True, capture_output=True, text=True)
    json_output = result.stdout
    try:
        server_inform = json.loads(json_output)
    except json.JSONDecodeError:
        server_inform = []

    # 서버 상태와 추가 정보를 합치기
    for server in servers:
        info = next((item for item in server_inform if item['hostname'] == server['name']), {})
        server['security_level'] = info.get('security_level', 'N/A')
        server['department'] = info.get('department', 'N/A')
        server['manager'] = info.get('manager', 'N/A')

    # 서버 상태를 JSON 파일로 저장 (sudo 사용)
    servers_json = json.dumps(servers, indent=4)
    with open('/tmp/server_status.json', 'w') as json_file:
        json_file.write(servers_json)
    os.system('sudo mv /tmp/server_status.json /AnsibleVulnScanner/server_status.json')

    return render_template('status_template.html', servers=servers)

