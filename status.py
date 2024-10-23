from flask import Blueprint, render_template
import subprocess
import re

status_bp = Blueprint('status', __name__, url_prefix='/')

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
        server_name, connection_status, os_info = message.split(' | ')
        servers.append({
            'name': server_name,
            'status': connection_status,
            'os': os_info,
        })

    return render_template('status_template.html', servers=servers)
