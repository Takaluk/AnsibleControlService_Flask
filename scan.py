import json
from flask import Blueprint, render_template, request, redirect, url_for

scan_bp = Blueprint('scan', __name__, url_prefix='/scan')

@scan_bp.route('/', methods=['GET', 'POST'])
def scan():
    if request.method == 'POST':
        selected_servers = request.form.getlist('servers')
        selected_linux = request.form.getlist('linux_checklist')
        selected_windows = request.form.getlist('windows_checklist')
        return redirect(url_for('report.report',
                                servers=','.join(selected_servers),
                                linux_checklist=','.join(selected_linux),
                                windows_checklist=','.join(selected_windows)))

    # 서버 데이터 읽기
    with open('/AnsibleVulnScanner/server_status.json') as f:
        server_data = json.load(f)

    connected_servers = [
        {
            'name': server['name'],
            'ip': server['ip'],
            'os': server['os'],  # OS 추가
            'version': server['version'],  # Version 추가
            'status': server['status'],
            'security_level': server['security_level'],
            'department': server['department'],
            'manager': server['manager']
        }
        for server in server_data if server['status'] == 'Connected'
    ]

    # Linux 체크리스트 읽기
    with open('/AnsibleVulnScanner/docs/linux_checklist_detail.json') as f:
        linux_checklist_data = json.load(f)

    linux_checklist = [
        {
            'number': item['number'],
            'msg': item['msg'],
            'detail': item['detail'],
            'level': item['level']
        }
        for item in linux_checklist_data
    ]

    # Windows 체크리스트 읽기
    with open('/AnsibleVulnScanner/docs/windows_checklist_detail.json') as f:
        windows_checklist_data = json.load(f)

    windows_checklist = [
        {
            'number': item['number'],
            'msg': item['msg'],
            'detail': item['detail'],
            'level': item['level']
        }
        for item in windows_checklist_data
    ]

    return render_template('scan_template.html',
                           servers=connected_servers,
                           linux_checklist=linux_checklist,
                           windows_checklist=windows_checklist)

