from flask import Blueprint, request, render_template, send_file
import subprocess
import json
import glob
import os
import pdfkit

report_bp = Blueprint('report', __name__, url_prefix='/report')

def load_checklist_numbers(filepath):
    with open(filepath) as json_file:
        data = json.load(json_file)
        return {item['number'] for item in data}

def load_server_status(filepath):
    with open(filepath) as json_file:
        return json.load(json_file)
def read_json_file(file_path):
    # sudo 권한으로 파일 읽기
    command = f"sudo cat {file_path}"
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True, check=True)
        return json.loads(result.stdout)
    except Exception as e:
        print(f"Error reading file: {e}")
        return []
def append_action_messages(scan_results, action_data):
    for item in action_data:
        number = item["number"]
        msg = item["msg"]
        if number in scan_results:
            if isinstance(scan_results[number], list):
                scan_results[number].append(msg)
            else:
                scan_results[number] = [scan_results[number], msg]
@report_bp.route('/')
def report():
    # 서버 이름 목록을 가져옴
    servers = request.args.get('servers')
    servers_names = servers.split(',') if servers else []

    # 서버 상태 파일에서 서버 정보를 로드
    server_status_file = '/AnsibleVulnScanner/server_status.json'
    server_status = load_server_status(server_status_file)

    # 서버 이름과 일치하는 서버 정보를 찾음
    servers_list = [server for server in server_status if server['name'] in servers_names]

    linux_checklist = request.args.get('linux_checklist')
    windows_checklist = request.args.get('windows_checklist')
    linux_list = linux_checklist.split(',') if linux_checklist else []
    windows_list = windows_checklist.split(',') if windows_checklist else []

    linux_checklist_numbers = load_checklist_numbers('/AnsibleVulnScanner/docs/linux_checklist_detail.json')
    windows_checklist_numbers = load_checklist_numbers('/AnsibleVulnScanner/docs/windows_checklist_detail.json')

    subprocess.run(['sudo', 'rm', '-rf', '/AnsibleVulnScanner/scan_results/*'], check=True)

    command = 'cd /AnsibleVulnScanner/ && sudo -u ubuntu ansible-playbook playbooks/main.yml'
    if servers_list:
        server_names = [server['name'] for server in servers_list]
        command += f" --limit {','.join(server_names)}"

    original_linux_checklist_numbers = linux_checklist_numbers.copy()
    original_windows_checklist_numbers = windows_checklist_numbers.copy()

    unchecked_linux = [item for item in original_linux_checklist_numbers if item not in linux_list]
    unchecked_windows = [item for item in original_windows_checklist_numbers if item not in windows_list]

    if unchecked_linux or unchecked_windows:
        command += f" --skip-tags {','.join(unchecked_linux + unchecked_windows)}"

    print(f"Executing command: {command}")
    subprocess.run(command, shell=True)

    scan_results_dir = '/AnsibleVulnScanner/scan_results/'
    json_files = glob.glob(os.path.join(scan_results_dir, '*.json'))
    if not json_files:
        return '스캔 결과 JSON 파일을 찾을 수 없습니다.'

    department_compliance = {}
    os_compliance = {}
    vulnerability_counts = {}

    sudo_command = 'sudo cat /AnsibleVulnScanner/docs/linux_action_inform.json'
    json_output = subprocess.getoutput(sudo_command)
    try:
        linux_action_data = json.loads(json_output)
    except json.JSONDecodeError:
        linux_action_data = []

    sudo_command = 'sudo cat /AnsibleVulnScanner/docs/windows_action_inform.json'
    json_output = subprocess.getoutput(sudo_command)
    try:
        windows_action_data = json.loads(json_output)
    except json.JSONDecodeError:
        windows_action_data = []
    for file in json_files:
        with open(file) as json_file:
            data = json.load(json_file)
            if data:
                hostname = data['hostname']
                scan_results = data['scan_results']
                if scan_results:
                    for server in servers_list:
                        if server['name'] == hostname:
                            server['scan_results'] = scan_results
                            department = server.get('department')
                            os_type = server.get('os')
                            # Calculate compliance ratio
                            total_checklist_items = original_windows_checklist_numbers if os_type == 'Windows' else original_linux_checklist_numbers
                            total_items_count = len(total_checklist_items)
                            non_compliant_count = sum(1 for key, value in scan_results.items() if value is None)
                            compliant_count = sum(1 for value in scan_results.values() if value is True)
                            compliant_ratio = round((compliant_count / (total_items_count - non_compliant_count)) * 100, 2) if total_items_count > 0 else 0
                            server['compliance_ratio'] = compliant_ratio
                            
                            # Update department compliance
                            if department:
                                if department not in department_compliance:
                                    department_compliance[department] = []
                                department_compliance[department].append(compliant_ratio)
                            
                            # Update OS compliance
                            if os_type:
                                if os_type not in os_compliance:
                                    os_compliance[os_type] = []
                                os_compliance[os_type].append(compliant_ratio)
                            
                            # Update vulnerability counts
                            for key, value in scan_results.items():
                                if value is False:
                                    if key not in vulnerability_counts:
                                        vulnerability_counts[key] = 0
                                    vulnerability_counts[key] += 1
                            break
    # Calculate average compliance for departments and OS types
    department_avg_compliance = {dept: round(sum(ratios) / len(ratios), 2) for dept, ratios in department_compliance.items()}
    os_avg_compliance = {os_type: round(sum(ratios) / len(ratios), 2) for os_type, ratios in os_compliance.items()}

    for server in servers_list:
        # Append action messages based on OS type
        os_type = server.get('os')
        if os_type == 'Windows':
            append_action_messages(server['scan_results'], windows_action_data)
        else:
            append_action_messages(server['scan_results'], linux_action_data)
    # Get top 10 vulnerabilities
    top_vulnerabilities = sorted(vulnerability_counts.items(), key=lambda item: item[1], reverse=True)[:10]
    return render_template('report_template.html', servers=servers_list,
                           department_compliance=department_avg_compliance,
                           os_compliance=os_avg_compliance,
                           top_vulnerabilities=top_vulnerabilities)
