from flask import Blueprint, request, render_template
import subprocess
import json
import glob
import os

report_bp = Blueprint('report', __name__)

@report_bp.route('/report')
def report():
    servers = request.args.get('servers')
    linux_checklist = request.args.get('linux_checklist')
    windows_checklist = request.args.get('windows_checklist')

    servers_list = servers.split(',') if servers else []
    linux_list = linux_checklist.split(',') if linux_checklist else []
    windows_list = windows_checklist.split(',') if windows_checklist else []
    
    # Clean previous scan results
    subprocess.run(['sudo', 'rm', '-rf', '/AnsibleVulnScanner/scan_results/*'], check=True)
    
    # Build the command
    command = 'cd /AnsibleVulnScanner/ && sudo -u ubuntu ansible-playbook playbooks/main.yml'
    if servers_list:
        command += f" --limit {','.join(servers_list)}"

    unchecked_linux = [item for item in (f'U_{i:02}' for i in range(1, 37)) if item not in linux_list]
    unchecked_windows = [item for item in (f'W_{i:02}' for i in range(1, 33)) if item not in windows_list]

    if unchecked_linux or unchecked_windows:
        command += f" --skip-tags {','.join(unchecked_linux + unchecked_windows)}"

    # Print the command for debugging
    print(f"Executing command: {command}")
    
    # Execute the command
    subprocess.run(command, shell=True)

    # Read JSON files
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
                if scan_results:  # scan_results가 비어 있지 않을 때만 실행
                    servers.append({'hostname': hostname, 'scan_results': scan_results})
    return render_template('report_template.html', servers=servers)

