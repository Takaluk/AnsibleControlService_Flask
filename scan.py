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
    
    with open('/AnsibleVulnScanner/server_status.json') as f:
        server_data = json.load(f)
    
    connected_servers = [server['name'] for server in server_data if server['status'] == 'Connected']
    linux_checklist = [f'U_{i:02}' for i in range(1, 37)]
    windows_checklist = [f'W_{i:02}' for i in range(1, 33)]
    
    return render_template('scan_template.html',
                           servers=connected_servers,
                           linux_checklist=linux_checklist,
                           windows_checklist=windows_checklist)

