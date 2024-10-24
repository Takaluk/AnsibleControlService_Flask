from flask import Flask

app = Flask(__name__)

with app.app_context():
    from status import status_bp
    from scan import scan_bp
    from report import report_bp

    app.register_blueprint(status_bp)
    app.register_blueprint(scan_bp)
    app.register_blueprint(report_bp)
if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')

