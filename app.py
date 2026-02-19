import os
import json
import tempfile
from flask import Flask, render_template, request, redirect, url_for, send_from_directory

# -------- Import Analysis Modules --------
from analyzer.apk_parser import extract_basic_info
from analyzer.permission_check import analyze_permissions
from analyzer.risk_engine import calculate_risk
from analyzer.network_ioc import extract_iocs_from_file
from analyzer.history_logger import log_scan
from report_generator.pdf_report import generate_pdf

# -------- Flask App Setup --------
app = Flask(__name__)

UPLOAD_FOLDER = tempfile.gettempdir()
REPORT_FOLDER = "reports"

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["REPORT_FOLDER"] = REPORT_FOLDER

ALLOWED_EXTENSIONS = {"apk"}


# -------- Helper Function --------
def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


# -------- Routes --------
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/upload", methods=["POST"])
def upload_apk():
    if "apkfile" not in request.files:
        return "No file part"

    file = request.files["apkfile"]

    if file.filename == "":
        return "No selected file"

    if file and allowed_file(file.filename):
        file_path = os.path.join(app.config["UPLOAD_FOLDER"], file.filename)
        file.save(file_path)
        return redirect(url_for("result", filename=file.filename))

    return "Invalid file type"


@app.route("/result/<filename>")
def result(filename):
    file_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)

    # -------- Phase 4: Forensic Metadata --------
    apk_info = extract_basic_info(file_path)

    # -------- Phase 5: Permission Analysis --------
    perm_info = analyze_permissions(file_path)

    # -------- Phase 6: Risk Scoring --------
    risk_info = calculate_risk(perm_info["dangerous_permissions"])

    # -------- Feature: Network IOC Extraction --------
    ioc_info = extract_iocs_from_file(file_path)

    # -------- Feature: PDF Report Generation --------
    report_data = {
        "apk_name": filename,
        "sha256": apk_info["sha256"],
        "file_size": apk_info["file_size"],
        "analysis_time": apk_info["analysis_time"],
        "all_permissions": perm_info["all_permissions"],
        "dangerous_permissions": perm_info["dangerous_permissions"],
        "risk_score": risk_info["risk_score"],
        "verdict": risk_info["verdict"],
        "reasons": risk_info["reasons"],
        "urls": ioc_info["urls"],
        "ips": ioc_info["ips"]
    }

    pdf_name = filename.replace(".apk", "_report.pdf")
    pdf_path = os.path.join(app.config["REPORT_FOLDER"], pdf_name)

    generate_pdf(report_data, pdf_path)

    # -------- Feature: Log Scan History --------
    log_scan({
        "file_name": filename,
        "sha256": apk_info["sha256"],
        "verdict": risk_info["verdict"],
        "risk_score": risk_info["risk_score"],
        "time": apk_info["analysis_time"]
    })

    return render_template(
        "result.html",
        apk_name=filename,
        sha256=apk_info["sha256"],
        file_size=apk_info["file_size"],
        analysis_time=apk_info["analysis_time"],
        all_permissions=perm_info["all_permissions"],
        dangerous_permissions=perm_info["dangerous_permissions"],
        risk_score=risk_info["risk_score"],
        verdict=risk_info["verdict"],
        reasons=risk_info["reasons"],
        urls=ioc_info["urls"],
        ips=ioc_info["ips"],
        pdf_file=pdf_name
    )


@app.route("/reports/<filename>")
def download_report(filename):
    return send_from_directory(app.config["REPORT_FOLDER"], filename)


@app.route("/history")
def history():
    try:
        with open("analysis_history.json", "r") as f:
            history_data = json.load(f)
    except Exception:
        history_data = []

    return render_template("history.html", history=history_data)


# -------- Run Server --------
if __name__ == "__main__":
 
    os.makedirs(REPORT_FOLDER, exist_ok=True)
    app.run(debug=True)

