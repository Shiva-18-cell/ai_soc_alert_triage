
import json
import subprocess
import sys
from pathlib import Path

from flask import Flask, render_template, redirect, url_for, flash

app = Flask(__name__)
app.secret_key = "local-development-key"

PROJECT_ROOT = Path(__file__).resolve().parent
REPORT_PATH = PROJECT_ROOT / "data" / "processed" / "triage_report.json"


def load_report():
    if not REPORT_PATH.exists():
        return []

    with REPORT_PATH.open("r", encoding="utf-8") as file:
        return json.load(file)


@app.route("/")
def dashboard():
    incidents = load_report()

    total_incidents = len(incidents)
    high_priority = sum(
        item.get("risk", {}).get("risk_severity") in ("HIGH", "CRITICAL")
        for item in incidents
    )
    likely_benign = sum(
        item.get("false_positive_analysis", {}).get("classification")
        == "LIKELY_BENIGN"
        for item in incidents
    )

    return render_template(
        "index.html",
        incidents=incidents,
        total_incidents=total_incidents,
        high_priority=high_priority,
        likely_benign=likely_benign,
    )


@app.route("/refresh", methods=["POST"])
def refresh():
    result = subprocess.run(
        [sys.executable, "src/pipeline.py"],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
    )

    if result.returncode != 0:
        app.logger.error("Pipeline failed: %s", result.stderr)
        flash("Pipeline failed. Check the terminal for details.", "error")
    else:
        flash("Incident report refreshed successfully.", "success")

    return redirect(url_for("dashboard"))


if __name__ == "__main__":
    app.run(debug=True)
