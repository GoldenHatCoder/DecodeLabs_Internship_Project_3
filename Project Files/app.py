from flask import Flask, jsonify, render_template, request
from analyzer import analyze_message

app = Flask(__name__)

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/analyze", methods=["POST"])
def api_analyze():
    data = request.get_json(silent=True) or {}
    message = str(data.get("message", "")).strip()
    if not message:
        return jsonify({"error": "Please enter a message to analyze."}), 400
    if len(message) > 20000:
        return jsonify({"error": "Message is too long. Please keep it under 20,000 characters."}), 400
    return jsonify(analyze_message(message))

if __name__ == "__main__":
    app.run(debug=True)
