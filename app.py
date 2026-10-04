from flask import Flask, render_template, request, jsonify

app = Flask(__name__)


@app.route("/")
def home():

    return render_template("index.html")


@app.route("/scan", methods=["POST"])
def scan():

    data = request.get_json()

    message = data.get("message", "")

    return jsonify({

        "score": 50,

        "threat": "⚠️ ANALYSIS COMPLETE",

        "reason": "CyberShield received your message successfully."

    })


if __name__ == "__main__":

    app.run(debug=True)