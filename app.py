from flask import Flask, render_template, request, jsonify 
from detector import analyze_message
from url_checker import check_url

app = Flask(__name__)


@app.route("/")
def home():

    return render_template("index.html")


@app.route("/scan", methods=["POST"])
def scan():

    data = request.get_json()

    message = data.get("message", "")
    result = analyze_message(message)

    return jsonify({

        "score": result["score"],

        "threat": result["threat"],
        "confidence": result["confidence"],
        "advice": result["advice"],
        "reason": " ".join(result["reasons"])


    })

@app.route("/check-url", methods=["POST"])
def check_url_route():
    data = request.get_json()

    url = data.get("url", "")

    result = check_url(url)

    return jsonify({
        "score": result["score"],
        "warnings": result["warnings"]
    })


if __name__ == "__main__":

    app.run(debug=True)