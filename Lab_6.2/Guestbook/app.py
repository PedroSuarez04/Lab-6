from datetime import datetime
from flask import Flask, redirect, render_template, request, url_for

app = Flask(__name__)

# Model: In-memory dictionary/list storage
db = {"entries": []}


@app.route("/", methods=["GET", "POST"])
def index():
    # Controller logic for POST (adding an entry)
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip()
        message = request.form.get("message", "").strip()

        # Basic input validation to prevent empty submissions
        if name and email and message:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            entry = {
                "name": name,
                "email": email,
                "message": message,
                "timestamp": timestamp,
            }
            db["entries"].append(entry)
            
        return redirect(url_for("index"))

    # Controller logic for GET (displaying view with model data)
    return render_template("index.html", entries=db["entries"])


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
