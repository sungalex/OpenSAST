# SR1-3: XSS vulnerable code
from flask import Flask, request, render_template_string

app = Flask(__name__)

@app.route("/search")
def search():
    query = request.args.get("q", "")
    return render_template_string(f"<h1>Results for {query}</h1>")

@app.route("/profile")
def profile():
    name = request.args.get("name")
    return f"<div>Welcome, {name}</div>"
