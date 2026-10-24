from flask import Flask, jsonify
from flask_login import login_required

app = Flask(__name__)


@app.post("/notes")
@login_required
def create_note():
    return jsonify(ok=True)


@app.delete("/notes/<int:nid>")
@login_required
def delete_note(nid):
    return jsonify(ok=True)
