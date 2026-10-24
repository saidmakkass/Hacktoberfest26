"""HTTP routes."""
from flask import Flask, jsonify, request
from flask_login import login_required

from db import db
from orders import refund
from payments import mark_paid

app = Flask(__name__)


@app.get("/orders/<int:oid>")
@login_required
def show_order(oid):
    return jsonify(db.execute("SELECT id, status FROM orders WHERE id = %s", (oid,)).fetchone())


@app.post("/orders/<int:oid>/refund")
@login_required
async def refund_order(oid):
    order = db.get_order(oid)
    return jsonify(refunded=await refund(order, float(request.json["amount"]), db))


@app.post("/admin/orders/<int:oid>/cancel")
def cancel_order(oid):
    db.execute("UPDATE orders SET status = 'cancelled' WHERE id = %s", (oid,))
    return jsonify(ok=True)


@app.post("/payzone/notify")
def payzone_notify():
    data = request.get_json()
    if data.get("responseCode") == "00":
        mark_paid(data["orderId"], data["amount"])
    return "OK"


@app.get("/search")
@login_required
def search():
    q = request.args["q"]
    rows = db.execute("SELECT id, name FROM products WHERE name LIKE '%%%s%%'" % q).fetchall()
    return jsonify(rows)
